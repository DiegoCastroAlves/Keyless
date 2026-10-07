// Background script: owns the connection to the Keyless app.
//
// Three kinds of callers, told apart by the sender:
// - the popup (trusted extension page): may search all logins, fill or copy
//   any of them and ask Keyless to unlock;
// - the Keyless menus shown inside web pages (inline.html, an extension page
//   in an iframe): may list the logins for the tab they are in, search, fill
//   into that tab and ask Keyless to unlock. They must present the token their content
//   script registered, so a page cannot embed them on its own;
// - content scripts (web page process): may only register that token and
//   ask how many logins match their page. Credentials never go to them
//   unless the user picked a login in the popup or a Keyless menu.
// The app re-checks every URL before returning credentials. The master
// password never goes through the extension: to unlock, Keyless asks the
// user itself (the system's password prompt or its own small window).

import { channelKey, equalBytes, fromBase64, identity, kvGet, kvSet, open, pairingCode, seal, toBase64 } from "./crypto";
import type { Credentials, InlineState, Login, PageState, Status } from "./types";

const HOST = "io.github.diegocastroalves.keyless";
const REQUEST_TIMEOUT_MS = 130_000;
/** Unlocking waits for the user. */
const UNLOCK_TIMEOUT_MS = 15 * 60_000;
/** After the user cancels the unlock prompt, opening the popup again does not
 * bring it back right away. */
const AUTO_PROMPT_COOLDOWN_MS = 30_000;
const EXTENSION_BASE = chrome.runtime.getURL("");

type Pending = { resolve: (value: any) => void; reject: (reason: Error) => void };

class NativeConnection {
  private port: chrome.runtime.Port | null = null;
  private queue: Pending[] = [];
  lastError: string | null = null;

  constructor(private readonly timeoutMs = REQUEST_TIMEOUT_MS) {}

  private connect(): chrome.runtime.Port {
    const port = chrome.runtime.connectNative(HOST);
    port.onMessage.addListener((message) => this.queue.shift()?.resolve(message));
    port.onDisconnect.addListener(() => {
      this.lastError = chrome.runtime.lastError?.message ?? "disconnected";
      this.port = null;
      const pending = this.queue;
      this.queue = [];
      pending.forEach((p) => p.reject(new Error("host_missing")));
    });
    this.port = port;
    return port;
  }

  send<T = any>(message: unknown): Promise<T> {
    const port = this.port ?? this.connect();
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timeout")), this.timeoutMs);
      this.queue.push({
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (reason) => {
          clearTimeout(timer);
          reject(reason);
        },
      });
      try {
        port.postMessage(message);
      } catch {
        this.queue.pop();
        clearTimeout(timer);
        reject(new Error("host_missing"));
      }
    });
  }
}

const native = new NativeConnection();
/** Unlocking can wait minutes for the user; the app answers one request at a
 * time per connection, so it gets its own. */
const slow = new NativeConnection(UNLOCK_TIMEOUT_MS);
let session: { key: CryptoKey; appPublic: Uint8Array } | null = null;

function browserName(): string {
  const ua = navigator.userAgent;
  if (ua.includes("Firefox/")) return "Firefox";
  if (ua.includes("Edg/")) return "Microsoft Edge";
  if (ua.includes("OPR/")) return "Opera";
  if ((navigator as any).brave) return "Brave";
  if (ua.includes("Vivaldi")) return "Vivaldi";
  return "Chrome";
}

class BridgeError extends Error {}

/** Says hello to the app and prepares the encrypted channel. */
async function connect(): Promise<Status> {
  const me = await identity();
  let reply: any;
  try {
    reply = await native.send({ type: "hello", pub: toBase64(me.publicRaw), name: browserName() });
  } catch {
    return { state: "host_missing" };
  }
  if (reply?.type === "error") {
    return { state: reply.code === "app_not_running" ? "app_not_running" : "error" };
  }
  const appPublic = fromBase64(reply.pub);
  const pinned = await kvGet<ArrayBuffer>("appPublic");
  if (pinned && !equalBytes(new Uint8Array(pinned), appPublic)) {
    // A different app key: another installation, or something impersonating
    // the app. Only pairing again, approved by the user, replaces the pin.
    session = null;
    return { state: "not_paired", code: await pairingCode(me, appPublic) };
  }
  if (!reply.paired) {
    session = null;
    return { state: "not_paired", code: await pairingCode(me, appPublic) };
  }
  if (!pinned) await kvSet("appPublic", appPublic.buffer);
  session = { key: await channelKey(me, appPublic), appPublic };
  return { state: "ready" };
}

async function call<T = any>(cmd: string, args: Record<string, unknown> = {}, connection = native): Promise<T> {
  try {
    return await send<T>(cmd, args, connection);
  } catch (err) {
    // A host still connected to an app that has since restarted answers
    // "not running" once, then reconnects.
    if (!(err instanceof BridgeError) || err.message !== "app_not_running") throw err;
    return send<T>(cmd, args, connection);
  }
}

async function send<T>(cmd: string, args: Record<string, unknown>, connection: NativeConnection): Promise<T> {
  if (!session) {
    const status = await connect();
    if (status.state !== "ready") throw new BridgeError(status.state);
  }
  const me = await identity();
  const request = { id: crypto.randomUUID(), ts: Date.now(), cmd, args };
  const { nonce, ct } = await seal(session!.key, request);
  let reply: any;
  try {
    reply = await connection.send({ type: "enc", pub: toBase64(me.publicRaw), nonce, ct });
  } catch {
    session = null;
    throw new BridgeError("host_missing");
  }
  if (reply?.type === "error") {
    session = null;
    throw new BridgeError(reply.code === "app_not_running" ? "app_not_running" : reply.code === "not_paired" ? "not_paired" : "error");
  }
  const response = await open<{ id: string; ok: boolean; data?: T; error?: string }>(session!.key, reply.nonce, reply.ct);
  if (response.id !== request.id) throw new BridgeError("error");
  if (!response.ok) throw new BridgeError(response.error ?? "error");
  return response.data as T;
}

type AppStatus = { locked: boolean; email?: string };

function fromAppStatus(result: AppStatus): Status {
  return result.locked ? { state: "locked" } : { state: "ready", email: result.email };
}

/** Full status for the popup, including the pairing code. */
async function status(): Promise<Status> {
  const base = await connect();
  if (base.state !== "ready") return base;
  return quickStatus();
}

/** Status over the existing channel, for frequent checks. */
async function quickStatus(): Promise<Status> {
  try {
    return fromAppStatus(await call<AppStatus>("status"));
  } catch (err) {
    return { state: err instanceof BridgeError ? (err.message as Status["state"]) : "error" };
  }
}

async function pair(): Promise<boolean> {
  const me = await identity();
  const hello = await native.send({ type: "hello", pub: toBase64(me.publicRaw), name: browserName() });
  if (hello?.type !== "hello") return false;
  const reply = await native.send({ type: "pair", pub: toBase64(me.publicRaw), name: browserName() });
  if (reply?.type === "pair" && reply.ok) {
    await kvSet("appPublic", fromBase64(hello.pub).buffer);
    session = null;
    return true;
  }
  return false;
}

// ----- Unlocking ----------------------------------------------------------------

let unlocking: Promise<void> | null = null;
let cancelledAt = 0;

/** Asks Keyless to unlock. It asks the user itself: the computer password
 * prompt when that is on, otherwise a small Keyless window for the master
 * password. The main window stays as it was. */
function requestUnlock(): Promise<void> {
  unlocking ??= call("unlock", {}, slow)
    .then(unlocked)
    .catch((err) => {
      if (err instanceof BridgeError && err.message === "cancelled") cancelledAt = Date.now();
      throw err;
    })
    .finally(() => {
      unlocking = null;
    });
  return unlocking;
}

/** Tells open Keyless menus to refresh. */
async function unlocked(): Promise<void> {
  await chrome.storage.session.set({ unlockedAt: Date.now() }).catch(() => undefined);
}

// ----- Filling ----------------------------------------------------------------

function isWebPage(url: string | undefined): url is string {
  return Boolean(url && /^https?:/.test(url));
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** Fills a login into the top frame of a tab. The content script checks that
 * the page is still on the origin the credentials were checked against. */
async function fillTab(tabId: number, url: string, id: string, options: { submit?: boolean; anySite?: boolean } = {}): Promise<void> {
  const credentials = await call<Credentials>("credentials", { id, url, anySite: Boolean(options.anySite) });
  await chrome.tabs.sendMessage(
    tabId,
    { type: "keyless-fill", ...credentials, origin: new URL(url).origin, submit: Boolean(options.submit) },
    { frameId: 0 },
  );
}

// ----- Menus inside pages -------------------------------------------------------

const tokenKey = (tabId: number) => `frame:${tabId}`;

async function validToken(tabId: number, token: unknown): Promise<boolean> {
  if (typeof token !== "string" || token.length < 32) return false;
  const key = tokenKey(tabId);
  const stored = (await chrome.storage.session.get(key))[key];
  return typeof stored === "string" && stored === token;
}

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(tokenKey(tabId)).catch(() => undefined);
});

async function inlineState(url: string | null): Promise<InlineState> {
  const host = url ? new URL(url).hostname.replace(/^www\./, "") : null;
  const current = await quickStatus();
  if (current.state !== "ready" || !url) return { state: current.state, url, host, logins: [] };
  return { state: "ready", url, host, logins: await call<Login[]>("match", { url }) };
}

// ----- Message routing ----------------------------------------------------------

type Reply = { ok: true; data?: unknown } | { ok: false; error: string };

async function handlePopup(message: any): Promise<Reply> {
  switch (message.type) {
    case "status":
      return { ok: true, data: await status() };
    case "pair":
      return { ok: true, data: await pair() };
    case "launch":
      await native.send({ type: "launch" }).catch(() => undefined);
      return { ok: true };
    case "unlock": {
      // Opening the popup asks by itself, unless the user just cancelled.
      if (message.auto && !unlocking && Date.now() - cancelledAt < AUTO_PROMPT_COOLDOWN_MS) {
        return { ok: false, error: "skipped" };
      }
      await requestUnlock();
      // The prompt takes the focus, which closes the popup: open it again,
      // now unlocked.
      await chrome.action.openPopup?.().catch(() => undefined);
      return { ok: true };
    }
    case "tab_matches": {
      const tab = await activeTab();
      if (!isWebPage(tab?.url)) return { ok: true, data: { url: null, logins: [] } };
      const logins = await call<Login[]>("match", { url: tab.url });
      return { ok: true, data: { url: tab.url, logins } };
    }
    case "search":
      return { ok: true, data: await call<Login[]>("search", { query: String(message.query ?? "") }) };
    case "fill": {
      const tab = await activeTab();
      if (!tab?.id || !isWebPage(tab.url)) return { ok: false, error: "no_tab" };
      await fillTab(tab.id, tab.url, String(message.id), { anySite: Boolean(message.anySite) });
      return { ok: true };
    }
    case "copy":
      return { ok: true, data: await call("copy", { id: String(message.id), field: String(message.field) }) };
    default:
      return { ok: false, error: "bad_request" };
  }
}

async function handleInline(message: any, sender: chrome.runtime.MessageSender): Promise<Reply> {
  const tab = sender.tab;
  if (tab?.id === undefined || !(await validToken(tab.id, message.token))) return { ok: false, error: "forbidden" };
  const url = isWebPage(tab.url) ? tab.url : null;
  switch (message.type) {
    case "hello":
      return { ok: true };
    case "state":
      return { ok: true, data: await inlineState(url) };
    case "search":
      return { ok: true, data: await call<Login[]>("search", { query: String(message.query ?? "") }) };
    case "fill":
      if (!url) return { ok: false, error: "no_tab" };
      await fillTab(tab.id, url, String(message.id), { submit: Boolean(message.submit), anySite: Boolean(message.anySite) });
      return { ok: true };
    case "unlock":
      await requestUnlock();
      return { ok: true };
    default:
      return { ok: false, error: "bad_request" };
  }
}

async function handleContent(message: any, sender: chrome.runtime.MessageSender): Promise<Reply> {
  // Only the top frame of a regular web page.
  if (sender.frameId !== 0 || sender.tab?.id === undefined || !isWebPage(sender.url)) return { ok: false, error: "forbidden" };
  switch (message.type) {
    case "register":
      // The token the page's Keyless menus will present.
      if (typeof message.token !== "string" || message.token.length < 32) return { ok: false, error: "bad_request" };
      await chrome.storage.session.set({ [tokenKey(sender.tab.id)]: message.token });
      return { ok: true };
    case "page_state": {
      const current = await quickStatus();
      let count = 0;
      if (current.state === "ready") count = (await call<Login[]>("match", { url: sender.url })).length;
      const data: PageState = { state: current.state, count };
      return { ok: true, data };
    }
    default:
      return { ok: false, error: "bad_request" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  // Extension pages (the popup, also when opened in a tab, and the menus in
  // web pages) are served from the extension origin; content scripts report
  // the URL of the web page.
  const page = sender.url?.startsWith(EXTENSION_BASE) ? new URL(sender.url).pathname : null;
  const handler =
    page === "/popup.html" ? handlePopup(message) : page === "/inline.html" ? handleInline(message, sender) : page === null ? handleContent(message, sender) : null;
  if (!handler) return false;
  handler
    .then(sendResponse)
    .catch((err: Error) => sendResponse({ ok: false, error: err instanceof BridgeError ? err.message : "error" }));
  return true;
});

// Keyboard shortcut: fill the best match into the current page.
chrome.commands?.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tab = await activeTab();
  if (!tab?.id || !isWebPage(tab.url)) return;
  try {
    const logins = await call<Login[]>("match", { url: tab.url });
    if (logins.length > 0) await fillTab(tab.id, tab.url, logins[0].id);
  } catch {
    // Not connected or locked: the popup explains what to do.
  }
});
