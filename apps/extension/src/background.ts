// Background script: owns the connection to the Keyless app.
//
// Three kinds of callers, told apart by the sender:
// - the popup (trusted extension page): may search all logins, fill or copy
//   any of them and ask Keyless to unlock;
// - the Keyless menus shown inside web pages (inline.html, an extension page
//   in an iframe): may list the logins for the tab they are in, search, fill
//   into that tab and ask Keyless to unlock. They must present the token their content
//   script registered, so a page cannot embed them on its own;
// - content scripts (web page process): may only register that token, ask
//   how many logins match their page, ask Keyless to unlock (a click on the
//   Keyless button in a field) and report what the user typed in a login
//   form, for the "Save login?" prompt. Credentials never go to them
//   unless the user picked a login in the popup or a Keyless menu.
// The app re-checks every URL before returning credentials. The master
// password never goes through the extension: to unlock, Keyless asks the
// user itself (the system's password prompt or its own small window).

import { channelKey, equalBytes, fromBase64, identity, kvGet, kvSet, open, pairingCode, seal, toBase64 } from "./crypto";
import { loadSettings, siteKey, updateSettings } from "./settings";
import type { BrowserManager, Credentials, FormItems, InlineState, Login, PageState, SaveCandidate, SaveState, Status, Vault } from "./types";

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

// ----- Toolbar icon -------------------------------------------------------------

/** Same padlock as the app's tray icon (tray.rs), drawn over the logo. */
function drawPadlock(ctx: OffscreenCanvasRenderingContext2D, size: number) {
  const b = size * 0.62;
  const [ox, oy] = [size - b, size - b];
  const cx = ox + b / 2;
  const joint = oy + b * 0.46;
  const shape = (grow: number, color: string) => {
    ctx.fillStyle = ctx.strokeStyle = color;
    ctx.lineWidth = b * 0.12 + 2 * grow;
    ctx.beginPath();
    ctx.arc(cx, joint, b * 0.22, Math.PI, 0);
    ctx.stroke();
    ctx.beginPath();
    ctx.roundRect(ox + b * 0.16 - grow, joint - grow, b * 0.68 + 2 * grow, b * 0.52 + 2 * grow, b * 0.12 + grow);
    ctx.fill();
  };
  shape(Math.max(1, b * 0.09), "#ffffff");
  shape(0, "#111827");
  if (size >= 32) {
    ctx.fillStyle = "#ffffff";
    ctx.beginPath();
    ctx.arc(cx, oy + b * 0.71, b * 0.075, 0, 2 * Math.PI);
    ctx.fill();
  }
}

async function actionIcon(size: number, locked: boolean): Promise<ImageData> {
  const logo = await createImageBitmap(await (await fetch(chrome.runtime.getURL(`icons/icon-${size}.png`))).blob());
  const ctx = new OffscreenCanvas(size, size).getContext("2d")!;
  ctx.drawImage(logo, 0, 0, size, size);
  if (locked) drawPadlock(ctx, size);
  return ctx.getImageData(0, 0, size, size);
}

let shownState: Status["state"] | null = null;
let iconLocked: boolean | null = null;

/** Shows whether Keyless is locked: on the toolbar icon, on the Keyless
 * button in login fields (content scripts get the state, nothing else) and
 * in open Keyless menus (the card hides, the list offers to unlock). */
async function showState(state: Status["state"]): Promise<void> {
  if (shownState === state) return;
  shownState = state;
  formItems = null;
  const locked = state !== "ready";
  if (iconLocked !== locked) {
    iconLocked = locked;
    try {
      await chrome.action.setIcon({ imageData: { 16: await actionIcon(16, locked), 32: await actionIcon(32, locked) } });
      await chrome.action.setTitle({ title: locked ? chrome.i18n.getMessage("lockedTitle") : "Keyless" });
    } catch {
      iconLocked = null;
    }
  }
  for (const tab of await chrome.tabs.query({}).catch(() => [])) {
    if (tab.id !== undefined && isWebPage(tab.url)) {
      chrome.tabs.sendMessage(tab.id, { type: "keyless-state", state }, { frameId: 0 }).catch(() => undefined);
    }
  }
  await chrome.storage.session.set({ lockState: { locked, at: Date.now() } }).catch(() => undefined);
}

/** Full status for the popup, including the pairing code. */
async function status(): Promise<Status> {
  const base = await connect();
  if (base.state !== "ready") return base;
  return quickStatus();
}

/** Status over the existing channel, for frequent checks. */
async function quickStatus(): Promise<Status> {
  let current: Status;
  try {
    current = fromAppStatus(await call<AppStatus>("status"));
  } catch (err) {
    current = { state: err instanceof BridgeError ? (err.message as Status["state"]) : "error" };
  }
  void showState(current.state);
  return current;
}

/** Keeps the toolbar icon in step with the app: the app answers this long
 * poll as soon as it locks or unlocks. */
async function followLockState(): Promise<never> {
  const watcher = new NativeConnection();
  let known: boolean | undefined;
  for (;;) {
    try {
      const result = await call<AppStatus>("wait_status", known === undefined ? {} : { locked: known }, watcher);
      known = result.locked;
      await showState(result.locked ? "locked" : "ready");
    } catch (err) {
      // Not connected (app closed, browser not paired…): try again later.
      known = undefined;
      await showState(err instanceof BridgeError ? (err.message as Status["state"]) : "error");
      const missing = err instanceof BridgeError && err.message === "host_missing";
      await new Promise((resolve) => setTimeout(resolve, missing ? 60_000 : 10_000));
    }
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

async function unlocked(): Promise<void> {
  await showState("ready");
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
  const settings = await loadSettings();
  const credentials = await call<Credentials>("credentials", { id, url, anySite: Boolean(options.anySite) });
  await chrome.tabs.sendMessage(
    tabId,
    { type: "keyless-fill", ...credentials, origin: new URL(url).origin, submit: Boolean(options.submit) && settings.autoSubmit },
    { frameId: 0 },
  );
  // Ready to paste on the next step of the sign-in. Copied by the app, which
  // clears the clipboard after a while.
  if (settings.copyTotp && credentials.totp) await call("copy", { id, field: "totp" }).catch(() => undefined);
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

// ----- Cards and identities ---------------------------------------------------------

/** Kept a minute: asked on every page with a form. */
const FORM_ITEMS_TTL_MS = 60_000;
let formItems: { at: number; value: Promise<FormItems> } | null = null;

function getFormItems(): Promise<FormItems> {
  if (!formItems || Date.now() - formItems.at > FORM_ITEMS_TTL_MS) {
    const value = call<FormItems>("form_items");
    value.catch(() => (formItems = null));
    formItems = { at: Date.now(), value };
  }
  return formItems.value;
}

/** Cards are filled only where the connection is encrypted. */
function isSecurePage(url: string): boolean {
  const { protocol, hostname } = new URL(url);
  return protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(hostname);
}

// ----- Saving logins --------------------------------------------------------------
//
// What the user typed in a login or sign-up form waits here (in memory: the
// session storage is never written to disk) until they save it, dismiss it,
// or 5 minutes pass. Only the prompt's frame can save it, after the user
// chose to; it never sees the password.
//
// The prompt waits until signing in worked: the form went away, or the next
// page has no login form. It is only shown on the same site, and only a
// login it offered (one saved for that site) can be updated.

interface Capture {
  url: string;
  username: string;
  password: string;
  /** The current password, in a change-password form. */
  current: string;
  /** Signing in worked (or a suggested password was used): the prompt can show. */
  ready: boolean;
  /** Suggested by Keyless. */
  generated: boolean;
  /** Kept when a suggested password was filled; shown on the next page, in
   * case the form's submission was missed. */
  deferred: boolean;
  at: number;
  check: SaveCheck | null;
}

interface SaveCheck {
  state: "new" | "update" | "same";
  candidates: SaveCandidate[];
  title: string;
}

const CAPTURE_TTL_MS = 5 * 60_000;
/** A username typed in the first step of a two-step sign-in. */
const USERNAME_TTL_MS = 2 * 60_000;
const captureKey = (tabId: number) => `capture:${tabId}`;
const usernameKey = (tabId: number) => `username:${tabId}`;
const suggestionKey = (tabId: number) => `suggestion:${tabId}`;

async function sessionGet<T>(key: string): Promise<T | undefined> {
  return (await chrome.storage.session.get(key))[key] as T | undefined;
}

async function getCapture(tabId: number): Promise<Capture | null> {
  const capture = await sessionGet<Capture>(captureKey(tabId));
  return capture && Date.now() - capture.at < CAPTURE_TTL_MS ? capture : null;
}

async function setCapture(tabId: number, capture: Capture | null): Promise<void> {
  if (capture) await chrome.storage.session.set({ [captureKey(tabId)]: capture });
  else await chrome.storage.session.remove(captureKey(tabId));
}

/** Rough "same site" for pairing the two steps of a sign-in. */
function siteOf(url: string): string {
  const labels = new URL(url).hostname.split(".");
  const short = labels.length > 2 && labels[labels.length - 1].length === 2 && labels[labels.length - 2].length <= 3;
  return labels.slice(short ? -3 : -2).join(".");
}

/** "accounts.google.com" -> "Google" (the app suggests the same). */
function suggestedTitle(url: string): string {
  const name = siteOf(url).split(".")[0];
  return name.charAt(0).toUpperCase() + name.slice(1);
}

async function checkCapture(capture: Capture): Promise<SaveCheck | null> {
  try {
    return await call<SaveCheck>("check_login", {
      url: capture.url,
      username: capture.username,
      password: capture.password,
      current: capture.current || undefined,
    });
  } catch {
    return null;
  }
}

/** A login or sign-up form was submitted. The prompt shows once it worked. */
async function onCapture(tabId: number, url: string, username: string, password: string, currentPassword: string, generated: boolean): Promise<void> {
  if (!password) {
    // First step of a two-step sign-in: remember who is signing in.
    if (username) await chrome.storage.session.set({ [usernameKey(tabId)]: { url, username, at: Date.now() } });
    return;
  }
  if (!username) {
    const first = await sessionGet<{ url: string; username: string; at: number }>(usernameKey(tabId));
    if (first && Date.now() - first.at < USERNAME_TTL_MS && siteOf(first.url) === siteOf(url)) username = first.username;
  }
  const previous = await getCapture(tabId);
  const capture: Capture = {
    url,
    username,
    password,
    current: currentPassword,
    ready: false,
    generated: generated || (previous?.generated === true && previous.password === password),
    deferred: false,
    at: Date.now(),
    check: null,
  };
  const current = await quickStatus();
  if (current.state === "ready") {
    capture.check = await checkCapture(capture);
    if (capture.check?.state === "same") {
      await setCapture(tabId, null);
      return;
    }
  } else if (current.state !== "locked") {
    return; // Not connected: nowhere to save it.
  }
  await setCapture(tabId, capture);
}

/** The page the prompt would show on belongs to the site the login was
 * typed in. */
function sameSite(capture: Capture, url: string | undefined): boolean {
  try {
    return url !== undefined && new URL(url).protocol === new URL(capture.url).protocol && siteOf(url) === siteOf(capture.url);
  } catch {
    return false;
  }
}

/** Signing in worked: shows the prompt on the page. */
async function captureDone(tabId: number, url: string): Promise<void> {
  const capture = await getCapture(tabId);
  if (!capture || capture.ready || !sameSite(capture, url)) return;
  capture.ready = true;
  await setCapture(tabId, capture);
  chrome.tabs.sendMessage(tabId, { type: "keyless-save" }, { frameId: 0 }).catch(() => undefined);
}

/** A page loaded in the tab: whether it shows the prompt. */
async function savePending(tabId: number, url: string, loginForm: boolean): Promise<boolean> {
  const capture = await getCapture(tabId);
  if (!capture || !sameSite(capture, url)) return false;
  if (capture.deferred) return capture.url !== url;
  if (!capture.ready) {
    // Back on a login form: signing in failed (the user tries again).
    if (loginForm) return false;
    capture.ready = true;
    await setCapture(tabId, capture);
  }
  return true;
}

async function saveState(tabId: number, url: string | undefined): Promise<SaveState | null> {
  const capture = await getCapture(tabId);
  if (!capture || !capture.ready || !sameSite(capture, url)) return null;
  const locked = (await quickStatus()).state !== "ready";
  if (!locked && !capture.check) {
    capture.check = await checkCapture(capture);
    if (capture.check?.state === "same") {
      await setCapture(tabId, null);
      return null;
    }
    await setCapture(tabId, capture);
  }
  return {
    locked,
    url: capture.url,
    host: new URL(capture.url).hostname.replace(/^www\./, ""),
    username: capture.username,
    generated: capture.generated,
    title: capture.check?.title ?? suggestedTitle(capture.url),
    state: capture.check?.state === "update" ? "update" : "new",
    candidates: capture.check?.candidates ?? [],
    vaults: locked ? [] : await call<Vault[]>("vaults").catch(() => []),
  };
}

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove([captureKey(tabId), usernameKey(tabId), suggestionKey(tabId)]).catch(() => undefined);
});

// ----- The browser's own password manager ------------------------------------------
//
// It offers to save and fill passwords, addresses and cards too, on top of the
// Keyless menus. The user can turn it off from the popup; this needs the
// optional "privacy" permission.

type BrowserSetting = chrome.types.ChromeSetting<boolean>;

function browserSettings(): BrowserSetting[] {
  const services = chrome.privacy?.services;
  if (!services) return [];
  // Firefox has only the first one.
  return [services.passwordSavingEnabled, services.autofillAddressEnabled, services.autofillCreditCardEnabled].filter(
    (s): s is BrowserSetting => Boolean(s),
  );
}

async function browserManagerState(): Promise<BrowserManager> {
  if (!(await chrome.permissions.contains({ permissions: ["privacy"] }))) return "unknown";
  const details = await Promise.all(browserSettings().map((s) => s.get({})));
  if (details.some((d) => d.levelOfControl === "controlled_by_other_extensions" || d.levelOfControl === "not_controllable")) return "other";
  if (details.some((d) => d.value)) return "on";
  // Keyless can only hand back what it turned off.
  return details.some((d) => d.levelOfControl === "controlled_by_this_extension") ? "off" : "off_browser";
}

async function applyBrowserManager(): Promise<void> {
  const wanted = await sessionGet<boolean>("browserManagerWanted");
  if (wanted === undefined || !(await chrome.permissions.contains({ permissions: ["privacy"] }))) return;
  await chrome.storage.session.remove("browserManagerWanted");
  for (const setting of browserSettings()) {
    // Turning it back on hands the setting back to the browser.
    if (wanted) await setting.clear({});
    else await setting.set({ value: false });
  }
}

chrome.permissions.onAdded.addListener(() => void applyBrowserManager().catch(() => undefined));

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
    case "settings": {
      const tab = await activeTab();
      return { ok: true, data: { settings: await loadSettings(), site: siteKey(isWebPage(tab?.url) ? tab.url : null) } };
    }
    case "set_settings":
      return { ok: true, data: await updateSettings(message.settings) };
    case "browser_manager":
      return { ok: true, data: await browserManagerState() };
    case "set_browser_manager":
      // Applied now if the "privacy" permission is there, otherwise once the
      // user grants it (the popup asks).
      await chrome.storage.session.set({ browserManagerWanted: message.enabled === true });
      await applyBrowserManager();
      return { ok: true };
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
    case "fill":
      // Only the page's own logins: a login saved for another site is filled
      // from the toolbar popup, which a page cannot cover or fake.
      if (!url) return { ok: false, error: "no_tab" };
      await fillTab(tab.id, url, String(message.id), { submit: Boolean(message.submit) });
      return { ok: true };
    case "unlock":
      await requestUnlock();
      return { ok: true };
    case "save_state":
      return { ok: true, data: await saveState(tab.id, tab.url) };
    case "save": {
      const capture = await getCapture(tab.id);
      if (!capture || !capture.ready || !sameSite(capture, tab.url)) return { ok: false, error: "expired" };
      const username = typeof message.username === "string" ? message.username.trim() : capture.username;
      if (message.mode === "update") {
        // Only a login the prompt offered: one saved for this site.
        const id = String(message.itemId ?? "");
        if (!capture.check?.candidates.some((c) => c.id === id)) return { ok: false, error: "bad_request" };
        await call("update_login", { id, url: capture.url, username, password: capture.password });
      } else {
        const vaultId = typeof message.vaultId === "string" ? message.vaultId : undefined;
        await call("save_login", { url: capture.url, title: String(message.title ?? ""), username, password: capture.password, vaultId });
      }
      await setCapture(tab.id, null);
      formItems = null;
      await chrome.storage.session.set({ itemsChangedAt: Date.now() }).catch(() => undefined);
      return { ok: true };
    }
    case "form_items":
      return { ok: true, data: await getFormItems() };
    case "fill_form": {
      if (!url) return { ok: false, error: "no_tab" };
      const data = await call<{ kind: string }>("form_details", { id: String(message.id ?? "") });
      if (data.kind === "card" && !isSecurePage(url)) return { ok: false, error: "insecure_page" };
      await chrome.tabs.sendMessage(tab.id, { type: "keyless-fill-form", ...data, origin: new URL(url).origin }, { frameId: 0 });
      return { ok: true };
    }
    case "dismiss_save":
      await setCapture(tab.id, null);
      return { ok: true };
    case "never_save": {
      // Never offered again on this site (removable in the popup's settings).
      const capture = await getCapture(tab.id);
      const site = siteKey(capture?.url);
      if (!capture || !site || !sameSite(capture, tab.url)) return { ok: false, error: "expired" };
      const settings = await loadSettings();
      await updateSettings({ neverSave: [...settings.neverSave, site] });
      await setCapture(tab.id, null);
      return { ok: true };
    }
    case "suggest": {
      // Generated by the app; kept here so only what was shown gets filled.
      const maxLength = Number(message.maxLength) || 0;
      const result = await call<{ password: string }>("suggest_password", { maxLength, symbols: message.symbols !== false });
      await chrome.storage.session.set({ [suggestionKey(tab.id)]: result.password });
      return { ok: true, data: result.password };
    }
    case "use_suggested": {
      if (!url) return { ok: false, error: "no_tab" };
      const password = await sessionGet<string>(suggestionKey(tab.id));
      if (typeof password !== "string") return { ok: false, error: "expired" };
      await chrome.storage.session.remove(suggestionKey(tab.id));
      await chrome.tabs.sendMessage(tab.id, { type: "keyless-fill-new", password, origin: new URL(url).origin }, { frameId: 0 });
      // In the app's generator history, in case the sign-up is never saved.
      await call("remember_generated", { password, url }).catch(() => undefined);
      // Not lost if the form's submission is missed: offered on the next page.
      const previous = await getCapture(tab.id);
      await setCapture(tab.id, {
        url,
        username: previous?.username ?? "",
        password,
        current: "",
        ready: true,
        generated: true,
        deferred: true,
        at: Date.now(),
        check: null,
      });
      return { ok: true };
    }
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
    case "unlock":
      // Keyless asks for the password in its own window or the system's:
      // nothing secret goes through the page.
      await requestUnlock();
      return { ok: true };
    case "capture": {
      const settings = await loadSettings();
      const site = siteKey(sender.url);
      if (!settings.offerSave || !site || settings.neverSave.includes(site) || settings.hidden.includes(site)) return { ok: true };
      const text = (value: unknown) => (typeof value === "string" ? value : "");
      await onCapture(sender.tab.id, sender.url, text(message.username).trim(), text(message.password), text(message.current), message.generated === true);
      return { ok: true };
    }
    case "capture_done":
      // The login form went away without leaving the page.
      await captureDone(sender.tab.id, sender.url);
      return { ok: true };
    case "save_pending":
      // A prompt to show on this page: after signing in worked, or on the
      // next page after a suggested password was used.
      return { ok: true, data: await savePending(sender.tab.id, sender.url, message.loginForm === true) };
    case "page_state": {
      const current = await quickStatus();
      const settings = await loadSettings();
      const site = siteKey(sender.url);
      const hidden = site !== null && settings.hidden.includes(site);
      const data: PageState = { state: current.state, count: 0, hidden, card: settings.signInCard && !hidden, autoOpen: settings.autoOpen };
      if (hidden) return { ok: true, data };
      if (current.state === "ready") {
        data.count = (await call<Login[]>("match", { url: sender.url })).length;
        const items = await getFormItems().catch(() => null);
        data.cards = items?.cards.length ?? 0;
        data.identities = items?.identities.length ?? 0;
      }
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

void followLockState();
