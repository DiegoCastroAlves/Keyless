// Background script: owns the connection to the Keyless app.
//
// Messages from the popup (trusted extension page) may search all logins and
// fill or copy any of them. Messages from content scripts may only ask for
// logins matching the page they run in; the app re-checks the URL before
// returning credentials.

import { channelKey, equalBytes, fromBase64, identity, kvDelete, kvGet, kvSet, open, pairingCode, seal, toBase64 } from "./crypto";
import type { Login, Status } from "./types";

const HOST = "io.github.diegocastroalves.keyless";
const REQUEST_TIMEOUT_MS = 130_000;

type Pending = { resolve: (value: any) => void; reject: (reason: Error) => void };

class NativeConnection {
  private port: chrome.runtime.Port | null = null;
  private queue: Pending[] = [];
  lastError: string | null = null;

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
      const timer = setTimeout(() => reject(new Error("timeout")), REQUEST_TIMEOUT_MS);
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
    // the app. Require pairing again.
    session = null;
    await kvDelete("appPublic");
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

async function call<T = any>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!session) {
    const status = await connect();
    if (status.state !== "ready") throw new BridgeError(status.state);
  }
  const me = await identity();
  const request = { id: crypto.randomUUID(), ts: Date.now(), cmd, args };
  const { nonce, ct } = await seal(session!.key, request);
  let reply: any;
  try {
    reply = await native.send({ type: "enc", pub: toBase64(me.publicRaw), nonce, ct });
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

async function status(): Promise<Status> {
  const base = await connect();
  if (base.state !== "ready") return base;
  try {
    const result = await call<{ locked: boolean; email?: string }>("status");
    return result.locked ? { state: "locked" } : { state: "ready", email: result.email };
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

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function fillTab(tabId: number, url: string, id: string): Promise<void> {
  const credentials = await call<{ username: string; password: string; totp: string | null }>("credentials", { id, url });
  await chrome.tabs.sendMessage(tabId, { type: "keyless-fill", ...credentials }, { frameId: 0 });
}

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
    case "show_app":
      await call("show_app");
      return { ok: true };
    case "tab_matches": {
      const tab = await activeTab();
      if (!tab?.url || !/^https?:/.test(tab.url)) return { ok: true, data: { url: null, logins: [] } };
      const logins = await call<Login[]>("match", { url: tab.url });
      return { ok: true, data: { url: tab.url, logins } };
    }
    case "search":
      return { ok: true, data: await call<Login[]>("search", { query: String(message.query ?? "") }) };
    case "fill": {
      const tab = await activeTab();
      if (!tab?.id || !tab.url) return { ok: false, error: "no_tab" };
      await fillTab(tab.id, tab.url, String(message.id));
      return { ok: true };
    }
    case "copy":
      return { ok: true, data: await call("copy", { id: String(message.id), field: String(message.field) }) };
    default:
      return { ok: false, error: "bad_request" };
  }
}

async function handleContent(message: any, sender: chrome.runtime.MessageSender): Promise<Reply> {
  // Only the top frame of a regular web page.
  if (sender.frameId !== 0 || !sender.url || !/^https?:/.test(sender.url)) return { ok: false, error: "forbidden" };
  switch (message.type) {
    case "matches":
      return { ok: true, data: await call<Login[]>("match", { url: sender.url }) };
    case "credentials":
      return { ok: true, data: await call("credentials", { id: String(message.id), url: sender.url }) };
    case "show_app":
      await call("show_app");
      return { ok: true };
    default:
      return { ok: false, error: "bad_request" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  // Extension pages (the popup, also when opened in a tab) are served from the
  // extension origin; content scripts report the URL of the web page.
  const fromExtensionPage = Boolean(sender.url?.startsWith(chrome.runtime.getURL("")));
  (fromExtensionPage ? handlePopup(message) : handleContent(message, sender))
    .then(sendResponse)
    .catch((err: Error) => sendResponse({ ok: false, error: err instanceof BridgeError ? err.message : "error" }));
  return true;
});

// Keyboard shortcut: fill the best match into the current page.
chrome.commands?.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tab = await activeTab();
  if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) return;
  try {
    const logins = await call<Login[]>("match", { url: tab.url });
    if (logins.length > 0) await fillTab(tab.id, tab.url, logins[0].id);
  } catch {
    // Not connected or locked: the popup explains what to do.
  }
});
