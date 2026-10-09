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
import type { BrowserManager, Credentials, FormItems, InlineState, Login, PageState, PasskeyEntry, SaveCandidate, SaveState, Status, Vault } from "./types";

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
      // Every frame: they show the Keyless button too.
      chrome.tabs.sendMessage(tab.id, { type: "keyless-state", state }).catch(() => undefined);
    }
  }
  await chrome.storage.session.set({ lockState: { locked, at: Date.now() } }).catch(() => undefined);
  // Passkeys waiting in pages' fields can be listed now.
  if (!locked) void refreshConditional();
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

/** Fills a login into a frame of the tab (the page itself by default). The
 * app checks the login against `url`, the address of that frame, and the
 * content script that the frame is still on that origin. `code`: only its
 * one-time code. */
async function fillTab(
  tabId: number,
  url: string,
  id: string,
  options: { submit?: boolean; anySite?: boolean; frameId?: number; code?: boolean } = {},
): Promise<void> {
  const settings = await loadSettings();
  const credentials = await call<Credentials>("credentials", { id, url, anySite: Boolean(options.anySite) });
  const filled = (await chrome.tabs.sendMessage(
    tabId,
    {
      type: "keyless-fill",
      ...credentials,
      origin: new URL(url).origin,
      submit: Boolean(options.submit) && settings.autoSubmit,
      codeOnly: Boolean(options.code),
    },
    { frameId: options.frameId ?? 0 },
  )) as { otp?: boolean } | undefined;
  // Not filled now (it is asked on the next step of the sign-in): ready to
  // paste. Copied by the app, which clears the clipboard after a while.
  if (credentials.totp && !filled?.otp && (settings.copyTotp || options.code)) await call("copy", { id, field: "totp" }).catch(() => undefined);
}

/** Frames report at the same time: updates of what is kept for a tab (read,
 * change, write) run one at a time, or one would undo another. */
let storageQueue: Promise<unknown> = Promise.resolve();
function serially<T>(task: () => Promise<T>): Promise<T> {
  const run = storageQueue.then(task, task);
  storageQueue = run.catch(() => undefined);
  return run;
}

// ----- Login forms in frames ----------------------------------------------------
//
// Content scripts in every frame report whether their frame has a login form
// (or asks for a one-time code). The popup and the keyboard shortcuts fill
// them; frames also show the Keyless button and menu (see content.ts). A
// login is always matched against the address of the frame that receives it,
// never the tab's, and the popup fills a frame from another site than the
// page only after the user confirms.

const framesKey = (tabId: number) => `loginFrames:${tabId}`;

interface LoginFrame {
  frameId: number;
  url: string;
  /** It asks only for a one-time code (the sign-in's next step). */
  code?: boolean;
}

/** Stored as the frame's address, with "#code" for a frame asking only for a
 * one-time code. */
async function loginFrames(tabId: number): Promise<LoginFrame[]> {
  const frames = (await sessionGet<Record<string, string>>(framesKey(tabId))) ?? {};
  return Object.entries(frames)
    .map(([frameId, value]) => ({ frameId: Number(frameId), url: value.replace(/#code$/, ""), code: value.endsWith("#code") }))
    .sort((a, b) => a.frameId - b.frameId);
}

function setLoginFrame(tabId: number, frameId: number, url: string | null, code = false): Promise<void> {
  return serially(() => saveLoginFrame(tabId, frameId, url, code));
}

async function saveLoginFrame(tabId: number, frameId: number, url: string | null, code: boolean): Promise<void> {
  const key = framesKey(tabId);
  const frames = (await sessionGet<Record<string, string>>(key)) ?? {};
  if (url) frames[frameId] = code ? `${url.replace(/#.*$/, "")}#code` : url;
  else delete frames[frameId];
  await chrome.storage.session.set({ [key]: frames });
}

chrome.tabs.onUpdated.addListener((tabId, change) => {
  // A new page: its frames report again.
  if (change.status === "loading" && change.url) void chrome.storage.session.remove(framesKey(tabId)).catch(() => undefined);
});
chrome.tabs.onRemoved.addListener((tabId) => void chrome.storage.session.remove(framesKey(tabId)).catch(() => undefined));

/** Logins for the tab, each with the frame it goes into: frames with a login
 * form first (the page itself before frames inside it), then the page.
 * Logins for a frame from another site carry that frame's host. */
async function tabLogins(tab: chrome.tabs.Tab & { url: string; id: number }): Promise<{ login: Login; frame: LoginFrame }[]> {
  const reported = await loginFrames(tab.id);
  const top: LoginFrame = { frameId: 0, url: tab.url, code: reported.find((f) => f.frameId === 0)?.code };
  const withForms = reported.filter((f) => isWebPage(f.url)).map((f) => (f.frameId === 0 ? top : f));
  const frames = withForms.some((f) => f.frameId === 0) ? withForms : [...withForms, top];
  const seen = new Set<string>();
  const result: { login: Login; frame: LoginFrame }[] = [];
  for (const frame of frames) {
    for (const login of await call<Login[]>("match", { url: frame.url })) {
      if (seen.has(login.id)) continue;
      seen.add(login.id);
      const other = frame.frameId !== 0 && !(await sameSites(frame.url, tab.url));
      result.push({ login: other ? { ...login, frame: new URL(frame.url).hostname } : login, frame });
    }
  }
  return result;
}

/** The frame a login goes into (see `tabLogins`). */
async function fillTarget(tab: chrome.tabs.Tab & { url: string; id: number }, id: string): Promise<LoginFrame | null> {
  const match = (await tabLogins(tab)).find((entry) => entry.login.id === id);
  return match?.frame ?? null;
}

// ----- Menus inside pages -------------------------------------------------------

// Each frame's content script registers a random token, which its menus
// present: a menu acts only for its own frame, with that frame's address
// (from the browser, never from the page).

const tokenKey = (tabId: number) => `frames:${tabId}`;

interface Registration {
  frameId: number;
  url: string;
}

/** Frames of a tab with menus, by token. */
async function registrations(tabId: number): Promise<Record<string, Registration>> {
  return (await sessionGet<Record<string, Registration>>(tokenKey(tabId))) ?? {};
}

/** The frame a menu's token was registered by. */
async function registration(tabId: number, token: unknown): Promise<Registration | null> {
  if (typeof token !== "string" || token.length < 32) return null;
  return (await registrations(tabId))[token] ?? null;
}

function register(tabId: number, frameId: number, url: string, token: string): Promise<void> {
  return serially(() => saveRegistration(tabId, frameId, url, token));
}

async function saveRegistration(tabId: number, frameId: number, url: string, token: string): Promise<void> {
  const all = await registrations(tabId);
  // A new page in the frame: its old token goes.
  for (const [other, reg] of Object.entries(all)) if (reg.frameId === frameId) delete all[other];
  const entries = Object.entries(all).slice(-63);
  await chrome.storage.session.set({ [tokenKey(tabId)]: Object.fromEntries([...entries, [token, { frameId, url }]]) });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(tokenKey(tabId)).catch(() => undefined);
});

async function inlineState(url: string | null, tabId: number, frameId: number): Promise<InlineState> {
  const host = url ? new URL(url).hostname.replace(/^www\./, "") : null;
  const current = await quickStatus();
  if (current.state !== "ready" || !url) return { state: current.state, url, host, logins: [] };
  const waiting = conditionalRequests.get(frameKey(tabId, frameId));
  const passkeys = waiting ? await conditionalPasskeys(waiting) : [];
  return { state: "ready", url, host, logins: await call<Login[]>("match", { url }), passkeys };
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

/** Payment services whose frames hold a shop's card fields (one frame per
 * field, often): filled with the card along with the shop's own fields. */
const PAYMENT_SITES = new Set([
  "stripe.com",
  "stripe.network",
  "braintreegateway.com",
  "braintree-api.com",
  "adyen.com",
  "adyenpayments.com",
  "paypal.com",
  "squareup.com",
  "squarecdn.com",
  "checkout.com",
  "mercadopago.com",
  "mercadopago.com.br",
  "pagar.me",
  "pagseguro.com.br",
  "recurly.com",
  "chargebee.com",
  "spreedly.com",
  "shopifyinc.com",
  "worldpay.com",
  "authorize.net",
  "cybersource.com",
  "ebanx.com",
  "iugu.com",
  "cielo.com.br",
  "getnet.com.br",
  "paddle.com",
  "razorpay.com",
  "mollie.com",
  "bluesnap.com",
  "nuvei.com",
  "globalpay.com",
  "vgs.io",
  "verygoodvault.com",
  "evervault.com",
  "basistheory.com",
]);

interface FormFrame {
  frameId: number;
  url: string;
  card: boolean;
  identity: boolean;
}

/** Answers to "which frames have card or address fields?", by question. */
const formAnswers = new Map<string, FormFrame[]>();

/** Asks every frame of the tab, now, which have card or address fields
 * (frames come and go: nothing is kept between fills). */
async function formFrames(tabId: number): Promise<FormFrame[]> {
  const nonce = crypto.randomUUID();
  formAnswers.set(nonce, []);
  await chrome.tabs.sendMessage(tabId, { type: "keyless-forms", nonce }).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 250));
  const frames = formAnswers.get(nonce) ?? [];
  formAnswers.delete(nonce);
  return frames;
}

/** Where a card or an identity picked in a frame's menu goes: that frame,
 * and the tab's other frames with such fields that are of its site or the
 * page's, or (cards) a payment service's. Never other sites' frames (ads,
 * widgets) that happen to ask for a card. Cards only on encrypted pages. */
async function formTargets(tabId: number, tabUrl: string, from: Registration, kind: "card" | "identity"): Promise<Registration[]> {
  const targets: Registration[] = [from];
  const others = (await formFrames(tabId)).filter((frame) => frame.frameId !== from.frameId && frame[kind]);
  if (others.length === 0) return targets;
  const [fromSite, topSite, ...sites] = await sitesOf(from.url, tabUrl, ...others.map((frame) => frame.url));
  others.forEach((frame, i) => {
    const site = sites[i];
    const related = site !== "" && (site === fromSite || site === topSite || (kind === "card" && PAYMENT_SITES.has(site)));
    if (related && (kind !== "card" || isSecurePage(frame.url))) targets.push({ frameId: frame.frameId, url: frame.url });
  });
  return targets;
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

/** Rough site of a URL, without the Public Suffix List: for titles, and
 * when the app cannot tell (see `sitesOf`). */
function roughSite(url: string): string {
  const labels = new URL(url).hostname.split(".");
  const short = labels.length > 2 && labels[labels.length - 1].length === 2 && labels[labels.length - 2].length <= 3;
  return labels.slice(short ? -3 : -2).join(".");
}

/** Sites the app worked out, by host. */
const siteCache = new Map<string, string>();

/** Each URL's site (registrable domain) as the app works it out from the
 * Public Suffix List, so alice.github.io and bob.github.io are different
 * sites. "" when unknown, which matches nothing. */
async function sitesOf(...urls: (string | undefined)[]): Promise<string[]> {
  const hosts = urls.map((url) => {
    try {
      return url ? new URL(url).hostname : "";
    } catch {
      return "";
    }
  });
  const missing = [...new Set(hosts.filter((host) => host && !siteCache.has(host)))];
  if (missing.length > 0) {
    try {
      const found = await call<unknown[]>("sites", { hosts: missing });
      if (siteCache.size > 500) siteCache.clear();
      missing.forEach((host, i) => typeof found[i] === "string" && found[i] && siteCache.set(host, found[i] as string));
    } catch {
      // An app from before this: the rough way, as it always was.
      return urls.map((url) => {
        try {
          return url ? roughSite(url) : "";
        } catch {
          return "";
        }
      });
    }
  }
  return hosts.map((host) => siteCache.get(host) ?? "");
}

async function sameSites(a: string | undefined, b: string | undefined): Promise<boolean> {
  const [first, second] = await sitesOf(a, b);
  return first !== "" && first === second;
}

/** "accounts.google.com" -> "Google" (the app suggests the same). */
function suggestedTitle(url: string): string {
  const name = roughSite(url).split(".")[0];
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
    if (first && Date.now() - first.at < USERNAME_TTL_MS && (await sameSites(first.url, url))) username = first.username;
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
async function sameSite(capture: Capture, url: string | undefined): Promise<boolean> {
  try {
    if (url === undefined || new URL(url).protocol !== new URL(capture.url).protocol) return false;
  } catch {
    return false;
  }
  return sameSites(url, capture.url);
}

/** Signing in worked: shows the prompt on the page. */
async function captureDone(tabId: number, url: string): Promise<void> {
  const capture = await getCapture(tabId);
  if (!capture || capture.ready || !(await sameSite(capture, url))) return;
  capture.ready = true;
  await setCapture(tabId, capture);
  chrome.tabs.sendMessage(tabId, { type: "keyless-save" }, { frameId: 0 }).catch(() => undefined);
}

/** A page loaded in the tab: whether it shows the prompt. */
async function savePending(tabId: number, url: string, loginForm: boolean): Promise<boolean> {
  const capture = await getCapture(tabId);
  if (!capture || !(await sameSite(capture, url))) return false;
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
  if (!capture || !capture.ready || !(await sameSite(capture, url))) return null;
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

// ----- Passkeys -----------------------------------------------------------------
//
// A site's passkey request (webauthn-page.ts, relayed by webauthn.ts) waits
// here while the user decides in Keyless's prompt at the top of the page
// (inline.html#passkey, like 1Password's), with the same protection against
// clickjacking as the menus that fill passwords; where the page cannot show
// it, in a Keyless window (passkey.html). The page's origin comes from the
// browser; the app checks it against the relying party. "Use another
// device", or closing the prompt, hands the request back to the browser's
// own WebAuthn (like Bitwarden), which also happens silently when Keyless
// cannot help (not connected, turned off, or hidden on the site). The
// window's Cancel refuses it. The prompt opens even when there is no passkey
// to sign in with: answering at once would tell any page, without the user
// doing anything, whether Keyless has a passkey for it.
//
// Frames: the request is the frame's (its origin, from the browser). For a
// frame of another origin than the page, which webauthn.ts lets through only
// where the page allows passkeys in it, the app also names the page, and the
// window says the request comes from inside it.
//
// Passkeys offered in the page's fields (conditional mediation) open no
// window: the request waits here, and the frame's Keyless menu lists the
// passkeys under fields that ask for them (autocomplete "webauthn"). Picking
// one there signs in.

interface PasskeyRequest {
  id: string;
  tabId: number;
  frameId: number;
  origin: string;
  host: string;
  /** The page's origin, for a frame of another origin inside it. */
  topOrigin: string | null;
  request: any;
  port: chrome.runtime.Port;
  windowId: number | null;
  /** Shown in the page's own prompt (not a window). */
  inPage: boolean;
  timer: ReturnType<typeof setTimeout> | undefined;
}

const passkeyRequests = new Map<string, PasskeyRequest>();
/** Waiting for a pick in a Keyless menu, by frame (see `frameKey`). */
const conditionalRequests = new Map<string, PasskeyRequest>();
const frameKey = (tabId: number, frameId: number) => `${tabId}:${frameId}`;

function finishPasskey(entry: PasskeyRequest, answer: unknown) {
  if (!passkeyRequests.delete(entry.id)) return;
  clearTimeout(entry.timer);
  try {
    entry.port.postMessage(answer);
  } catch {
    // The page went away.
  }
  if (entry.windowId !== null) void chrome.windows.remove(entry.windowId).catch(() => undefined);
  if (entry.inPage) void chrome.tabs.sendMessage(entry.tabId, { type: "keyless-passkey-close" }, { frameId: 0 }).catch(() => undefined);
}

/** Ends a request waiting in the page's fields; `null`: the page ended it. */
function finishConditional(entry: PasskeyRequest, answer: unknown) {
  const key = frameKey(entry.tabId, entry.frameId);
  if (conditionalRequests.get(key) !== entry) return;
  conditionalRequests.delete(key);
  if (answer !== null) {
    try {
      entry.port.postMessage(answer);
    } catch {
      // The page went away.
    }
  }
  void tellFrame(entry, 0);
}

/** The passkeys a request waiting in the page's fields can sign in with
 * (none while locked). */
async function conditionalPasskeys(entry: PasskeyRequest): Promise<PasskeyEntry[]> {
  if ((await quickStatus()).state !== "ready") return [];
  return call<PasskeyEntry[]>("passkey_list", {
    origin: entry.origin,
    rpId: entry.request.rpId,
    allowCredentials: entry.request.allowCredentials,
  }).catch(() => []);
}

/** Tells the frame's content script how many passkeys its fields offer. */
async function tellFrame(entry: PasskeyRequest, count: number) {
  await chrome.tabs.sendMessage(entry.tabId, { type: "keyless-passkeys", count }, { frameId: entry.frameId }).catch(() => undefined);
}

/** Unlocked: the requests waiting in pages now have passkeys to offer. */
async function refreshConditional() {
  for (const entry of conditionalRequests.values()) await tellFrame(entry, (await conditionalPasskeys(entry)).length);
}

/** A page where passkeys may be used: https, or the local computer. */
function passkeyOrigin(url: string | undefined): { origin: string; host: string } | null {
  try {
    const parsed = new URL(url ?? "");
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && parsed.hostname === "localhost")) return null;
    return { origin: parsed.origin, host: parsed.hostname };
  } catch {
    return null;
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "keyless-webauthn") return;
  const sender = port.sender;
  // A page (or a frame in it) where passkeys may be used.
  const page = passkeyOrigin(sender?.url);
  if (sender?.id !== chrome.runtime.id || sender.frameId === undefined || sender.tab?.id === undefined || !page) {
    port.postMessage({ fallback: true });
    return;
  }
  const tabId = sender.tab.id;
  const frameId = sender.frameId;
  const tabUrl = sender.tab.url;
  let started = false;
  port.onMessage.addListener((request) => {
    // The first message is the request; the ones after it keep this awake.
    if (started) return;
    started = true;
    let topOrigin: string | null = null;
    if (frameId !== 0 && request?.crossOrigin === true) {
      const top = passkeyOrigin(tabUrl);
      if (!top) return port.postMessage({ fallback: true });
      topOrigin = top.origin;
    }
    void startPasskey(port, { tabId, frameId, ...page, topOrigin }, request);
  });
});

async function startPasskey(
  port: chrome.runtime.Port,
  where: { tabId: number; frameId: number; origin: string; host: string; topOrigin: string | null },
  request: any,
) {
  const fallback = () => port.postMessage({ fallback: true });
  if (request?.kind !== "create" && request?.kind !== "get") return fallback();
  const settings = await loadSettings();
  const sites = [siteKey(where.origin), siteKey(where.topOrigin)].filter((site): site is string => site !== null);
  if (!settings.passkeys || sites.some((site) => settings.hidden.includes(site))) return fallback();
  const conditional = request.kind === "get" && request.conditional === true;
  const current = await quickStatus();
  const connected = current.state === "ready" || current.state === "locked";
  // Passkeys for the page's fields wait even while Keyless cannot be reached
  // (the browser just started, the app is opening): they are offered once it
  // can, and the app checks the site when it lists them and signs.
  if (!connected && !conditional) return fallback();
  if (connected) {
    // A site that names another site's relying party is refused before the
    // user sees anything.
    try {
      await call("passkey_check", { origin: where.origin, rpId: request.rpId });
    } catch (err) {
      const code = err instanceof BridgeError ? err.message : "error";
      if (code === "rp_id_mismatch" || code === "insecure_page") return port.postMessage({ ok: false, error: "security" });
      if (!conditional) return fallback();
    }
  }
  const entry: PasskeyRequest = { id: crypto.randomUUID(), ...where, request, port, windowId: null, inPage: false, timer: undefined };
  if (conditional) return startConditional(entry);

  // One request per tab, like the browser. Passkeys offered in the page's
  // fields stay: pages call those off themselves first (the browser
  // requires it), and may offer them again after.
  for (const other of passkeyRequests.values()) {
    if (other.tabId === where.tabId) finishPasskey(other, { ok: false, error: "cancelled" });
  }
  const ms = Math.min(Math.max(Number(request.timeout) || 300_000, 30_000), 600_000);
  entry.timer = setTimeout(() => finishPasskey(entry, { ok: false, error: "cancelled" }), ms);
  passkeyRequests.set(entry.id, entry);
  port.onDisconnect.addListener(() => finishPasskey(entry, null));
  // The page's prompt, or a window where the page cannot show it.
  const shown = await chrome.tabs.sendMessage(where.tabId, { type: "keyless-passkey-prompt" }, { frameId: 0 }).catch(() => false);
  if (shown === true) {
    entry.inPage = true;
    return;
  }
  const window = await chrome.windows
    .create({ url: chrome.runtime.getURL(`passkey.html#${entry.id}`), type: "popup", width: 440, height: 560, focused: true })
    .catch(() => null);
  if (!window?.id) return finishPasskey(entry, { fallback: true });
  entry.windowId = window.id;
}

/** A request for the page's fields: waits for a pick in the frame's menu. No
 * time limit: the page ends it (or leaves). */
async function startConditional(entry: PasskeyRequest) {
  const key = frameKey(entry.tabId, entry.frameId);
  const previous = conditionalRequests.get(key);
  if (previous) finishConditional(previous, { ok: false, error: "cancelled" });
  conditionalRequests.set(key, entry);
  entry.port.onDisconnect.addListener(() => finishConditional(entry, null));
  await tellFrame(entry, (await conditionalPasskeys(entry)).length);
}

chrome.windows.onRemoved.addListener((windowId) => {
  // Closing the Keyless window hands the request to the browser.
  for (const entry of passkeyRequests.values()) {
    if (entry.windowId === windowId) {
      entry.windowId = null;
      finishPasskey(entry, { fallback: true });
    }
  }
});

/** What the Keyless window shows. */
async function passkeyView(entry: PasskeyRequest) {
  const locked = (await quickStatus()).state !== "ready";
  const base = {
    kind: entry.request.kind,
    host: entry.host,
    rpId: entry.request.rpId ?? entry.host,
    locked,
    // Asked from a frame of another site inside this page.
    topHost: entry.topOrigin ? new URL(entry.topOrigin).hostname : undefined,
  };
  if (locked) return base;
  if (entry.request.kind === "create") {
    const logins = await call<Login[]>("match", { url: entry.origin }).catch(() => []);
    // The site lists the passkeys it already has for this account.
    const excluded = entry.request.excludeCredentials as string[];
    const exists =
      excluded.length > 0 &&
      (await call<unknown[]>("passkey_list", { origin: entry.origin, rpId: entry.request.rpId, allowCredentials: excluded }).catch(() => [])).length > 0;
    return { ...base, rpName: entry.request.rpName, userName: entry.request.userName || entry.request.userDisplayName, logins, exists };
  }
  const passkeys = await call<unknown[]>("passkey_list", {
    origin: entry.origin,
    rpId: entry.request.rpId,
    allowCredentials: entry.request.allowCredentials,
  }).catch(() => []);
  return { ...base, passkeys };
}

/** Signs in with a passkey the user picked, for a request. */
function passkeyGet(entry: PasskeyRequest, credentialId: string) {
  const r = entry.request;
  return call("passkey_get", {
    origin: entry.origin,
    topOrigin: entry.topOrigin ?? undefined,
    rpId: r.rpId,
    challenge: r.challenge,
    credentialId,
    prf: r.prf,
  });
}

async function handlePasskeyWindow(message: any): Promise<Reply> {
  const entry = passkeyRequests.get(String(message.id ?? ""));
  if (!entry || entry.inPage) return { ok: false, error: "expired" };
  return handlePasskey(entry, message);
}

/** What the passkey prompt (or window) asks for a request. */
async function handlePasskey(entry: PasskeyRequest, message: any): Promise<Reply> {
  switch (message.type) {
    case "passkey_view":
      return { ok: true, data: await passkeyView(entry) };
    case "passkey_unlock":
      await requestUnlock();
      return { ok: true, data: await passkeyView(entry) };
    case "passkey_fallback":
      finishPasskey(entry, { fallback: true });
      return { ok: true };
    case "passkey_cancel":
      // The account already had a passkey: the site is told so.
      finishPasskey(entry, { ok: false, error: message.exists === true ? "exists" : "cancelled" });
      return { ok: true };
    case "passkey_choose": {
      const r = entry.request;
      try {
        const credential =
          r.kind === "create"
            ? await call("passkey_create", {
                origin: entry.origin,
                topOrigin: entry.topOrigin ?? undefined,
                rpId: r.rpId,
                rpName: r.rpName,
                userId: r.userId,
                userName: r.userName,
                userDisplayName: r.userDisplayName,
                challenge: r.challenge,
                algorithms: r.algorithms,
                excludeCredentials: r.excludeCredentials,
                prf: r.prf,
                itemId: typeof message.itemId === "string" ? message.itemId : "",
              })
            : await passkeyGet(entry, String(message.credentialId ?? ""));
        finishPasskey(entry, { ok: true, credential });
        if (r.kind === "create") await chrome.storage.session.set({ itemsChangedAt: Date.now() }).catch(() => undefined);
        return { ok: true };
      } catch (err) {
        const code = err instanceof BridgeError ? err.message : "error";
        // Already there, or a site Keyless refuses: the page is told.
        if (code === "exists" || code === "rp_id_mismatch" || code === "unsupported" || code === "insecure_page") {
          finishPasskey(entry, { ok: false, error: code === "exists" ? "exists" : code === "unsupported" ? "unsupported" : "security" });
        }
        return { ok: false, error: code };
      }
    }
    default:
      return { ok: false, error: "bad_request" };
  }
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
      if (tab?.id === undefined || !isWebPage(tab.url)) return { ok: true, data: { url: null, logins: [] } };
      const logins = (await tabLogins({ ...tab, id: tab.id, url: tab.url })).map((entry) => entry.login);
      return { ok: true, data: { url: tab.url, logins } };
    }
    case "search":
      return { ok: true, data: await call<Login[]>("search", { query: String(message.query ?? "") }) };
    case "fill": {
      const tab = await activeTab();
      if (!tab?.id || !isWebPage(tab.url)) return { ok: false, error: "no_tab" };
      const id = String(message.id);
      const frame = message.anySite ? null : await fillTarget({ ...tab, id: tab.id, url: tab.url }, id);
      if (frame && frame.frameId !== 0 && message.frameConfirmed !== true && !(await sameSites(frame.url, tab.url))) {
        // A sign-in form from another site inside this page.
        return { ok: false, error: "cross_site_frame" };
      }
      await fillTab(tab.id, frame?.url ?? tab.url, id, { anySite: Boolean(message.anySite), frameId: frame?.frameId ?? 0 });
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
  const reg = tab?.id === undefined ? null : await registration(tab.id, message.token);
  if (tab?.id === undefined || !reg) return { ok: false, error: "forbidden" };
  // The frame's address; the page's own stays current (single-page apps).
  const frameUrl = reg.frameId === 0 ? tab.url : reg.url;
  const url = isWebPage(frameUrl) ? frameUrl : null;
  // The "Save login?" prompt and the sign-in card are the page's only.
  if (reg.frameId !== 0 && ["save_state", "save", "dismiss_save", "never_save"].includes(message.type)) return { ok: false, error: "forbidden" };
  switch (message.type) {
    case "hello":
      return { ok: true };
    case "state":
      return { ok: true, data: await inlineState(url, tab.id, reg.frameId) };
    case "fill":
      // Only the frame's own logins: a login saved for another site is filled
      // from the toolbar popup, which a page cannot cover or fake.
      if (!url) return { ok: false, error: "no_tab" };
      await fillTab(tab.id, url, String(message.id), { submit: Boolean(message.submit), frameId: reg.frameId, code: message.code === true });
      return { ok: true };
    case "passkey_view":
    case "passkey_unlock":
    case "passkey_fallback":
    case "passkey_cancel":
    case "passkey_choose": {
      // The page's passkey prompt: the request waiting in this tab.
      if (reg.frameId !== 0) return { ok: false, error: "forbidden" };
      const entry = [...passkeyRequests.values()].find((other) => other.tabId === tab.id && other.inPage);
      if (!entry) return { ok: false, error: "expired" };
      return handlePasskey(entry, message);
    }
    case "passkey_pick": {
      // A passkey from the menu under a field that asks for one.
      const entry = conditionalRequests.get(frameKey(tab.id, reg.frameId));
      if (!entry) return { ok: false, error: "expired" };
      const credential = await passkeyGet(entry, String(message.credentialId ?? ""));
      finishConditional(entry, { ok: true, credential });
      return { ok: true };
    }
    case "unlock":
      await requestUnlock();
      return { ok: true };
    case "save_state":
      return { ok: true, data: await saveState(tab.id, tab.url) };
    case "save": {
      const capture = await getCapture(tab.id);
      if (!capture || !capture.ready || !(await sameSite(capture, tab.url))) return { ok: false, error: "expired" };
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
      if (!url || !isWebPage(tab.url)) return { ok: false, error: "no_tab" };
      const data = await call<{ kind: string }>("form_details", { id: String(message.id ?? "") });
      if (data.kind !== "card" && data.kind !== "identity") return { ok: false, error: "bad_request" };
      if (data.kind === "card" && !isSecurePage(url)) return { ok: false, error: "insecure_page" };
      // Also the frames a payment service holds the card's fields in.
      for (const target of await formTargets(tab.id, tab.url, { frameId: reg.frameId, url }, data.kind)) {
        const message = { type: "keyless-fill-form", ...data, origin: new URL(target.url).origin };
        await chrome.tabs.sendMessage(tab.id, message, { frameId: target.frameId }).catch(() => undefined);
      }
      return { ok: true };
    }
    case "dismiss_save":
      await setCapture(tab.id, null);
      return { ok: true };
    case "never_save": {
      // Never offered again on this site (removable in the popup's settings).
      const capture = await getCapture(tab.id);
      const site = siteKey(capture?.url);
      if (!capture || !site || !(await sameSite(capture, tab.url))) return { ok: false, error: "expired" };
      const settings = await loadSettings();
      await updateSettings({ neverSave: [...settings.neverSave, site] });
      await setCapture(tab.id, null);
      return { ok: true };
    }
    case "suggest": {
      // Generated by the app; kept here so only what was shown gets filled.
      const maxLength = Number(message.maxLength) || 0;
      // The site's rules: the page's own, or the known ones for its site.
      const rules = typeof message.rules === "string" ? message.rules.slice(0, 1024) : "";
      const result = await call<{ password: string }>("suggest_password", { maxLength, symbols: message.symbols !== false, rules, url: url ?? "" });
      await chrome.storage.session.set({ [suggestionKey(tab.id)]: result.password });
      return { ok: true, data: result.password };
    }
    case "use_suggested": {
      if (!url) return { ok: false, error: "no_tab" };
      const password = await sessionGet<string>(suggestionKey(tab.id));
      if (typeof password !== "string") return { ok: false, error: "expired" };
      await chrome.storage.session.remove(suggestionKey(tab.id));
      await chrome.tabs.sendMessage(tab.id, { type: "keyless-fill-new", password, origin: new URL(url).origin }, { frameId: reg.frameId });
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

/** What content scripts in frames inside the page may ask (their menus act
 * for them, see `registration`). */
const FRAME_MESSAGES = new Set(["frame_login", "frame_form", "capture", "capture_done", "register", "page_state", "unlock", "menu_elsewhere"]);

async function handleContent(message: any, sender: chrome.runtime.MessageSender): Promise<Reply> {
  // Regular web pages; frames inside them only for a few things.
  if (sender.tab?.id === undefined || sender.frameId === undefined || !isWebPage(sender.url)) return { ok: false, error: "forbidden" };
  if (sender.frameId !== 0 && !FRAME_MESSAGES.has(message?.type)) return { ok: false, error: "forbidden" };
  switch (message.type) {
    case "frame_login":
      await setLoginFrame(sender.tab.id, sender.frameId, message.login === true ? sender.url : null, message.code === true);
      return { ok: true };
    case "menu_elsewhere": {
      // A frame too small for the menu: the page shows it for the frame,
      // with the frame's token (so it acts for the frame's address only).
      if (sender.frameId === 0) return { ok: false, error: "bad_request" };
      const frameId = sender.frameId;
      const token = Object.entries(await registrations(sender.tab.id)).find(([, reg]) => reg.frameId === frameId)?.[0];
      if (!token) return { ok: false, error: "forbidden" };
      const field = message.field && typeof message.field === "object" ? message.field : null;
      await chrome.tabs.sendMessage(sender.tab.id, { type: "keyless-menu-for", token, field, activate: message.activate === true }, { frameId: 0 });
      return { ok: true };
    }
    case "frame_form": {
      // An answer to `formFrames`.
      const answers = formAnswers.get(String(message.nonce ?? ""));
      if (answers && !answers.some((frame) => frame.frameId === sender.frameId)) {
        answers.push({ frameId: sender.frameId, url: sender.url, card: message.card === true, identity: message.identity === true });
      }
      return { ok: true };
    }
    case "register":
      // The token the frame's Keyless menus will present.
      if (typeof message.token !== "string" || message.token.length < 32) return { ok: false, error: "bad_request" };
      await register(sender.tab.id, sender.frameId, sender.url, message.token);
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
      const frame = sender.frameId === 0 ? "top" : (await sameSites(sender.url, sender.tab.url)) ? "same-site" : "cross-site";
      const data: PageState = { state: current.state, count: 0, hidden, card: settings.signInCard && !hidden, autoOpen: settings.autoOpen, frame };
      if (hidden) return { ok: true, data };
      if (current.state === "ready") {
        const logins = await call<Login[]>("match", { url: sender.url });
        data.count = logins.length;
        data.codes = logins.filter((login) => login.totp).length;
        const waiting = conditionalRequests.get(frameKey(sender.tab.id, sender.frameId));
        data.passkeys = waiting ? (await conditionalPasskeys(waiting)).length : 0;
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
    page === "/popup.html"
      ? handlePopup(message)
      : page === "/inline.html"
        ? handleInline(message, sender)
        : page === "/passkey.html"
          ? handlePasskeyWindow(message)
          : page === null
            ? handleContent(message, sender)
            : null;
  if (!handler) return false;
  handler
    .then(sendResponse)
    .catch((err: Error) => sendResponse({ ok: false, error: err instanceof BridgeError ? err.message : "error" }));
  return true;
});

// Keyboard shortcuts: fill the best match into the current page, or only
// its one-time code (copied when the page has no field for it yet).
chrome.commands?.onCommand.addListener(async (command) => {
  if (command !== "fill-login" && command !== "fill-code") return;
  const tab = await activeTab();
  if (!tab?.id || !isWebPage(tab.url)) return;
  try {
    // The page's best login, or one for a login form in a frame of the same
    // site (another site's needs the popup, to confirm).
    const entries = (await tabLogins({ ...tab, id: tab.id, url: tab.url })).filter((entry) => !entry.login.frame);
    // On a page asking only for the code, the login's code.
    const code = command === "fill-code" || entries[0]?.frame.code === true;
    const best = entries.find((entry) => !code || entry.login.totp);
    if (best) await fillTab(tab.id, best.frame.url, best.login.id, { frameId: best.frame.frameId, code });
  } catch {
    // Not connected or locked: the popup explains what to do.
  }
});

void followLockState();
