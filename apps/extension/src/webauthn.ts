// Content script (isolated world, every frame, from the start of the page):
// carries the page's passkey requests (see webauthn-page.ts) to the
// background script and the answers back.
//
// What the page sends is only a request, checked and trimmed here: the
// background script takes the page's origin from the browser, the app checks
// the site, and the user decides in a Keyless window the page cannot reach.
//
// A frame of another origin than the page (or than any frame between them)
// may ask only where the page let it use passkeys (its Permissions Policy,
// read here, where the page's scripts cannot change it), as the browser
// requires. Creating a passkey there, which the browser also allows only
// right after a click in the frame, is left to the browser, and so is
// everything where the browser cannot say what the page allows.

const TAG = "keyless-webauthn";
const MAX_ITEMS = 64;

const text = (value: unknown, max = 1024) => (typeof value === "string" ? value.slice(0, max) : "");
const b64url = (value: unknown, max = 1024) => {
  const s = text(value, max);
  return /^[A-Za-z0-9_-]*$/.test(s) ? s : "";
};
const descriptors = (value: unknown) =>
  (Array.isArray(value) ? value.slice(0, MAX_ITEMS) : []).map((c) => b64url((c as { id?: unknown })?.id)).filter(Boolean);

/** PRF inputs: `{first, second?}`, base64url. */
function prfValues(value: unknown): { first: string; second?: string } | undefined {
  const v = value as { first?: unknown; second?: unknown } | undefined;
  const first = b64url(v?.first, 1400);
  if (!first) return undefined;
  const second = b64url(v?.second, 1400);
  return second ? { first, second } : { first };
}

function prf(value: unknown) {
  if (!value || typeof value !== "object") return undefined;
  const input = value as { eval?: unknown; evalByCredential?: unknown };
  const request: { eval?: ReturnType<typeof prfValues>; evalByCredential?: Record<string, ReturnType<typeof prfValues>> } = {};
  const first = prfValues(input.eval);
  if (first) request.eval = first;
  if (input.evalByCredential && typeof input.evalByCredential === "object") {
    const by: Record<string, ReturnType<typeof prfValues>> = {};
    for (const [id, values] of Object.entries(input.evalByCredential).slice(0, 16)) {
      const v = prfValues(values);
      if (b64url(id) && v) by[id] = v;
    }
    request.evalByCredential = by;
  }
  return request;
}

/** This frame and every frame above it are of the same origin. */
function sameOriginWithAncestors(): boolean {
  let frame: Window = window;
  while (frame !== frame.top) {
    frame = frame.parent;
    try {
      if (frame.location.origin !== location.origin) return false;
    } catch {
      return false;
    }
  }
  return true;
}

/** Whether the page lets this frame sign in with passkeys; null when the
 * browser cannot say (Firefox). */
function getAllowed(): boolean | null {
  const policy = (document as { permissionsPolicy?: unknown; featurePolicy?: unknown }).permissionsPolicy ?? (document as { featurePolicy?: unknown }).featurePolicy;
  const allows = (policy as { allowsFeature?: (feature: string) => boolean } | undefined)?.allowsFeature;
  return typeof allows === "function" ? allows.call(policy, "publickey-credentials-get") : null;
}

window.addEventListener("message", (event) => {
  const data = event.data;
  if (event.origin !== location.origin || data?.[TAG] !== "request" || !event.ports[0] || location.origin === "null") return;
  const page = event.ports[0];
  const request =
    data.kind === "create"
      ? {
          kind: "create",
          rpId: data.rpId === null ? null : text(data.rpId, 253),
          rpName: text(data.rpName, 128),
          userId: b64url(data.userId, 128),
          userName: text(data.userName, 256),
          userDisplayName: text(data.userDisplayName, 256),
          challenge: b64url(data.challenge),
          algorithms: (Array.isArray(data.algorithms) ? data.algorithms.slice(0, MAX_ITEMS) : []).filter((a: unknown) => Number.isInteger(a)),
          excludeCredentials: descriptors(data.excludeCredentials),
          timeout: Number(data.timeout) || null,
          prf: prf(data.prf),
          crossOrigin: false,
        }
      : data.kind === "get"
        ? {
            kind: "get",
            rpId: data.rpId === null ? null : text(data.rpId, 253),
            challenge: b64url(data.challenge),
            allowCredentials: descriptors(data.allowCredentials),
            timeout: Number(data.timeout) || null,
            prf: prf(data.prf),
            conditional: data.conditional === true,
            crossOrigin: false,
          }
        : null;
  if (!request) return;

  let answered = false;
  let keepAlive: ReturnType<typeof setInterval> | undefined;
  const answer = (message: unknown) => {
    if (answered) return;
    answered = true;
    clearInterval(keepAlive);
    page.postMessage(message);
    page.close();
  };

  if (!sameOriginWithAncestors()) {
    if (request.kind === "create") return answer({ fallback: true });
    const allowed = getAllowed();
    if (allowed === null) return answer({ fallback: true });
    // Refused as the browser refuses it.
    if (!allowed) return answer({ ok: false, error: "not_allowed" });
    request.crossOrigin = true;
  }

  // A long-lived connection: the user may take a while to decide.
  let port: chrome.runtime.Port;
  try {
    port = chrome.runtime.connect({ name: TAG });
  } catch {
    // The extension was reloaded under this page: the browser handles it.
    answer({ fallback: true });
    return;
  }
  port.onMessage.addListener((message) => {
    answer(message);
    port.disconnect();
  });
  port.onDisconnect.addListener(() => answer({ fallback: true }));
  page.onmessage = (e) => {
    if (e.data?.type === "abort") {
      answered = true;
      clearInterval(keepAlive);
      port.disconnect();
    }
  };
  port.postMessage(request);
  // A passkey offered in the page's fields can wait for as long as the page
  // is open: the background stays awake for it.
  if (request.kind === "get" && request.conditional) keepAlive = setInterval(() => port.postMessage({ type: "ping" }), 20_000);
});
