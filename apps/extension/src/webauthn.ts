// Content script (isolated world, top frame, from the start of the page):
// carries the page's passkey requests (see webauthn-page.ts) to the
// background script and the answers back.
//
// What the page sends is only a request, checked and trimmed here: the
// background script takes the page's origin from the browser, the app checks
// the site, and the user decides in a Keyless window the page cannot reach.

const TAG = "keyless-webauthn";
const MAX_ITEMS = 64;

const text = (value: unknown, max = 1024) => (typeof value === "string" ? value.slice(0, max) : "");
const b64url = (value: unknown, max = 1024) => {
  const s = text(value, max);
  return /^[A-Za-z0-9_-]*$/.test(s) ? s : "";
};
const descriptors = (value: unknown) =>
  (Array.isArray(value) ? value.slice(0, MAX_ITEMS) : []).map((c) => b64url((c as { id?: unknown })?.id)).filter(Boolean);

window.addEventListener("message", (event) => {
  const data = event.data;
  if (event.origin !== location.origin || data?.[TAG] !== "request" || !event.ports[0]) return;
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
        }
      : data.kind === "get"
        ? {
            kind: "get",
            rpId: data.rpId === null ? null : text(data.rpId, 253),
            challenge: b64url(data.challenge),
            allowCredentials: descriptors(data.allowCredentials),
            timeout: Number(data.timeout) || null,
          }
        : null;
  if (!request) return;

  // A long-lived connection: the user may take a while to decide.
  let answered = false;
  const answer = (message: unknown) => {
    if (answered) return;
    answered = true;
    page.postMessage(message);
    page.close();
  };
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
    if (e.data?.type === "abort") port.disconnect();
  };
  port.postMessage(request);
});
