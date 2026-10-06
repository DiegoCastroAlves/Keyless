// End-to-end encryption between the extension and the Keyless app.
// Mirrors apps/desktop/src-tauri/src/bridge/crypto.rs:
//   shared = X25519(ext private, app public)
//   key    = HKDF-SHA256(ikm = shared, salt = "keyless/bridge/v1", info = ext_pub || app_pub)
//   AES-256-GCM, random 96-bit nonce, direction label as associated data.
// The extension's private key is generated as non-extractable and kept in
// IndexedDB: page scripts cannot reach it, and it never leaves the browser.

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const TO_APP = encoder.encode("keyless-bridge-v1:to-app");
const TO_EXTENSION = encoder.encode("keyless-bridge-v1:to-extension");

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ----- small IndexedDB key/value store -----------------------------------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("keyless", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("kv");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function kvGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction("kv", "readonly").objectStore("kv").get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

export async function kvSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function kvDelete(key: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ----- identity and channel ------------------------------------------------

export interface Identity {
  privateKey: CryptoKey;
  publicRaw: Uint8Array;
}

export async function identity(): Promise<Identity> {
  const stored = await kvGet<{ privateKey: CryptoKey; publicRaw: ArrayBuffer }>("identity");
  if (stored) return { privateKey: stored.privateKey, publicRaw: new Uint8Array(stored.publicRaw) };
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  await kvSet("identity", { privateKey: pair.privateKey, publicRaw: publicRaw.buffer });
  return { privateKey: pair.privateKey, publicRaw };
}

export async function channelKey(me: Identity, appPublic: Uint8Array): Promise<CryptoKey> {
  const peer = await crypto.subtle.importKey("raw", appPublic as BufferSource, { name: "X25519" }, true, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: peer }, me.privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode("keyless/bridge/v1"),
      info: concat(me.publicRaw, appPublic) as BufferSource,
    },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function seal(key: CryptoKey, value: unknown): Promise<{ nonce: string; ct: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: TO_APP },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  return { nonce: toBase64(nonce), ct: toBase64(new Uint8Array(ct)) };
}

export async function open<T>(key: CryptoKey, nonce: string, ct: string): Promise<T> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(nonce) as BufferSource, additionalData: TO_EXTENSION },
    key,
    fromBase64(ct) as BufferSource,
  );
  return JSON.parse(decoder.decode(plain)) as T;
}

/** Same 8-digit code the app shows: SHA-256(label || ext_pub || app_pub). */
export async function pairingCode(me: Identity, appPublic: Uint8Array): Promise<string> {
  const data = concat(concat(encoder.encode("keyless/bridge/v1/pairing"), me.publicRaw), appPublic);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
  const n = new DataView(digest.buffer).getUint32(0, false) % 100_000_000;
  const text = n.toString().padStart(8, "0");
  return `${text.slice(0, 4)}-${text.slice(4)}`;
}
