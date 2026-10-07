// Runs in the page's own world, before the page's scripts: replaces
// navigator.credentials.create and get so a site's passkey requests can go
// to Keyless. It holds nothing secret and can do nothing the page could not
// do itself: it hands the request to Keyless's content script and returns
// what Keyless answered, or calls the browser's own implementation when the
// user prefers it (security key, phone) or Keyless cannot help.

(() => {
  const credentials = navigator.credentials;
  if (!credentials || typeof PublicKeyCredential === "undefined") return;
  const nativeCreate = credentials.create.bind(credentials);
  const nativeGet = credentials.get.bind(credentials);
  const TAG = "keyless-webauthn";

  const b64 = (data: BufferSource): string => {
    const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const buffer = (text: string): ArrayBuffer => {
    const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  };
  const ids = (list?: PublicKeyCredentialDescriptor[]) => (list ?? []).map((c) => ({ id: b64(c.id), transports: c.transports ?? [] }));

  /** Asks Keyless's content script; resolves with its answer. */
  function ask(message: Record<string, unknown>, signal?: AbortSignal | null): Promise<any> {
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const abort = () => {
        channel.port1.postMessage({ type: "abort" });
        reject(new DOMException("The operation was aborted.", "AbortError"));
      };
      if (signal?.aborted) return abort();
      signal?.addEventListener("abort", abort, { once: true });
      channel.port1.onmessage = (event) => {
        signal?.removeEventListener("abort", abort);
        channel.port1.close();
        resolve(event.data);
      };
      window.postMessage({ [TAG]: "request", ...message }, location.origin, [channel.port2]);
    });
  }

  function failure(answer: { error?: string }): DOMException {
    const name =
      answer.error === "exists" ? "InvalidStateError" : answer.error === "unsupported" ? "NotSupportedError" : answer.error === "security" ? "SecurityError" : "NotAllowedError";
    return new DOMException("The operation either timed out or was not allowed.", name);
  }

  function attestation(answer: any): PublicKeyCredential {
    const response = {
      clientDataJSON: buffer(answer.clientDataJSON),
      attestationObject: buffer(answer.attestationObject),
      getAuthenticatorData: () => buffer(answer.authenticatorData),
      getPublicKey: () => buffer(answer.publicKey),
      getPublicKeyAlgorithm: () => answer.publicKeyAlgorithm,
      getTransports: () => ["internal", "hybrid"],
    };
    Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    return credential(answer.credentialId, response, {
      clientDataJSON: answer.clientDataJSON,
      attestationObject: answer.attestationObject,
      authenticatorData: answer.authenticatorData,
      publicKey: answer.publicKey,
      publicKeyAlgorithm: answer.publicKeyAlgorithm,
      transports: ["internal", "hybrid"],
    });
  }

  function assertion(answer: any): PublicKeyCredential {
    const response = {
      clientDataJSON: buffer(answer.clientDataJSON),
      authenticatorData: buffer(answer.authenticatorData),
      signature: buffer(answer.signature),
      userHandle: answer.userHandle ? buffer(answer.userHandle) : null,
    };
    Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    return credential(answer.credentialId, response, {
      clientDataJSON: answer.clientDataJSON,
      authenticatorData: answer.authenticatorData,
      signature: answer.signature,
      userHandle: answer.userHandle ?? null,
    });
  }

  /** A PublicKeyCredential as the browser would return it. */
  function credential(id: string, response: object, json: Record<string, unknown>): PublicKeyCredential {
    const result = {
      id,
      rawId: buffer(id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({ id, rawId: id, type: "public-key", authenticatorAttachment: "platform", response: json, clientExtensionResults: {} }),
    };
    Object.setPrototypeOf(result, PublicKeyCredential.prototype);
    return result as unknown as PublicKeyCredential;
  }

  credentials.create = async function create(options?: CredentialCreationOptions) {
    const publicKey = options?.publicKey;
    if (!publicKey) return nativeCreate(options);
    const answer = await ask(
      {
        kind: "create",
        rpId: publicKey.rp.id ?? null,
        rpName: publicKey.rp.name ?? "",
        userId: b64(publicKey.user.id),
        userName: publicKey.user.name ?? "",
        userDisplayName: publicKey.user.displayName ?? "",
        challenge: b64(publicKey.challenge),
        algorithms: (publicKey.pubKeyCredParams ?? []).map((p) => Number(p.alg)),
        excludeCredentials: ids(publicKey.excludeCredentials),
        timeout: publicKey.timeout ?? null,
      },
      options?.signal,
    );
    if (answer?.fallback) return nativeCreate(options);
    if (!answer?.ok) throw failure(answer ?? {});
    return attestation(answer.credential);
  };

  credentials.get = async function get(options?: CredentialRequestOptions) {
    const publicKey = options?.publicKey;
    // Passkeys offered in the page's own fields (conditional mediation) stay
    // with the browser for now.
    if (!publicKey || options?.mediation === "conditional") return nativeGet(options);
    const answer = await ask(
      {
        kind: "get",
        rpId: publicKey.rpId ?? null,
        challenge: b64(publicKey.challenge),
        allowCredentials: ids(publicKey.allowCredentials),
        timeout: publicKey.timeout ?? null,
      },
      options?.signal,
    );
    if (answer?.fallback) return nativeGet(options);
    if (!answer?.ok) throw failure(answer ?? {});
    return assertion(answer.credential);
  };
})();
