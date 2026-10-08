// Runs in the page's own world (and in its frames), before the page's
// scripts: replaces navigator.credentials.create and get so a site's passkey
// requests can go to Keyless. It holds nothing secret and can do nothing the
// page could not do itself: it hands the request to Keyless's content script
// and returns what Keyless answered, or calls the browser's own
// implementation when the user prefers it (security key, phone) or Keyless
// cannot help.
//
// Passkeys offered in the page's own fields (conditional mediation) go to
// both at once: Keyless lists its passkeys in its menu under the field, the
// browser shows its own suggestions, and whichever the user picks wins; the
// other is called off.

(() => {
  const credentials = navigator.credentials;
  // Sandboxed frames, with no origin of their own, keep the browser's.
  if (!credentials || typeof PublicKeyCredential === "undefined" || location.origin === "null") return;
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
  const isBytes = (value: unknown): value is BufferSource => value instanceof ArrayBuffer || ArrayBuffer.isView(value);
  const ids = (list?: PublicKeyCredentialDescriptor[]) => (list ?? []).map((c) => ({ id: b64(c.id), transports: c.transports ?? [] }));

  // ----- Extensions -------------------------------------------------------------
  //
  // credProps is answered here (Keyless passkeys are always discoverable);
  // prf goes to Keyless; the others are not supported and left out.

  type Values = { first: string; second?: string };
  const values = (input: unknown): Values | undefined => {
    const v = input as { first?: unknown; second?: unknown } | undefined;
    if (!v || !isBytes(v.first)) return undefined;
    return isBytes(v.second) ? { first: b64(v.first), second: b64(v.second) } : { first: b64(v.first) };
  };

  /** The site's PRF inputs, base64url. */
  function prfRequest(extensions: AuthenticationExtensionsClientInputs | undefined) {
    const prf = (extensions as { prf?: { eval?: unknown; evalByCredential?: Record<string, unknown> } } | undefined)?.prf;
    if (!prf || typeof prf !== "object") return undefined;
    const request: { eval?: Values; evalByCredential?: Record<string, Values> } = {};
    const first = values(prf.eval);
    if (first) request.eval = first;
    if (prf.evalByCredential && typeof prf.evalByCredential === "object") {
      const by: Record<string, Values> = {};
      for (const [id, input] of Object.entries(prf.evalByCredential).slice(0, 16)) {
        const v = values(input);
        if (v) by[id] = v;
      }
      if (Object.keys(by).length > 0) request.evalByCredential = by;
    }
    return request;
  }

  /** getClientExtensionResults() and its JSON form. */
  function extensionResults(answer: any, extensions: AuthenticationExtensionsClientInputs | undefined, creating: boolean) {
    const results: Record<string, unknown> = {};
    const json: Record<string, unknown> = {};
    if (creating && (extensions as { credProps?: boolean } | undefined)?.credProps) {
      results.credProps = { rk: true };
      json.credProps = { rk: true };
    }
    const prf = answer?.prf;
    if (prf && typeof prf === "object") {
      const out: Record<string, unknown> = {};
      const outJson: Record<string, unknown> = {};
      if (typeof prf.enabled === "boolean") out.enabled = outJson.enabled = prf.enabled;
      if (prf.results?.first) {
        out.results = { first: buffer(prf.results.first), ...(prf.results.second ? { second: buffer(prf.results.second) } : {}) };
        outJson.results = { first: prf.results.first, ...(prf.results.second ? { second: prf.results.second } : {}) };
      }
      results.prf = out;
      json.prf = outJson;
    }
    return { results, json };
  }

  // ----- Talking to Keyless -------------------------------------------------------

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

  /** The browser's own WebAuthn needs the page focused: back from the
   * Keyless window, it waits for the focus (a few seconds at most). */
  function focused(): Promise<void> {
    if (document.hasFocus()) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        window.removeEventListener("focus", done);
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(done, 5000);
      window.addEventListener("focus", done);
    });
  }

  function failure(answer: { error?: string }): DOMException {
    const name =
      answer.error === "exists" ? "InvalidStateError" : answer.error === "unsupported" ? "NotSupportedError" : answer.error === "security" ? "SecurityError" : "NotAllowedError";
    return new DOMException("The operation either timed out or was not allowed.", name);
  }

  function attestation(answer: any, extensions: AuthenticationExtensionsClientInputs | undefined): PublicKeyCredential {
    const response = {
      clientDataJSON: buffer(answer.clientDataJSON),
      attestationObject: buffer(answer.attestationObject),
      getAuthenticatorData: () => buffer(answer.authenticatorData),
      getPublicKey: () => buffer(answer.publicKey),
      getPublicKeyAlgorithm: () => answer.publicKeyAlgorithm,
      getTransports: () => ["internal", "hybrid"],
    };
    Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    return credential(
      answer.credentialId,
      response,
      {
        clientDataJSON: answer.clientDataJSON,
        attestationObject: answer.attestationObject,
        authenticatorData: answer.authenticatorData,
        publicKey: answer.publicKey,
        publicKeyAlgorithm: answer.publicKeyAlgorithm,
        transports: ["internal", "hybrid"],
      },
      extensionResults(answer, extensions, true),
    );
  }

  function assertion(answer: any, extensions: AuthenticationExtensionsClientInputs | undefined): PublicKeyCredential {
    const response = {
      clientDataJSON: buffer(answer.clientDataJSON),
      authenticatorData: buffer(answer.authenticatorData),
      signature: buffer(answer.signature),
      userHandle: answer.userHandle ? buffer(answer.userHandle) : null,
    };
    Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    return credential(
      answer.credentialId,
      response,
      {
        clientDataJSON: answer.clientDataJSON,
        authenticatorData: answer.authenticatorData,
        signature: answer.signature,
        userHandle: answer.userHandle ?? null,
      },
      extensionResults(answer, extensions, false),
    );
  }

  /** A PublicKeyCredential as the browser would return it. */
  function credential(
    id: string,
    response: object,
    json: Record<string, unknown>,
    extensions: { results: Record<string, unknown>; json: Record<string, unknown> },
  ): PublicKeyCredential {
    const result = {
      id,
      rawId: buffer(id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => extensions.results,
      toJSON: () => ({ id, rawId: id, type: "public-key", authenticatorAttachment: "platform", response: json, clientExtensionResults: extensions.json }),
    };
    Object.setPrototypeOf(result, PublicKeyCredential.prototype);
    return result as unknown as PublicKeyCredential;
  }

  // ----- create and get -----------------------------------------------------------

  credentials.create = async function create(options?: CredentialCreationOptions) {
    const publicKey = options?.publicKey;
    // A passkey made quietly after a password sign-in (conditional create)
    // stays with the browser.
    if (!publicKey || (options as { mediation?: string } | undefined)?.mediation === "conditional") return nativeCreate(options);
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
        prf: prfRequest(publicKey.extensions),
      },
      options?.signal,
    );
    if (answer?.fallback) {
      await focused();
      return nativeCreate(options);
    }
    if (!answer?.ok) throw failure(answer ?? {});
    return attestation(answer.credential, publicKey.extensions);
  };

  credentials.get = async function get(options?: CredentialRequestOptions) {
    const publicKey = options?.publicKey;
    if (!publicKey) return nativeGet(options);
    const request = {
      kind: "get",
      rpId: publicKey.rpId ?? null,
      challenge: b64(publicKey.challenge),
      allowCredentials: ids(publicKey.allowCredentials),
      timeout: publicKey.timeout ?? null,
      prf: prfRequest(publicKey.extensions),
    };
    if (options?.mediation === "conditional") return conditional(options, publicKey, request);
    const answer = await ask(request, options?.signal);
    if (answer?.fallback) {
      await focused();
      return nativeGet(options);
    }
    if (!answer?.ok) throw failure(answer ?? {});
    return assertion(answer.credential, publicKey.extensions);
  };

  /** Passkeys offered in the page's fields: Keyless's and the browser's at
   * once. It settles when the user picks one, or with the browser's error
   * once Keyless has nothing to offer either. */
  async function conditional(options: CredentialRequestOptions, publicKey: PublicKeyCredentialRequestOptions, request: Record<string, unknown>) {
    const outer = options.signal;
    if (outer?.aborted) throw new DOMException("The operation was aborted.", "AbortError");
    const keyless = new AbortController();
    const browser = new AbortController();
    const stop = () => {
      keyless.abort();
      browser.abort();
    };
    outer?.addEventListener("abort", stop, { once: true });
    const never = new Promise<never>(() => undefined);
    let keylessOut = false;
    let browserError: unknown = null;
    let fail: (error: unknown) => void = () => undefined;
    const failed = new Promise<never>((_, reject) => (fail = reject));

    const fromKeyless = ask({ ...request, conditional: true }, keyless.signal).then(
      (answer) => {
        if (answer?.ok) return assertion(answer.credential, publicKey.extensions);
        // Nothing from Keyless here: the browser's suggestions stay.
        keylessOut = true;
        if (browserError) fail(browserError);
        return never;
      },
      () => never,
    );
    const fromBrowser = nativeGet({ ...options, signal: browser.signal }).catch((error) => {
      if (outer?.aborted) throw error;
      // The browser cannot offer passkeys in fields: Keyless still can.
      browserError = error;
      if (keylessOut) throw error;
      return never;
    });
    try {
      return await Promise.race([fromKeyless, fromBrowser, failed]);
    } finally {
      outer?.removeEventListener("abort", stop);
      stop();
    }
  }
})();
