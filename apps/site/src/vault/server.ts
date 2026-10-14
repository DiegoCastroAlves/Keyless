// The Keyless server (Supabase Auth and the Data API), as the desktop app
// uses it (apps/desktop api.rs). Everything sent is ciphertext, a proof or
// the derived sign-in secret.

declare const __SUPABASE_URL__: string;
declare const __SUPABASE_KEY__: string;

/** An error with a key the page translates. */
export class ServerError extends Error {
  constructor(
    public key: string,
    message = key,
  ) {
    super(message);
  }
}

export interface Session {
  accessToken: string;
  refreshToken: string;
  /** Unix seconds. */
  expiresAt: number;
  userId: string;
}

async function request<T>(path: string, init: { method?: string; body?: unknown; token?: string; headers?: Record<string, string> } = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${__SUPABASE_URL__}/${path}`, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      headers: {
        apikey: __SUPABASE_KEY__,
        ...(init.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(init.token ? { Authorization: `Bearer ${init.token}` } : {}),
        ...init.headers,
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new ServerError("offline");
  }
  const text = await response.text();
  const data = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  if (!response.ok) throw mapError(response.status, data ?? {});
  return data as T;
}

function mapError(status: number, body: Record<string, unknown>): ServerError {
  const code = String(body.error_code ?? body.code ?? body.error ?? "");
  const message = String(body.msg ?? body.message ?? body.error_description ?? status);
  if (code === "invalid_credentials" || code === "invalid_grant") return new ServerError("invalid_credentials", message);
  if (code === "email_not_confirmed") return new ServerError("email_not_confirmed", message);
  if (status === 429 || code.startsWith("over_")) return new ServerError("too_many_attempts", message);
  if (code === "PGRST202" || code === "PGRST205") return new ServerError("missing_function", message);
  if (status === 401 || status === 403) return new ServerError("session_expired", message);
  return new ServerError("unknown", `${message} (${code || status})`);
}

interface RawSession {
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  expires_at?: number;
  user: { id: string };
}

const toSession = (raw: RawSession): Session => ({
  accessToken: raw.access_token,
  refreshToken: raw.refresh_token,
  expiresAt: raw.expires_at ?? Math.floor(Date.now() / 1000) + (raw.expires_in ?? 3600),
  userId: raw.user.id,
});

export const server = {
  signIn: async (email: string, authSecret: string) =>
    toSession(await request<RawSession>("auth/v1/token?grant_type=password", { body: { email, password: authSecret } })),
  refresh: async (refreshToken: string) => toSession(await request<RawSession>("auth/v1/token?grant_type=refresh_token", { body: { refresh_token: refreshToken } })),
  signOut: (token: string) => request<unknown>("auth/v1/logout?scope=local", { body: {}, token }).catch(() => undefined),
  profile: async (token: string, userId: string) => {
    const rows = await request<unknown[]>(
      `rest/v1/profiles?user_id=eq.${encodeURIComponent(userId)}&select=format,kdf,enc_user_key,public_key,enc_private_key,pending_kdf,pending_enc_user_key`,
      { token },
    );
    return rows[0] ?? null;
  },
  memberships: (token: string, userId: string) =>
    request<unknown[]>(
      `rest/v1/vault_members?user_id=eq.${encodeURIComponent(userId)}&select=vault_id,role,enc_vault_key,vaults(owner_id,enc_meta,seq,deleted_at,enc_tombstone)`,
      { token },
    ),
  itemsSince: (token: string, vaultId: string, cursor: number, limit: number) =>
    request<unknown[]>(`rest/v1/items?select=*&vault_id=eq.${encodeURIComponent(vaultId)}&seq=gt.${cursor}&order=seq.asc&limit=${limit}`, { token }),
  rpc: <T>(name: string, args: object, token?: string) => request<T>(`rest/v1/rpc/${name}`, { body: args, token }),
  passkeys: (token: string) => request<unknown[]>("rest/v1/passkeys?select=id,credential_id,enc_name,created_at,last_used_at&order=created_at.asc", { token }),
};
