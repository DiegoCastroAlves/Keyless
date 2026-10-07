export interface Login {
  id: string;
  title: string;
  username: string;
  url: string;
  vault: string;
  favorite: boolean;
}

export interface Status {
  state: "ready" | "locked" | "not_paired" | "app_not_running" | "host_missing" | "error";
  /** Pairing code to compare with the app (when not paired). */
  code?: string;
  email?: string;
}

/** What a content script may know about its page: no login data. */
export interface PageState {
  state: Status["state"];
  count: number;
}

/** What the Keyless menus shown in a page get. */
export interface InlineState {
  state: Status["state"];
  /** The tab's address. */
  url: string | null;
  host: string | null;
  logins: Login[];
}

export interface Credentials {
  username: string;
  password: string;
  totp: string | null;
}
