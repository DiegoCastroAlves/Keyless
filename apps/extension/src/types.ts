export interface Login {
  id: string;
  title: string;
  username: string;
  url: string;
  vault: string;
  favorite: boolean;
  /** The site's icon, from the app's cache. */
  icon?: { src: string; padded: boolean };
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

/** The field a Keyless menu was opened for. */
export interface FieldInfo {
  /** A password being chosen (sign-up, change password): suggest one. */
  newPassword: boolean;
  maxLength: number | null;
}

export interface SaveCandidate {
  id: string;
  title: string;
  username: string;
  vault: string;
  /** Saved with the username that was typed. */
  sameUser: boolean;
}

export interface Vault {
  id: string;
  name: string;
}

/** What the "Save login?" prompt shows. The password stays in the
 * background script. */
export interface SaveState {
  locked: boolean;
  url: string;
  host: string;
  username: string;
  /** The password was suggested by Keyless. */
  generated: boolean;
  title: string;
  state: "new" | "update";
  candidates: SaveCandidate[];
  vaults: Vault[];
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
