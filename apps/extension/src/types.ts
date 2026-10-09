export interface Login {
  id: string;
  title: string;
  username: string;
  url: string;
  vault: string;
  favorite: boolean;
  /** The site's icon, from the app's cache. */
  icon?: { src: string; padded: boolean };
  /** For a login form in a frame from another site inside the page: that
   * frame's host. */
  frame?: string;
  /** It has a one-time code. */
  totp?: boolean;
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
  /** Saved credit cards and identities (for payment and address forms). */
  cards?: number;
  identities?: number;
  /** The user asked Keyless to stay out of this site. */
  hidden?: boolean;
  /** Show the sign-in card on login forms. */
  card?: boolean;
  /** Open the list when the user clicks a login field. */
  autoOpen?: boolean;
  /** Logins for the page with a one-time code. */
  codes?: number;
  /** Passkeys the page offers in its fields (it is waiting for one). */
  passkeys?: number;
  /** This frame: the page itself, or a frame of its site or another. */
  frame?: "top" | "same-site" | "cross-site";
}

export type FormKind = "card" | "identity";

/** The field a Keyless menu was opened for. */
export interface FieldInfo {
  /** A password being chosen (sign-up, change password): suggest one. */
  newPassword: boolean;
  maxLength: number | null;
  /** A payment or address form field. */
  form?: FormKind | null;
  /** A field for a one-time code: logins fill only their code. */
  code?: boolean;
  /** A field that asks for passkeys (autocomplete "webauthn"). */
  passkeys?: boolean;
  /** The page's own password rules for a new password (its
   * `passwordrules` attribute). */
  rules?: string;
}

/** A passkey the page's field can sign in with. */
export interface PasskeyEntry {
  itemId: string;
  credentialId: string;
  title: string;
  userName: string;
}

export interface CardSummary {
  id: string;
  title: string;
  holder: string;
  last4: string;
  brand: string;
}

export interface IdentitySummary {
  id: string;
  title: string;
  name: string;
  email: string;
  city: string;
}

export interface FormItems {
  cards: CardSummary[];
  identities: IdentitySummary[];
}

export interface SaveCandidate {
  id: string;
  title: string;
  username: string;
  vault: string;
  /** Saved with the username that was typed. */
  sameUser: boolean;
  /** Its password is the current password typed in a change-password form. */
  current: boolean;
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
  /** Passkeys for the frame's fields, while the page waits for one. */
  passkeys?: PasskeyEntry[];
}

export interface Credentials {
  username: string;
  password: string;
  totp: string | null;
}

/** The browser's own password manager: on, off (by Keyless, or by the user
 * in the browser's settings), controlled by someone else, or unknown until
 * the "privacy" permission is granted. */
export type BrowserManager = "on" | "off" | "off_browser" | "other" | "unknown";
