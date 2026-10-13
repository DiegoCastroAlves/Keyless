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
  /** It signs in through another provider ("google", "apple"…), with that
   * account there when known. */
  signInWith?: string;
  providerAccount?: string;
  /** It has a one-time code. */
  totp?: boolean;
  /** The kind of item (search results list every kind, see `all`). */
  category?: string;
}

export interface Status {
  state:
    | "ready"
    | "locked"
    | "not_paired"
    | "app_not_running"
    | "host_missing"
    /** The app refused this browser (not one installed on the system). */
    | "untrusted_browser"
    /** The app refused the process that connected (not Keyless, or tampered with). */
    | "untrusted_host"
    | "error";
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
  /** A login the user typed in the field's form (not one Keyless filled):
   * the menu offers to save it now. */
  savable?: boolean;
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
  /** A card or an identity typed in a form, instead of a login. */
  /** `provider`: the name of a "sign in with" provider. */
  form?: { kind: "card" | "identity" | "sign_in_with" | "api_key"; summary: string; provider?: string };
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

/** A login with a serious Sentinel alert, for the warning on its website. */
export interface SiteAlert {
  itemId: string;
  title: string;
  username: string;
  /** Its password was seen in breaches, or the website lost it in a breach
   * after it was set. */
  kind: "breached" | "compromised";
  /** The website's breach date (YYYY-MM-DD). */
  date?: string;
}

/** A one-time password setup read from a QR code on the page. */
export interface ScannedCode {
  uri: string;
  issuer: string | null;
  account: string | null;
}

/** A login whose password was pasted on another site. */
export interface PastedLogin {
  itemId: string;
  title: string;
  site: string;
}

/** The warning shown at the top of a page (see background.ts): the
 * website's logins are breached, a password of another site's login was
 * pasted there, or the Keyless Secret Key was. */
export type AlertView =
  | { kind: "breach"; host: string; url: string; alerts: SiteAlert[] }
  | { kind: "paste"; host: string; url: string; logins: PastedLogin[] }
  | { kind: "secret_key"; host: string; url: string };

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
  /** The item's website says whether filling signs in; null follows the
   * extension's setting. */
  submit?: boolean | null;
}

/** The browser's own password manager: on, off (by Keyless, or by the user
 * in the browser's settings), controlled by someone else, or unknown until
 * the "privacy" permission is granted. */
export type BrowserManager = "on" | "off" | "off_browser" | "other" | "unknown";
