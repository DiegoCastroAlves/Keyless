// Typed wrappers around the Rust commands. All secret handling happens on
// the Rust side; these calls only move what the UI needs to show.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import i18n, { translateError } from "../i18n";

export type Category =
  | "login"
  | "password"
  | "secure_note"
  | "credit_card"
  | "identity"
  | "bank_account"
  | "api_credential"
  | "database"
  | "server"
  | "ssh_key"
  | "software_license"
  | "wireless_router"
  | "email_account"
  | "passport"
  | "driver_license"
  | "membership"
  | "crypto_wallet"
  | "medical_record"
  | "document"
  | "other";

export type FieldKind =
  | "text"
  | "concealed"
  | "email"
  | "url"
  | "phone"
  | "totp"
  | "date"
  | "month_year"
  | "card_number"
  | "pin"
  | "multiline"
  | "address"
  | "security_question"
  | "sign_in_with"
  | "location"
  | "reference"
  | "file";

/** How long before a date field's date to warn that it expires. */
export type ExpiryAlert = "never" | "day" | "week" | "two_weeks" | "month" | "two_months" | "three_months" | "six_months" | "nine_months";

/** The parts of an address field. */
export interface Address {
  street?: string;
  line2?: string;
  city?: string;
  state?: string;
  zip?: string;
  country?: string;
}

export type FieldPurpose = "username" | "password" | "other";

export interface AppError {
  code: string;
  key: string;
  params: Record<string, string>;
  message: string;
}

export interface AppStatus {
  state: "no_account" | "locked" | "unlocked";
  email: string | null;
  pendingEmail: string | null;
  hasSecretKey: boolean;
  /** The lock screen can unlock with the computer's password. */
  systemUnlock: boolean;
  /** This installation supports unlocking with the computer's password. */
  systemUnlockSupported: boolean;
  /** How: the computer password (Linux) or Windows Hello. */
  systemUnlockMethod: "computer_password" | "windows_hello";
  /** Email of a setup code (or another device's approval) waiting for the
   * sign-in form; this device then has its Secret Key. */
  setupEmail: string | null;
}

/** A device where the account is signed in. */
export interface DeviceView {
  id: string;
  name: string;
  platform: "linux" | "windows" | "macos" | "android" | "ios" | "web" | "";
  os: string;
  appVersion: string;
  ip: string | null;
  /** ISO 3166 code, when known. */
  country: string | null;
  createdAt: string;
  lastSeenAt: string;
  current: boolean;
}

/** This device's request to sign in with another one. */
export interface SignInQr {
  id: string;
  svg: string;
}

export interface SetupProgress {
  status: "waiting" | "code" | "approved" | "denied" | "expired";
  code: string | null;
  email: string | null;
}

/** A new device asking to sign in to the account. */
export interface SetupRequestView {
  id: string;
  platform: string;
  ip: string | null;
  country: string | null;
  createdAt: string;
  expiresAt: string;
  /** "pending": nobody answered; "answering": this device waits for the new
   * one's code; "code": type it here; "elsewhere": another device has it. */
  status: "pending" | "answering" | "code" | "elsewhere";
}

/** A passkey for signing in to the account (added in the web vault). */
export interface AccountPasskey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

/** A setup code: the QR code (SVG) and the keyless://setup link it holds. */
export interface SetupQr {
  svg: string;
  link: string;
}

/** The Emergency Kit's texts for its PDF. */
export interface KitLabels {
  title: string;
  created: string;
  intro: string;
  email: string;
  secretKey: string;
  masterPassword: string;
  writeByHand: string;
  setupCode: string;
  setupCodeHelp: string;
}

export interface CreatedAccount {
  secretKey: string;
  confirmationRequired: boolean;
}

export function isCancelled(err: unknown): boolean {
  return !!err && typeof err === "object" && "code" in err && (err as { code: string }).code === "cancelled";
}

export interface Strength {
  /** 0 to 4: what the rules use (weak is below 3). */
  score: number;
  /** 0 (very weak) to 6 (excellent): what the user sees. */
  level: number;
  guessesLog10: number;
  warning: string | null;
  suggestions: string[];
}

export interface Settings {
  /** 0: never locks by itself. */
  auto_lock_minutes: number;
  clipboard_clear_seconds: number;
  lock_on_sleep: boolean;
  theme: "system" | "light" | "dark";
  language: "system" | "en" | "es" | "pt-BR";
  browser_integration: boolean;
  check_updates: boolean;
  /** Changed only through api.setSystemUnlock (needs the master password). */
  system_unlock: boolean;
  list_sort: ListSort;
  /** Newest (or most used, or Z to A) first. */
  list_sort_desc: boolean;
  /** Closing the window keeps Keyless running in the tray. */
  close_to_tray: boolean;
  start_at_login: boolean;
  /** When started at login, stay in the tray. */
  start_minimized: boolean;
  /** Registered by the app on Windows; Linux desktops own their shortcuts. */
  quick_access_shortcut: string;
  /** Show website icons, downloaded from each site and kept encrypted here. */
  site_icons: boolean;
  ssh_agent: boolean;
  /** Run Sentinel's online check by itself once a day. */
  sentinel_check_passwords: boolean;
  /** Download the public lists Sentinel compares websites with, each on its
   * own: breached websites, two-factor codes, passkeys. */
  sentinel_breach_list: boolean;
  sentinel_two_factor_list: boolean;
  sentinel_passkey_list: boolean;
  /** Announce Sentinel's new serious alerts with system notifications. */
  sentinel_notifications: boolean;
  /** Vault for new items ("" picks one). */
  default_vault: string;
  /** New logins start with the username used most. */
  prefill_username: boolean;
  /** What the main window shows after unlocking. */
  start_view: "all" | "favorites" | "sentinel";
  density: "comfortable" | "compact";
  /** Interface zoom, in percent. */
  zoom: number;
  /** Global shortcuts registered by the app (Windows). */
  show_shortcut: string;
  lock_shortcut: string;
  fill_shortcut: string;
  /** Attached files go to the system's trash afterwards. */
  trash_attached_files: boolean;
  /** Only Keyless's own use counts as activity. */
  auto_lock_app_only: boolean;
  /** Lock when the main window is closed to the tray. */
  lock_on_close: boolean;
  /** How often system unlock needs the master password (days; 0 never). */
  master_password_days: number;
}

export interface SiteIcon {
  /** PNG as a data URL. */
  src: string;
  /** Transparent background: shown on a light tile. */
  padded: boolean;
}

export type ListSort = "title" | "created" | "modified" | "frequent" | "recent" | "strength";

/** A newer Keyless release found by the update check. */
export interface UpdateInfo {
  version: string;
  url: string;
}

/** How this copy updates: in the app ("bundle", "pacman") or from the release page ("manual"). */
export type InstallKind = "bundle" | "pacman" | "manual";

export interface VersionInfo {
  current: string;
  update: UpdateInfo | null;
  install: InstallKind;
  /** The system asks for the administrator password to install updates. */
  needsPassword: boolean;
}

export interface UpdateProgress {
  downloaded: number;
  total: number | null;
}

export interface SyncStatus {
  state: "" | "idle" | "syncing" | "offline" | "error" | "signed_out";
  last_synced_at: number | null;
  message: string | null;
}

export interface Vault {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  role: "owner" | "editor" | "viewer";
  canWrite: boolean;
  itemCount: number;
  orphaned: boolean;
}

/** A secret the developer scan found in a file. */
export interface DevFinding {
  id: string;
  /** The format ("github_token"…), "secret_variable", or an SSH key's
   * finding ("ssh_key", "ssh_key_outdated", "ssh_key_short", "ssh_key_saved"). */
  format: string;
  /** What it is ("token", "key", "private_key", "ssh_key_saved"…), for the UI to word. */
  kind: string;
  /** The service it is for ("GitHub"), when known. */
  service: string;
  path: string;
  /** "~/…" under the home folder. */
  shownPath: string;
  /** 1-based; 0 for a whole file. */
  line: number;
  /** The variable that holds it, or the key's file name. */
  key: string;
  /** Mostly hidden, or an SSH key's fingerprint. */
  preview: string;
  ignored: boolean;
  /** A key too short: its length in bits. */
  bits?: number;
  /** A key already saved in Keyless: the item it is in. */
  savedIn?: { itemId: string; title: string };
  /** A key without a passphrase: the command that adds one, to copy. */
  command?: string;
}

export interface DevScan {
  findings: DevFinding[];
  files: number;
  partial: boolean;
  formats: number;
  scannedAt: number;
}

export interface DeletedVault {
  id: string;
  name: string;
  /** Unix seconds. */
  deletedAt: number;
}

export interface VaultMeta {
  name: string;
  description: string;
  icon: string;
  color: string;
}

export interface ItemSummary {
  id: string;
  vaultId: string;
  title: string;
  subtitle: string;
  category: Category;
  urls: string[];
  tags: string[];
  favorite: boolean;
  archived: boolean;
  trashedAt: number | null;
  createdAt: number;
  updatedAt: number;
  /** Uses on this device (copied, revealed, opened, filled). Local only. */
  uses: number;
  lastUsedAt: number | null;
  /** The item has its own icon (see api.itemIcon). */
  customIcon: boolean;
}

/** A program asking the SSH agent to sign. */
export interface SshRequest {
  id: number;
  program: string;
  parent: string | null;
  keyTitle: string;
  fingerprint: string;
  /** "login" (as `user`), "git", "sign" (with a namespace) or "unknown". */
  purpose: string;
  namespace: string | null;
  user: string | null;
  /** The program may be let do this again until Keyless locks. */
  canRemember: boolean;
}

export type SshAnswer = "deny" | "once" | "remember";

/** The fields of an SSH key item. */
export interface SshKeyFields {
  privateKey: string;
  publicKey: string;
  fingerprint: string;
}

/** A password from the generator history (local to this device). */
export interface GeneratedEntry {
  id: string;
  password: string;
  /** The website it was filled on by the browser extension. */
  site: string | null;
  createdAt: number;
}

/** Where an item's website is filled: anywhere on the site (default), only
 * its exact host, or never. */
export type UrlFill = "domain" | "host" | "never";

export interface ItemUrl {
  href: string;
  label?: string;
  fill?: UrlFill;
  /** Filling it also signs in; unset follows the browser extension. */
  submit?: boolean | null;
}

export interface FieldView {
  id: string;
  label: string;
  kind: FieldKind;
  purpose: FieldPurpose | null;
  value: string | null;
  hasValue: boolean;
  /** Date fields: when to warn (null: Keyless decides from the label). */
  alert: ExpiryAlert | null;
  address: Address | null;
  /** The related item, or the login a "sign in with" account uses. */
  link: string;
  /** "latitude,longitude". */
  geo: string;
}

export interface SectionView {
  id: string;
  title: string;
  fields: FieldView[];
}

export interface PasskeyView {
  credentialId: string;
  rpId: string;
  userName: string;
  createdAt: number;
}

export interface ItemDetail extends ItemSummary {
  urlEntries: ItemUrl[];
  fields: FieldView[];
  sections: SectionView[];
  notes: string;
  passkeys: PasskeyView[];
  attachments: AttachmentView[];
  passwordHistoryCount: number;
  canEdit: boolean;
}

/** A share link just created: shown once, never stored. */
export interface CreatedShare {
  id: string;
  link: string;
  expiresAt: number;
}

/** A share link and what became of it. */
export interface ShareView {
  id: string;
  itemId: string;
  title: string;
  createdAt: number;
  expiresAt: number;
  maxViews: number | null;
  views: number;
  status: "active" | "expired" | "revoked" | "used";
  /** Only these emails may open it (empty: anyone with the link). */
  recipients: string[];
}

/** A file kept in an item. */
export interface AttachmentView {
  id: string;
  name: string;
  /** Bytes. */
  size: number;
  createdAt: number;
}

/** What an attachment shows inside Keyless. */
export type AttachmentPreview = { kind: "image"; src: string } | { kind: "text"; text: string } | { kind: "none" };

/** A file the user dropped or chose, to attach. */
export interface FileInfo {
  path: string;
  name: string;
  size: number;
}

/** Attachment space the account uses and may use, in bytes. */
export interface AttachmentSpace {
  used: number;
  quota: number;
}

export interface AttachmentProgress {
  itemId: string;
  name: string;
  direction: "upload" | "download";
  /** Bytes. */
  done: number;
  total: number;
}

/** An earlier version of an item (see the item history). */
export interface ItemVersion {
  revision: number;
  updatedAt: number;
  title: string;
  urlEntries: ItemUrl[];
  fields: FieldView[];
  sections: SectionView[];
  notes: string;
  /** What the following version changed: field labels, or ":title",
   * ":websites", ":notes", ":tags". */
  changed: string[];
}

export interface Field {
  id: string;
  label: string;
  kind: FieldKind;
  value: string;
  purpose?: FieldPurpose | null;
  alert?: ExpiryAlert | null;
  address?: Address | null;
  link?: string;
  geo?: string;
}

export interface Section {
  id: string;
  title: string;
  fields: Field[];
}

export interface ItemDraft {
  id: string | null;
  vaultId: string;
  title: string;
  category: Category;
  urls: ItemUrl[];
  tags: string[];
  favorite: boolean;
  fields: Field[];
  sections: Section[];
  notes: string;
  /** The item's own icon (PNG data URL), or "". */
  icon: string;
}

export interface TotpCode {
  code: string;
  period: number;
  remaining: number;
}

export interface HistoryEntry {
  value: string;
  changedAt: number;
}

/** A recovery's new credentials, to save before it is sent. */
export interface RecoveryPrepare {
  email: string;
  secretKey: string;
  recoveryKey: string;
}

export interface CopyResult {
  clearAfterSeconds: number;
}

export type GeneratorOptions =
  | {
      kind: "random";
      length: number;
      uppercase: boolean;
      lowercase: boolean;
      digits: boolean;
      symbols: boolean;
      avoid_ambiguous: boolean;
    }
  | {
      kind: "memorable";
      words: number;
      separator: string;
      capitalize: boolean;
      include_number: boolean;
      /** Words, made-up words of syllables, or three letters each. */
      style?: "words" | "syllables" | "three_letters";
      /** The separator, or a random digit (or digit or symbol) each time. */
      separators?: "fixed" | "digits" | "digits_symbols";
    }
  | { kind: "pin"; length: number };

export interface GeneratedPassword {
  password: string;
  entropy_bits: number;
}

export interface HealthReport {
  checked: number;
  weak: string[];
  reused: string[][];
  /** Groups of items for the same account (website and user name). */
  duplicates: string[][];
  /** Items with a website on plain http. */
  unsecured: string[];
  /** Those whose website can simply move to https (no other port): "Use HTTPS". */
  httpsReady: string[];
  expiring: { id: string; expiresAt: number; expired: boolean }[];
  /** Items whose password was seen in breaches, with how often. */
  breached: [string, number][];
  /** Websites breached after the item's password was set. */
  compromised: SiteIssue[];
  /** Websites offering one-time codes the item does not have. */
  twoFactor: SiteIssue[];
  /** Websites that accept passkeys, for items without one. */
  passkeys: SiteIssue[];
  /** Logins imported from LastPass whose password was not changed since. */
  lastpass: string[];
  /** Alerts not known yet: their list was never downloaded, or the passwords
   * never checked online. */
  pending: SentinelAlert[];
  /** Passwords not checked online yet (new or changed since). */
  unchecked: number;
  /** When every password was last checked online (unix seconds). */
  passwordsCheckedAt: number | null;
  /** When the oldest list was downloaded (unix seconds). */
  listsUpdatedAt: number | null;
  /** Alerts the user ignored: [item id, alert]. */
  ignored: [string, SentinelAlert][];
  /** The ignored alerts that no longer apply (fixed since): [item id, alert]. */
  stale: [string, SentinelAlert][];
  /** Alerts whose list is turned off in the settings. */
  off: SentinelAlert[];
  /** Item id -> its password's strength level (0 to 6). */
  levels: Record<string, number>;
  /** Vault id -> how many of its passwords are at each strength level (0 to 6). */
  strengths: Record<string, number[]>;
}

/** The editor's check of a password being typed. */
export interface PasswordCheck {
  /** 0 (very weak) to 6 (excellent). */
  level: number;
  /** Other items that already use it. */
  reused: number;
}

export type SentinelAlert =
  | "weak"
  | "reused"
  | "breached"
  | "compromised"
  | "unsecured"
  | "expiring"
  | "two_factor"
  | "passkey"
  | "duplicate"
  | "lastpass";

export interface SiteIssue {
  id: string;
  site: string;
  /** Breach date (YYYY-MM-DD), for breached websites. */
  date?: string;
  /** For breached websites, what Have I Been Pwned's list says about it. */
  breach?: BreachDetails;
}

export interface BreachDetails {
  /** The breach's name ("Adobe"). */
  title: string;
  /** What leaked, in the list's words ("Email addresses", "Passwords"…). */
  dataClasses: string[];
  /** Accounts in the breach. */
  accounts: number;
}

export interface ImportSummary {
  vaults: [string, number][];
  total_items: number;
  /** Attached files, and their bytes. */
  files: number;
  file_bytes: number;
  /** Passkeys in the items. */
  passkeys: number;
  /** `code` names a translation (importer.warn_<code>); `n` is its count. */
  warnings: { code: string; n: number }[];
  /** Next to the account's items: new, the same (left alone), changed in
   * the file, and changed in Keyless after the file's version (kept). */
  new_items: number;
  same_items: number;
  changed_items: number;
  kept_items: number;
  /** For each of `vaults`, the account's vault with most of its items
   * already (an import again): where its new items go by default. */
  vault_home: (string | null)[];
}

/** What an import added. */
export interface ImportOutcome {
  items: number;
  /** Items the account had that the file changed, updated. */
  updated: number;
  files: number;
  /** Attached files that could not be added. */
  filesFailed: number;
}

/** What an export wrote. */
export interface ExportOutcome {
  items: number;
  files: number;
  /** Attached files that could not be downloaded. */
  filesMissing: number;
}

/** Bytes of attached files an import or export has done. */
export interface FilesProgress {
  done: number;
  total: number;
}

export type ImportFormat = "one_pux" | "csv" | "keyless_backup" | "keyless_export" | "json" | "kdbx" | "one_pif" | "keeper_csv" | "dashlane_zip";
export type PlainExportFormat = "csv" | "json" | "zip" | "cxf" | "1pux";

export type ImportTarget = { mode: "new_vaults" } | { mode: "vault"; vaultId: string } | { mode: "new_vault"; name: string };

export interface AccountInfo {
  email: string;
  deleteAfter: string | null;
  secretKeyInFile: boolean;
}

export interface BridgePeer {
  publicKey: string;
  name: string;
  pairedAt: number;
}

export interface PairRequest {
  requestId: string;
  code: string;
  name: string;
}

/** A browser Keyless does not know wants to connect. */
export interface BrowserRequest {
  requestId: string;
  /** Its executable's name. */
  name: string;
  /** Its executable. */
  path: string;
}

export function errorMessage(err: unknown): string {
  return translateError(err);
}

export function errorCode(err: unknown): string | null {
  if (err && typeof err === "object" && "code" in err) {
    return String((err as AppError).code);
  }
  return null;
}

/** The words of a system file dialog, in the user's language. */
function dialogText(key: "qrImage" | "backup" | "attach" | "icon" | "saveAttachment" | "export" | "keyFile" | "setupCode" | "saveKit") {
  const filter = `dialogs.${key}.filter`;
  return { title: i18n.t(`dialogs.${key}.title`), filter: i18n.exists(filter) ? i18n.t(filter) : "" };
}

export const api = {
  status: () => invoke<AppStatus>("get_status"),
  createAccount: (email: string, masterPassword: string) =>
    invoke<CreatedAccount>("create_account", { email, masterPassword, language: i18n.language }),
  signIn: (email: string, secretKey: string | null, masterPassword: string) =>
    invoke<void>("sign_in", { email, secretKey, masterPassword }),
  unlock: (masterPassword: string) => invoke<void>("unlock", { masterPassword }),
  unlockWithSystem: () => invoke<void>("unlock_with_system"),
  setSystemUnlock: (enabled: boolean, masterPassword: string | null) =>
    invoke<Settings>("set_system_unlock", { enabled, masterPassword }),
  /** With `secretKey` when the account was recovered on another device. */
  reauthenticate: (masterPassword: string, secretKey?: string) => invoke<void>("reauthenticate", { masterPassword, secretKey: secretKey || null }),
  lock: () => invoke<void>("lock"),
  signOut: () => invoke<void>("sign_out"),
  resendConfirmation: (email: string) => invoke<void>("resend_confirmation", { email }),
  revealSecretKey: (masterPassword: string) => invoke<string>("reveal_secret_key", { masterPassword }),
  copySecretKey: () => invoke<CopyResult>("copy_secret_key"),
  /** When the account's recovery key was made (ISO 8601), or null. */
  recoveryKeyStatus: () => invoke<string | null>("recovery_key_status"),
  recoveryKeyCreate: (masterPassword: string) => invoke<string>("recovery_key_create", { masterPassword }),
  recoveryKeyRemove: (masterPassword: string) => invoke<void>("recovery_key_remove", { masterPassword }),
  recoveryKeyHide: () => invoke<void>("recovery_key_hide"),
  recoveryCopy: (which: "recovery_key" | "secret_key") => invoke<CopyResult>("recovery_copy", { which }),
  recoveryBegin: (email: string, recoveryKey: string) => invoke<void>("recovery_begin", { email, recoveryKey }),
  recoveryPrepare: (masterPassword: string) => invoke<RecoveryPrepare>("recovery_prepare", { masterPassword }),
  /** True when the device signed in with the new credentials. */
  recoveryFinish: () => invoke<boolean>("recovery_finish"),
  recoveryCancel: () => invoke<void>("recovery_cancel"),
  accountInfo: () => invoke<AccountInfo>("account_info"),
  cancelAccountDeletion: () => invoke<void>("cancel_account_deletion"),
  versionInfo: () => invoke<VersionInfo>("version_info"),
  configureTray: (labels: { open: string; quickAccess: string; lock: string; quit: string }) => invoke<void>("configure_tray", { labels }),
  /** Texts of the system notifications ("{count}" stands for the number). */
  configureNotifications: (labels: {
    sentinelTitle: string;
    newAlertsOne: string;
    newAlertsOther: string;
    deviceSetupTitle: string;
    deviceSetupBody: string;
  }) => invoke<void>("configure_notifications", { labels }),
  listDevices: () => invoke<DeviceView[]>("list_devices"),
  revokeDevice: (id: string) => invoke<void>("revoke_device", { id }),
  signOutOtherDevices: () => invoke<void>("sign_out_other_devices"),
  requestDeviceSetup: (email: string) => invoke<void>("request_device_setup", { email }),
  pollDeviceSetup: () => invoke<SetupProgress>("poll_device_setup"),
  cancelDeviceSetup: () => invoke<void>("cancel_device_setup"),
  /** A QR code for a signed-in phone to read; then poll its request until the phone answers. */
  startQrSignIn: () => invoke<SignInQr>("start_qr_sign_in"),
  pollQrSignIn: (id: string) => invoke<SetupProgress>("poll_qr_sign_in", { id }),
  cancelQrSignIn: (id: string) => invoke<void>("cancel_qr_sign_in", { id }),
  /** A pasted keyless://setup link; returns its email. */
  useSetupLink: (link: string) => invoke<string>("use_setup_link", { link }),
  /** A setup code from the screen, the clipboard or a file (picture or Emergency Kit PDF). */
  scanSetupCode: (source: "screen" | "clipboard" | "file") => invoke<string>("scan_setup_code", { source, dialog: dialogText("setupCode") }),
  clearSetupCode: () => invoke<void>("clear_setup_code"),
  pendingDeviceSetups: () => invoke<SetupRequestView[]>("pending_device_setups"),
  answerDeviceSetup: (id: string) => invoke<void>("answer_device_setup", { id }),
  approveDeviceSetup: (id: string, code: string) => invoke<void>("approve_device_setup", { id, code }),
  denyDeviceSetup: (id: string) => invoke<void>("deny_device_setup", { id }),
  accountSetupCode: (masterPassword: string) => invoke<SetupQr>("account_setup_code", { masterPassword }),
  kitSetupCode: (email: string, secretKey: string) => invoke<SetupQr>("kit_setup_code", { email, secretKey }),
  saveEmergencyKit: (labels: KitLabels, email: string, secretKey: string) =>
    invoke<void>("save_emergency_kit", { labels, email, secretKey, dialog: dialogText("saveKit") }),
  /** Returns the new Secret Key. */
  changeSecretKey: (masterPassword: string) => invoke<string>("change_secret_key", { masterPassword }),
  /** Returns the new email, which waits for its confirmation links. */
  changeEmail: (masterPassword: string, newEmail: string) => invoke<string>("change_email", { masterPassword, newEmail }),
  listPasskeys: () => invoke<AccountPasskey[]>("list_passkeys"),
  removePasskey: (id: string) => invoke<void>("remove_passkey", { id }),
  openWebVault: () => invoke<void>("open_web_vault"),
  /** The email a change waits to confirm, if any. */
  emailChangeStatus: () => invoke<string | null>("email_change_status"),
  showQuickAccess: () => invoke<void>("show_quick_access"),
  hideQuickAccess: () => invoke<void>("hide_quick_access"),
  quickAccessReady: () => invoke<void>("quick_access_ready"),
  scanQr: (source: "screen" | "clipboard" | "file") => invoke<string>("scan_qr", { source, dialog: dialogText("qrImage") }),
  siteIcons: (sites: string[]) => invoke<Record<string, SiteIcon>>("site_icons", { sites }),
  unlockPromptReady: () => invoke<void>("unlock_prompt_ready"),
  closeUnlockPrompt: () => invoke<void>("close_unlock_prompt"),
  showItemInApp: (itemId: string) => invoke<void>("show_item_in_app", { itemId }),
  setGlobalShortcuts: (quickAccess: string, show: string, lock: string, fill: string) =>
    invoke<Settings>("set_global_shortcuts", { quickAccess, show, lock, fill }),
  /** Types the item's login into the app Quick Access covered. */
  autoType: (itemId: string) => invoke<void>("auto_type", { itemId }),
  checkForUpdates: () => invoke<VersionInfo>("check_for_updates"),
  openUpdatePage: () => invoke<void>("open_update_page"),
  installUpdate: () => invoke<void>("install_update"),
  bridgePairRespond: (requestId: string, approve: boolean) => invoke<void>("bridge_pair_respond", { requestId, approve }),
  listBridgePeers: () => invoke<BridgePeer[]>("list_bridge_peers"),
  removeBridgePeer: (publicKey: string) => invoke<void>("remove_bridge_peer", { publicKey }),
  bridgeBrowserRespond: (requestId: string, allow: boolean) => invoke<void>("bridge_browser_respond", { requestId, allow }),
  listAllowedBrowsers: () => invoke<string[]>("list_allowed_browsers"),
  removeAllowedBrowser: (path: string) => invoke<void>("remove_allowed_browser", { path }),
  changeMasterPassword: (current: string, next: string) =>
    invoke<void>("change_master_password", { current, new: next }),
  deleteAccount: (masterPassword: string) => invoke<void>("delete_account", { masterPassword }),
  passwordStrength: (password: string, email?: string) =>
    invoke<Strength>("password_strength", { password, email: email ?? null }),

  heartbeat: () => invoke<void>("heartbeat"),
  getSettings: () => invoke<Settings>("get_settings"),
  updateSettings: (settings: Settings) => invoke<Settings>("update_settings", { settings }),
  syncStatus: () => invoke<SyncStatus>("get_sync_status"),
  syncNow: () => invoke<void>("sync_now"),

  listVaults: () => invoke<Vault[]>("list_vaults"),
  createVault: (meta: VaultMeta) => invoke<string>("create_vault", { meta }),
  updateVault: (vaultId: string, meta: VaultMeta) => invoke<void>("update_vault", { vaultId, meta }),
  deleteVault: (vaultId: string) => invoke<void>("delete_vault", { vaultId }),
  setMasterPasswordDays: (days: number) => invoke<Settings>("set_master_password_days", { days }),
  /** The item a `keyless://` link asked for, once. */
  takeItemRequest: () => invoke<{ id: string; edit: boolean } | null>("take_item_request"),
  /** Looks for secrets left in files on this computer. */
  devScan: () => invoke<DevScan>("dev_scan"),
  devSecretSave: (id: string, vaultId: string, label: string, notes: string) => invoke<ItemSummary>("dev_secret_save", { id, vaultId, label, notes }),
  devSecretTrash: (id: string) => invoke<void>("dev_secret_trash", { id }),
  devSecretReveal: (id: string) => invoke<void>("dev_secret_reveal", { id }),
  devSecretIgnore: (id: string, ignored: boolean) => invoke<void>("dev_secret_ignore", { id, ignored }),
  /** Opens the item's website at its page to change the password. */
  openChangePassword: (itemId: string) => invoke<void>("open_change_password", { itemId }),
  /** Opens an item in a window of its own, above the others. */
  openItemWindow: (itemId: string) => invoke<void>("open_item_window", { itemId }),
  /** Vaults deleted in the last 30 days, which can still be restored. */
  deletedVaults: () => invoke<DeletedVault[]>("deleted_vaults"),
  restoreVault: (vaultId: string) => invoke<void>("restore_vault", { vaultId }),
  moveItems: (itemIds: string[], vaultId: string) => invoke<number>("move_items", { itemIds, vaultId }),
  moveVaultItems: (fromVault: string, toVault: string, deleteSource: boolean) =>
    invoke<number>("move_vault_items", { fromVault, toVault, deleteSource }),

  listItems: () => invoke<ItemSummary[]>("list_items"),
  getItem: (itemId: string) => invoke<ItemDetail>("get_item", { itemId }),
  getItemDraft: (itemId: string) => invoke<ItemDraft>("get_item_draft", { itemId }),
  saveItem: (draft: ItemDraft) => invoke<ItemSummary>("save_item", { draft }),
  revealField: (itemId: string, fieldId: string) => invoke<string>("reveal_field", { itemId, fieldId }),
  getTotp: (itemId: string, fieldId: string) => invoke<TotpCode>("get_totp", { itemId, fieldId }),
  passwordHistory: (itemId: string) => invoke<HistoryEntry[]>("get_password_history", { itemId }),
  copyField: (itemId: string, fieldId: string) => invoke<CopyResult>("copy_field", { itemId, fieldId }),
  copyItemValue: (itemId: string, purpose: "username" | "password" | "totp") =>
    invoke<CopyResult>("copy_item_value", { itemId, purpose }),
  copyText: (text: string) => invoke<CopyResult>("copy_text", { text }),
  openItemUrl: (itemId: string, index: number) => invoke<void>("open_item_url", { itemId, index }),
  setFavorite: (itemId: string, favorite: boolean) => invoke<void>("set_favorite", { itemId, favorite }),
  setSentinelIgnored: (itemId: string, alert: SentinelAlert, ignored: boolean) =>
    invoke<void>("set_sentinel_ignored", { itemId, alert, ignored }),
  /** Watches again several ignored alerts (the ones that no longer apply). */
  sentinelUnignore: (pairs: [string, SentinelAlert][]) => invoke<void>("sentinel_unignore", { pairs }),
  /** Moves the item's websites on plain http to https (a new version). */
  sentinelUseHttps: (itemId: string) => invoke<void>("sentinel_use_https", { itemId }),
  setArchived: (itemId: string, archived: boolean) => invoke<void>("set_archived", { itemId, archived }),
  trashItem: (itemId: string) => invoke<void>("trash_item", { itemId }),
  restoreItem: (itemId: string) => invoke<void>("restore_item", { itemId }),
  deleteItemsPermanently: (itemIds: string[]) => invoke<void>("delete_items_permanently", { itemIds }),

  generatePassword: (options: GeneratorOptions) => invoke<GeneratedPassword>("generate_password", { options }),
  rememberGenerated: (password: string) => invoke<void>("remember_generated", { password }),
  itemVersions: (itemId: string) => invoke<ItemVersion[]>("item_versions", { itemId }),
  revealVersionField: (itemId: string, revision: number, fieldId: string) =>
    invoke<string>("reveal_version_field", { itemId, revision, fieldId }),
  restoreItemVersion: (itemId: string, revision: number) => invoke<ItemSummary>("restore_item_version", { itemId, revision }),
  generatorHistory: () => invoke<GeneratedEntry[]>("generator_history"),
  /** One entry, or the whole history without an id. */
  deleteGenerated: (id?: string) => invoke<void>("delete_generated", { id: id ?? null }),
  passwordHealth: () => invoke<HealthReport>("password_health"),
  checkBreaches: () => invoke<void>("check_breaches"),
  suggestTitle: (url: string) => invoke<string | null>("suggest_title", { url }),
  checkItemPassword: (password: string, itemId: string | null, inputs: string[]) =>
    invoke<PasswordCheck>("check_item_password", { password, itemId, inputs }),
  importPick: (format: ImportFormat, password?: string, keyFile?: string) =>
    invoke<ImportSummary>("import_pick", {
      format,
      password: password ?? null,
      keyFile: keyFile ?? null,
      dialog: { title: i18n.t("dialogs.import.title"), filter: i18n.t(`dialogs.import.filters.${format}`) },
    }),
  exportBackup: (masterPassword: string, password: string, includePasskeys: boolean) =>
    invoke<ExportOutcome>("export_backup", { masterPassword, password, includePasskeys, dialog: dialogText("backup") }),
  sshGenerateKey: (comment: string) => invoke<SshKeyFields>("ssh_generate_key", { comment }),
  deletePasskey: (itemId: string, credentialId: string) => invoke<ItemSummary>("delete_passkey", { itemId, credentialId }),
  /** Asks for files to attach; throws "cancelled" if none was chosen. */
  attachmentPick: () => invoke<FileInfo[]>("attachment_pick", { dialog: dialogText("attach") }),
  /** Name and size of files the user dropped or chose. */
  attachmentInspect: (paths: string[]) => invoke<FileInfo[]>("attachment_inspect", { paths }),
  /** `links`: file fields (path, field id) that point to these files. */
  attachmentAddPaths: (itemId: string, paths: string[], links?: [string, string][]) =>
    invoke<ItemSummary>("attachment_add_paths", { itemId, paths, links: links ?? null }),
  attachmentRename: (itemId: string, attachmentId: string, name: string) => invoke<ItemSummary>("attachment_rename", { itemId, attachmentId, name }),
  itemIcon: (itemId: string) => invoke<string | null>("item_icon", { itemId }),
  pickItemIcon: () => invoke<string>("pick_item_icon", { dialog: dialogText("icon") }),
  duplicateItem: (itemId: string, title: string) => invoke<ItemSummary>("duplicate_item", { itemId, title }),
  copyItemToVault: (itemId: string, vaultId: string) => invoke<ItemSummary>("copy_item_to_vault", { itemId, vaultId }),
  /** Opens a web or mail link in the system browser. */
  openLink: (url: string) => invoke<void>("open_link", { url }),
  /** A field's value as a QR code (SVG markup made by Keyless). */
  fieldQr: (itemId: string, fieldId: string) => invoke<string>("field_qr", { itemId, fieldId }),
  /** The QR code to join a wireless router item's network (SVG). */
  wifiQr: (itemId: string) => invoke<string>("wifi_qr", { itemId }),
  attachmentPreview: (itemId: string, attachmentId: string) => invoke<AttachmentPreview>("attachment_preview", { itemId, attachmentId }),
  itemsWithPasskeys: () => invoke<string[]>("items_with_passkeys"),
  /** Ids of items whose notes or values that are not secret hold `query`. */
  searchItemDetails: (query: string) => invoke<string[]>("search_item_details", { query }),
  attachmentSave: (itemId: string, attachmentId: string) =>
    invoke<void>("attachment_save", { itemId, attachmentId, dialog: dialogText("saveAttachment") }),
  attachmentDelete: (itemId: string, attachmentId: string) => invoke<ItemSummary>("attachment_delete", { itemId, attachmentId }),
  attachmentSpace: () => invoke<AttachmentSpace | null>("attachment_space"),
  /** `recipients`: only these emails may open it (empty: anyone with the link). */
  shareCreate: (itemId: string, hours: number, viewOnce: boolean, recipients: string[] = []) =>
    invoke<CreatedShare>("share_create", { itemId, hours, viewOnce, recipients }),
  /** Links that still work; with `all`, also those that ended recently. */
  shareList: (itemId?: string, all = false) => invoke<ShareView[]>("share_list", { itemId: itemId ?? null, all }),
  shareRevoke: (shareId: string) => invoke<void>("share_revoke", { shareId }),
  sshRequest: () => invoke<SshRequest | null>("ssh_request"),
  sshRequestReady: () => invoke<void>("ssh_request_ready"),
  /** Resolves to whether more requests wait. */
  sshAnswer: (id: number, answer: SshAnswer) => invoke<boolean>("ssh_answer", { id, answer }),
  sshClose: () => invoke<void>("ssh_close"),
  unlockPromptReason: () => invoke<"browser" | "ssh">("unlock_prompt_reason"),
  sshAgentInfo: () => invoke<string | null>("ssh_agent_info"),
  sshImportKey: (privateKey: string, passphrase: string | null, comment: string) =>
    invoke<SshKeyFields>("ssh_import_key", { privateKey, passphrase, comment }),
  /** An unencrypted export, after the master password. */
  /** A KeePass key file, picked in the system's dialog: its path. */
  importPickKeyFile: () => invoke<string | null>("import_pick_key_file", { dialog: dialogText("keyFile") }),
  exportPlain: (masterPassword: string, format: PlainExportFormat) =>
    invoke<ExportOutcome>("export_plain", { masterPassword, format, dialog: dialogText("export") }),
  importCommit: (target: ImportTarget, updateChanged: boolean) => invoke<ImportOutcome>("import_commit", { target, updateChanged }),
  importCancel: () => invoke<void>("import_cancel"),
  /** The main window has its listeners: the events waiting for it come now
   * (it is made when shown and goes when closed to the tray). */
  mainReady: () => invoke<void>("main_ready"),
};

export const events = {
  onItemsChanged: (cb: () => void): Promise<UnlistenFn> => listen("keyless://items-changed", () => cb()),
  onSiteIconsChanged: (cb: () => void): Promise<UnlistenFn> => listen("keyless://site-icons-changed", () => cb()),
  onLocked: (cb: () => void): Promise<UnlistenFn> => listen("keyless://locked", () => cb()),
  onAttachmentProgress: (cb: (progress: AttachmentProgress) => void): Promise<UnlistenFn> =>
    listen<AttachmentProgress>("keyless://attachment-progress", (e) => cb(e.payload)),
  onSentinelUpdated: (cb: () => void): Promise<UnlistenFn> => listen("keyless://sentinel-updated", () => cb()),
  onFilesProgress: (cb: (progress: FilesProgress) => void): Promise<UnlistenFn> =>
    listen<FilesProgress>("keyless://files-progress", (e) => cb(e.payload)),
  onUnlocked: (cb: () => void): Promise<UnlistenFn> => listen("keyless://unlocked", () => cb()),
  /** `autoType`: opened by the fill shortcut outside a browser, to type a
   * login into the app that has the focus. */
  onQuickAccessOpened: (cb: (opened: { autoType: boolean }) => void): Promise<UnlistenFn> =>
    listen<{ autoType: boolean }>("keyless://quick-access-opened", (e) => cb({ autoType: e.payload?.autoType === true })),
  onSelectItem: (cb: (itemId: string) => void): Promise<UnlistenFn> => listen<string>("keyless://select-item", (e) => cb(e.payload)),
  /** A notification asked for Sentinel. */
  onOpenSentinel: (cb: () => void): Promise<UnlistenFn> => listen("keyless://open-sentinel", () => cb()),
  /** A `keyless://` link asked for an item (see `takeItemRequest`). */
  onItemRequested: (cb: () => void): Promise<UnlistenFn> => listen("keyless://item-requested", () => cb()),
  /** The browser extension's "+": a new item, with the tab's address for a login. */
  onNewItem: (cb: (request: { category: Category; url: string; title: string }) => void): Promise<UnlistenFn> =>
    listen<{ category: Category; url: string; title: string }>("keyless://new-item", (e) => cb(e.payload)),
  onSyncStatus: (cb: (s: SyncStatus) => void): Promise<UnlistenFn> =>
    listen<SyncStatus>("keyless://sync-status", (e) => cb(e.payload)),
  onUpdateAvailable: (cb: (u: UpdateInfo) => void): Promise<UnlistenFn> =>
    listen<UpdateInfo>("keyless://update-available", (e) => cb(e.payload)),
  onUpdateProgress: (cb: (p: UpdateProgress) => void): Promise<UnlistenFn> =>
    listen<UpdateProgress>("keyless://update-progress", (e) => cb(e.payload)),
  onPairRequest: (cb: (r: PairRequest) => void): Promise<UnlistenFn> =>
    listen<PairRequest>("keyless://pair-request", (e) => cb(e.payload)),
  /** A browser extension was connected. */
  onBridgePaired: (cb: () => void): Promise<UnlistenFn> => listen("keyless://bridge-paired", () => cb()),
  onBrowserRequest: (cb: (r: BrowserRequest) => void): Promise<UnlistenFn> =>
    listen<BrowserRequest>("keyless://browser-request", (e) => cb(e.payload)),
  /** This device was signed out from another one (its data is gone). */
  onDeviceRevoked: (cb: () => void): Promise<UnlistenFn> => listen("keyless://device-revoked", () => cb()),
  /** A new device asks to sign in to the account. */
  onDeviceSetupRequested: (cb: () => void): Promise<UnlistenFn> => listen("keyless://device-setup-requested", () => cb()),
  /** A keyless://setup link was opened; its email. */
  onSetupReceived: (cb: (email: string) => void): Promise<UnlistenFn> => listen<string>("keyless://setup-received", (e) => cb(e.payload)),
  /** The account's email changed. */
  onAccountChanged: (cb: () => void): Promise<UnlistenFn> => listen("keyless://account-changed", () => cb()),
};
