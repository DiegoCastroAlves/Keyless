// Typed wrappers around the Rust commands. All secret handling happens on
// the Rust side; these calls only move what the UI needs to show.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { translateError } from "../i18n";

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
  | "multiline";

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
}

export interface CreatedAccount {
  secretKey: string;
  confirmationRequired: boolean;
}

/** "Continue with Google": whether the Google account already has Keyless. */
export interface GoogleResult {
  kind: "new" | "existing";
  email: string;
}

/** Texts of the page the browser shows when Google sends the user back. */
export interface BrowserPage {
  doneTitle: string;
  doneBody: string;
  errorTitle: string;
}

export function isCancelled(err: unknown): boolean {
  return !!err && typeof err === "object" && "code" in err && (err as { code: string }).code === "cancelled";
}

export interface Strength {
  score: number;
  guessesLog10: number;
  warning: string | null;
  suggestions: string[];
}

export interface Settings {
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
}

export interface SiteIcon {
  /** PNG as a data URL. */
  src: string;
  /** Transparent background: shown on a light tile. */
  padded: boolean;
}

export type ListSort = "title" | "created" | "modified" | "frequent" | "recent";

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
}

export interface FieldView {
  id: string;
  label: string;
  kind: FieldKind;
  purpose: FieldPurpose | null;
  value: string | null;
  hasValue: boolean;
}

export interface SectionView {
  id: string;
  title: string;
  fields: FieldView[];
}

export interface ItemDetail extends ItemSummary {
  urlEntries: ItemUrl[];
  fields: FieldView[];
  sections: SectionView[];
  notes: string;
  passwordHistoryCount: number;
  canEdit: boolean;
}

export interface Field {
  id: string;
  label: string;
  kind: FieldKind;
  value: string;
  purpose?: FieldPurpose | null;
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
}

export interface BreachReport {
  checked: number;
  breached: [string, number][];
}

export interface ImportSummary {
  vaults: [string, number][];
  total_items: number;
  warnings: string[];
}

export type ImportTarget = { mode: "new_vaults" } | { mode: "vault"; vaultId: string };

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

export function errorMessage(err: unknown): string {
  return translateError(err);
}

export function errorCode(err: unknown): string | null {
  if (err && typeof err === "object" && "code" in err) {
    return String((err as AppError).code);
  }
  return null;
}

export const api = {
  status: () => invoke<AppStatus>("get_status"),
  createAccount: (email: string, masterPassword: string) =>
    invoke<CreatedAccount>("create_account", { email, masterPassword }),
  signInWithGoogle: (page: BrowserPage) => invoke<GoogleResult>("sign_in_with_google", { page }),
  cancelGoogleSignIn: () => invoke<void>("cancel_google_sign_in"),
  createAccountWithGoogle: (masterPassword: string) =>
    invoke<CreatedAccount>("create_account_with_google", { masterPassword }),
  signIn: (email: string, secretKey: string | null, masterPassword: string) =>
    invoke<void>("sign_in", { email, secretKey, masterPassword }),
  unlock: (masterPassword: string) => invoke<void>("unlock", { masterPassword }),
  unlockWithSystem: () => invoke<void>("unlock_with_system"),
  setSystemUnlock: (enabled: boolean, masterPassword: string | null) =>
    invoke<Settings>("set_system_unlock", { enabled, masterPassword }),
  reauthenticate: (masterPassword: string) => invoke<void>("reauthenticate", { masterPassword }),
  lock: () => invoke<void>("lock"),
  signOut: () => invoke<void>("sign_out"),
  resendConfirmation: (email: string) => invoke<void>("resend_confirmation", { email }),
  revealSecretKey: (masterPassword: string) => invoke<string>("reveal_secret_key", { masterPassword }),
  copySecretKey: () => invoke<CopyResult>("copy_secret_key"),
  accountInfo: () => invoke<AccountInfo>("account_info"),
  cancelAccountDeletion: () => invoke<void>("cancel_account_deletion"),
  versionInfo: () => invoke<VersionInfo>("version_info"),
  configureTray: (labels: { open: string; quickAccess: string; lock: string; quit: string }) => invoke<void>("configure_tray", { labels }),
  showQuickAccess: () => invoke<void>("show_quick_access"),
  hideQuickAccess: () => invoke<void>("hide_quick_access"),
  quickAccessReady: () => invoke<void>("quick_access_ready"),
  scanQr: (source: "screen" | "clipboard" | "file") => invoke<string>("scan_qr", { source }),
  siteIcons: (sites: string[]) => invoke<Record<string, SiteIcon>>("site_icons", { sites }),
  unlockPromptReady: () => invoke<void>("unlock_prompt_ready"),
  closeUnlockPrompt: () => invoke<void>("close_unlock_prompt"),
  showItemInApp: (itemId: string) => invoke<void>("show_item_in_app", { itemId }),
  setQuickAccessShortcut: (shortcut: string) => invoke<Settings>("set_quick_access_shortcut", { shortcut }),
  checkForUpdates: () => invoke<VersionInfo>("check_for_updates"),
  openUpdatePage: () => invoke<void>("open_update_page"),
  installUpdate: () => invoke<void>("install_update"),
  bridgePairRespond: (requestId: string, approve: boolean) => invoke<void>("bridge_pair_respond", { requestId, approve }),
  listBridgePeers: () => invoke<BridgePeer[]>("list_bridge_peers"),
  removeBridgePeer: (publicKey: string) => invoke<void>("remove_bridge_peer", { publicKey }),
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
  setArchived: (itemId: string, archived: boolean) => invoke<void>("set_archived", { itemId, archived }),
  trashItem: (itemId: string) => invoke<void>("trash_item", { itemId }),
  restoreItem: (itemId: string) => invoke<void>("restore_item", { itemId }),
  deleteItemsPermanently: (itemIds: string[]) => invoke<void>("delete_items_permanently", { itemIds }),

  generatePassword: (options: GeneratorOptions) => invoke<GeneratedPassword>("generate_password", { options }),
  rememberGenerated: (password: string) => invoke<void>("remember_generated", { password }),
  generatorHistory: () => invoke<GeneratedEntry[]>("generator_history"),
  /** One entry, or the whole history without an id. */
  deleteGenerated: (id?: string) => invoke<void>("delete_generated", { id: id ?? null }),
  passwordHealth: () => invoke<HealthReport>("password_health"),
  checkBreaches: () => invoke<BreachReport>("check_breaches"),
  importPick: (format: "one_pux" | "csv" | "keyless_backup", password?: string) =>
    invoke<ImportSummary>("import_pick", { format, password: password ?? null }),
  exportBackup: (masterPassword: string, password: string) => invoke<number>("export_backup", { masterPassword, password }),
  importCommit: (target: ImportTarget) => invoke<number>("import_commit", { target }),
  importCancel: () => invoke<void>("import_cancel"),
};

export const events = {
  onItemsChanged: (cb: () => void): Promise<UnlistenFn> => listen("keyless://items-changed", () => cb()),
  onSiteIconsChanged: (cb: () => void): Promise<UnlistenFn> => listen("keyless://site-icons-changed", () => cb()),
  onLocked: (cb: () => void): Promise<UnlistenFn> => listen("keyless://locked", () => cb()),
  onUnlocked: (cb: () => void): Promise<UnlistenFn> => listen("keyless://unlocked", () => cb()),
  onQuickAccessOpened: (cb: () => void): Promise<UnlistenFn> => listen("keyless://quick-access-opened", () => cb()),
  onSelectItem: (cb: (itemId: string) => void): Promise<UnlistenFn> => listen<string>("keyless://select-item", (e) => cb(e.payload)),
  onSyncStatus: (cb: (s: SyncStatus) => void): Promise<UnlistenFn> =>
    listen<SyncStatus>("keyless://sync-status", (e) => cb(e.payload)),
  onUpdateAvailable: (cb: (u: UpdateInfo) => void): Promise<UnlistenFn> =>
    listen<UpdateInfo>("keyless://update-available", (e) => cb(e.payload)),
  onUpdateProgress: (cb: (p: UpdateProgress) => void): Promise<UnlistenFn> =>
    listen<UpdateProgress>("keyless://update-progress", (e) => cb(e.payload)),
  onPairRequest: (cb: (r: PairRequest) => void): Promise<UnlistenFn> =>
    listen<PairRequest>("keyless://pair-request", (e) => cb(e.payload)),
};
