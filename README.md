# Keyless

A zero-knowledge password manager for Windows and Linux.

Your vault is encrypted on your device with a key derived from your master
password **and** a 128-bit Secret Key that never leaves your devices. The
server (Supabase) only stores ciphertext: nobody, including whoever runs the
server, can read your data. See [docs/SECURITY.md](docs/SECURITY.md).

> **Status: beta.** Keyless has not had an independent security audit yet.

## Features

- Logins, passwords, secure notes, credit cards, identities, bank accounts,
  API credentials, servers, databases, SSH keys, Wi-Fi, passports, licenses
  and more, with custom fields and sections
- One-time passwords (TOTP, including Steam Guard) with live codes
- Password generator (random, memorable, PIN)
- Multiple vaults, favorites, tags, archive, Recently Deleted (30 days)
- Sync across devices, offline first, conflicts never lose data
- Continue with Google to create or find your account (the master password
  and Secret Key still protect the vault)
- An optional recovery key, like 1Password's, for a forgotten master password
  or a lost Secret Key
- Sentinel: weak, reused and breached passwords (Have I Been Pwned,
  k-anonymity), websites breached since the password was set, websites
  offering two-factor codes or passkeys the item lacks, duplicate items,
  websites without HTTPS, and cards or documents about to expire; each alert
  lists its items and shows on them, any alert can be ignored per item, and
  the online check can run by itself once a day
- File attachments in items, encrypted on the device in chunks (250 MiB per
  account)
- Share links: a copy of an item that someone without Keyless opens in the
  browser, for up to 30 days or a single view; the key is only in the link
- Import from 1Password (`.1pux`, with its attached files), Chrome, Edge,
  Firefox, Bitwarden (CSV), and Keyless's own backups and exports
- Encrypted backups (`.keyless`, with the attached files) with a separate
  backup password, and an unencrypted CSV, JSON or ZIP (JSON and files)
  export for moving elsewhere
- Auto-lock on inactivity, sleep and screen lock; clipboard auto-clear that
  stays out of clipboard history
- Browser extension for Chrome, Edge, Brave, Vivaldi, Opera and Firefox: fills
  logins, cards and addresses on the matching site, offers to save new and
  changed logins, suggests strong passwords, and copies one-time passwords,
  with an end-to-end encrypted, paired connection to the desktop app. Its
  settings let you hide it on chosen sites, never save on others, and turn
  off the browser's own password manager
- Passkeys: sites can save passkeys in Keyless and sign in with them from the
  browser extension, approved in a Keyless window; the browser's own way
  (security key, phone) stays one click away
- SSH agent (Linux): SSH and git sign with keys kept in Keyless, each use
  approved in Keyless; keys can be generated or imported (OpenSSH or RSA PEM,
  with a passphrase)
- English, Spanish and Brazilian Portuguese (follows the system language by default)

## Install

Download the installer for your system from the
[releases page](https://github.com/DiegoCastroAlves/Keyless/releases):

| System | File | How to install |
| --- | --- | --- |
| Windows | `Keyless_*_x64-setup.exe` | Run it. |
| Arch Linux, CachyOS, Manjaro | `keyless-*-x86_64.pkg.tar.zst` | `sudo pacman -U keyless-*-x86_64.pkg.tar.zst` |
| Debian, Ubuntu, Mint | `Keyless_*_amd64.deb` | `sudo apt install ./Keyless_*_amd64.deb` |
| Fedora, openSUSE | `Keyless-*.x86_64.rpm` | `sudo dnf install ./Keyless-*.x86_64.rpm` |
| Any Linux | `Keyless_*_amd64.AppImage` | Mark it as executable and run it. |

The packages add Keyless to the applications menu; the AppImage is a single
file that runs without installing.

### Browser extension

The extension talks to the desktop app, so install and open the app first.
It registers itself with your browsers when it starts (Settings > Browser).

- **Chrome, Edge, Brave, Vivaldi, Opera:** unzip `keyless-chrome-*.zip`, open
  `chrome://extensions`, turn on *Developer mode*, choose *Load unpacked* and
  pick the unzipped folder.
- **Firefox:** Firefox only installs signed extensions permanently. Until
  Keyless is signed by Mozilla, load `keyless-firefox-*.zip` from
  `about:debugging#/runtime/this-firefox` (*Load Temporary Add-on*); it stays
  until Firefox restarts.

Click the Keyless icon in the toolbar, choose *Connect* and approve the
browser in the app after checking that both show the same code. Then click
the Keyless button inside a login field, or press `Ctrl+Shift+L`. Filling
only a verification code has a shortcut too, with no key by default: set one
in the browser's extension shortcuts page (`chrome://extensions/shortcuts`,
or *Manage Extension Shortcuts* in Firefox's add-ons page).

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/keyless-core` | Cryptography, key hierarchy, item model, TOTP, generator, importers and backups. |
| `apps/desktop` | Desktop app: Tauri (Rust, `src-tauri/`) and React UI (`src/`). |
| `apps/extension` | Browser extension (Manifest V3) for Chromium browsers and Firefox. |
| `apps/site` | Public site (keyless.diegoalves.dev): the page that opens share links. |
| `supabase/migrations` | Database schema, Row Level Security and RPCs. |
| `packaging/arch` | Arch Linux package (`PKGBUILD`), built for every release. |
| `docs/SECURITY.md` | Security design and threat model. |

## Development

Requirements: Rust (stable), Node.js 24+, pnpm, and the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS.

```sh
cd apps/desktop
pnpm install
pnpm tauri dev        # run the app
pnpm tauri build      # build installers

cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

cd apps/extension
pnpm install
pnpm build            # dist/chrome and dist/firefox
pnpm test             # field detection on generated pages (headless Chromium)

cd apps/site
pnpm install
pnpm build            # dist/, with Cloudflare Pages headers in dist/_headers
```

The site is served by Cloudflare Pages from this repository: root directory
`apps/site`, build command `pnpm install --frozen-lockfile && pnpm build`,
output directory `dist`, custom domain `keyless.diegoalves.dev`. The app
builds share links for that address (`KEYLESS_SHARE_URL` at build time
changes it).

Releases: push a tag like `v0.1.0` and GitHub Actions builds the Windows and
Linux installers, the Arch package and the browser extension, signs the
installers for in-app updates (`latest.json`) and publishes the release.
Signing needs the `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` repository secrets; the matching public
key is in `apps/desktop/src-tauri/tauri.conf.json`. Without them the release
stays a draft.

## Credits

Memorable passwords use the [EFF large wordlist](https://www.eff.org/dice)
(CC BY 3.0 US).
