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
- Watchtower: weak, reused and breached passwords (Have I Been Pwned,
  k-anonymity)
- Import from 1Password (`.1pux`), Chrome, Edge, Firefox, Bitwarden (CSV)
- Encrypted backups (`.keyless`) with a separate backup password
- Auto-lock on inactivity, sleep and screen lock; clipboard auto-clear that
  stays out of clipboard history
- Browser extension for Chrome, Edge, Brave, Vivaldi, Opera and Firefox: fills
  logins on the matching site, with an end-to-end encrypted, paired connection
  to the desktop app
- English and Spanish

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
the Keyless button inside a login field, or press `Ctrl+Shift+L`.

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/keyless-core` | Cryptography, key hierarchy, item model, TOTP, generator, importers and backups. |
| `apps/desktop` | Desktop app: Tauri (Rust, `src-tauri/`) and React UI (`src/`). |
| `apps/extension` | Browser extension (Manifest V3) for Chromium browsers and Firefox. |
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
```

Releases: push a tag like `v0.1.0` and GitHub Actions builds the Windows and
Linux installers and the browser extension into a draft release.

## Credits

Memorable passwords use the [EFF large wordlist](https://www.eff.org/dice)
(CC BY 3.0 US).
