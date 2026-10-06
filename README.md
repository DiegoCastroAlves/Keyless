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
- Watchtower: weak, reused and breached passwords (Have I Been Pwned,
  k-anonymity)
- Import from 1Password (`.1pux`), Chrome, Edge, Firefox, Bitwarden (CSV)
- Encrypted backups (`.keyless`) with a separate backup password
- Auto-lock on inactivity, sleep and screen lock; clipboard auto-clear that
  stays out of clipboard history
- English and Spanish

## Install

Download the installer for your system from the
[releases page](https://github.com/DiegoCastroAlves/Keyless/releases):
`.exe` for Windows, `.deb`/`.rpm`/`.AppImage` for Linux.

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/keyless-core` | Cryptography, key hierarchy, item model, TOTP, generator, importers and backups. |
| `apps/desktop` | Desktop app: Tauri (Rust, `src-tauri/`) and React UI (`src/`). |
| `supabase/migrations` | Database schema, Row Level Security and RPCs. |
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
```

Releases: push a tag like `v0.1.0` and GitHub Actions builds the Windows and
Linux installers into a draft release.

## Credits

Memorable passwords use the [EFF large wordlist](https://www.eff.org/dice)
(CC BY 3.0 US).
