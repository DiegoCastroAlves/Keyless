# Keyless

A zero-knowledge password manager for Windows and Linux.

Your vault is encrypted on your device with a key derived from your master
password **and** a 128-bit Secret Key that never leaves your devices. The
server (Supabase) only stores ciphertext: nobody, including whoever runs the
server, can read your data.

> **Status: beta.** Keyless has not had an independent security audit yet.

## Repository layout

| Path | What it is |
| --- | --- |
| `crates/keyless-core` | Cryptography, key hierarchy, item model, TOTP, password generator and importers (1Password `.1pux`, CSV). |
| `supabase/migrations` | Database schema, Row Level Security and RPCs. |

## Development

```sh
cargo test -p keyless-core
```

## Credits

Memorable passwords use the [EFF large wordlist](https://www.eff.org/dice)
(CC BY 3.0 US).
