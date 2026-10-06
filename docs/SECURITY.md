# Keyless security design

Keyless is a zero-knowledge password manager: everything a user stores is
encrypted on their device before it is uploaded, with keys that never leave
their devices. The server (a Supabase project) stores only ciphertext, public
keys and the metadata it needs to sync. Nobody with access to the server or
the database, including its operators, can read a user's items.

> **Status: beta.** This design has not had an independent audit yet. Treat
> Keyless accordingly until it has.

## Secrets

| Secret | Where it lives | Leaves the device? |
| --- | --- | --- |
| Master password | The user's memory | Never |
| Secret Key (128 random bits) | OS credential store on each device, and the user's printed Emergency Kit | Never |
| Key-encryption key (KEK) | Derived in memory while unlocking | Never |
| User key, vault keys, item plaintext | In memory while unlocked | Never (only as ciphertext) |
| Auth secret | Derived in memory while signing in | Sent to the server over TLS. The server stores only a bcrypt hash of it |

## Key derivation ("two-secret key derivation")

```text
salt   = HKDF-SHA256(ikm = SecretKey, salt = "keyless/v1/kdf-salt", info = "argon2id salt")[16]
k_mp   = Argon2id(NFKD(trim(master password)), salt, m = 64 MiB, t = 3, p = 4)[32]
k_sk   = HKDF-SHA256(ikm = SecretKey, salt = "keyless/v1/secret-key", info = "2skd")[32]
root   = HKDF-Extract(salt = k_sk, ikm = k_mp)
auth   = HKDF-Expand(root, "keyless/v1 auth secret")[32]          -> sign-in password
kek    = HKDF-Expand(root, "keyless/v1 key encryption key")[32]   -> wraps the user key
```

- The **Secret Key** makes a stolen server database useless for guessing master
  passwords: every guess would also have to guess 128 random bits.
- **Argon2id** protects the master password if a device (and therefore the
  Secret Key) is stolen.
- `auth` and `kek` come from the same root through HKDF with distinct labels,
  so knowing `auth` (or its hash) reveals nothing about `kek`.
- The client refuses Argon2id parameters below 64 MiB / 3 iterations or above
  1 GiB / 10 iterations / 8 lanes, and the parameters (with the user id) are
  bound into the encryption of the user key. A server cannot weaken
  derivation, swap in another account's keys, or change the parameters to
  make every unlock take minutes.

## Key hierarchy

```text
kek
 └─ user key (random 256-bit)            profiles.enc_user_key
     ├─ X25519 private key               profiles.enc_private_key (public key stored in clear)
     └─ vault key (random 256-bit)       vault_members.enc_vault_key
         ├─ vault name/description       vaults.enc_meta
         └─ item overview / item details items.enc_overview / items.enc_details
```

Changing the master password re-wraps only the user key. The X25519 key pair
is reserved for sharing vaults between users (not enabled yet).

## Encryption

All ciphertexts are XChaCha20-Poly1305 envelopes (`k1.` + base64url of a
random 24-byte nonce, the ciphertext and the 16-byte tag). Each envelope is
bound through associated data to its purpose and to the ids of the objects it
belongs to (`item-details / vault id / item id`, `vault-key / vault id`, ...).
A server that swaps ciphertexts between items, vaults, purposes or users makes
decryption fail instead of showing the wrong data.

Item and vault contents are padded to a multiple of 64 bytes before
encryption to hide exact lengths.

## Integrity: what the server cannot do

The server can store and serve data, but the client checks everything it
receives and repairs the server when a check fails:

- **Versions (rollback protection).** Every write carries a version number
  and a random content id inside both encrypted documents of an item. The
  client never replaces its copy with an older version, and never accepts an
  overview and details that come from different writes.
- **Authenticated deletions.** Deleting an item uploads a *tombstone*
  encrypted with the vault key. Deletions without a valid, newer tombstone
  are ignored and the item is uploaded again. Deleted items and vaults stay
  on the server (encrypted) for 30 days before a daily job purges them.
- **Vaults.** Vaults are deleted with a proof as well. A vault that
  disappears from the server is kept on the device, read-only, instead of
  being wiped.
- **Account deletion** is scheduled 7 days ahead and can be cancelled.

## Sessions

Signing in requires the auth secret, i.e. the master password **and** the
Secret Key. Email-based sign-ins (password recovery, magic links, one-time
codes) would give a session without either, so they are refused twice:

- a Supabase Auth *Custom Access Token* hook
  (`public.keyless_access_token_hook`) rejects every authentication method
  except `password` and `token_refresh` (it must be enabled in the Supabase
  dashboard, Authentication > Hooks);
- every Row Level Security policy and RPC also requires a `password` entry in
  the session's `amr` claim.

Even with a stolen session, an attacker cannot read anything, and the
integrity checks above stop them from destroying data.

Libraries: RustCrypto `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`
and `x25519-dalek`; randomness from the operating system via `getrandom`.

## What the server stores

- `auth.users`: email, bcrypt hash of the auth secret, timestamps (Supabase Auth).
- `profiles`: KDF parameters, wrapped user key, public key, wrapped private key.
- `vaults`, `vault_members`: wrapped vault keys and encrypted vault metadata.
- `items`: encrypted overview and details, a revision counter and a sync
  sequence number. Deleted items keep only their id and deletion time.

Row Level Security limits every table to the rows of vaults the user belongs
to. Server-managed columns (`seq`, `revision`, timestamps) are set by
triggers and are not writable through the API; `anon` has no access at all.

**Metadata the server can see:** email addresses, how many vaults and items an
account has, approximate item sizes (padded), and when items change.

## The desktop app

- All cryptography runs in Rust. The web UI never holds keys; secret field
  values (passwords, card numbers, one-time password secrets) are sent to it
  only when the user explicitly reveals or edits them. Copying happens in Rust.
- Copied secrets are marked so clipboard managers don't keep them
  (`x-kde-passwordManagerHint` on Linux, excluded from history and cloud
  clipboard on Windows) and are cleared after a configurable delay.
- Auto-lock after inactivity, on system sleep and on screen lock. Locking drops
  every key from memory (keys are zeroized on drop).
- Unlock attempts are throttled (exponential back-off after 5 failures,
  persisted across restarts, one attempt at a time).
- Showing the Secret Key again requires the master password.
- The local database contains only what the server stores, plus the refresh
  token encrypted with the user key. File permissions are restricted to the
  current user.
- The Secret Key is kept in the OS credential store (Windows Credential
  Manager with local-only persistence, Secret Service on Linux). Without one,
  it falls back to a file readable only by the current user, and the app says
  so in Settings.
- New master passwords and backup passwords must reach a zxcvbn score of 3
  ("good"), checked in Rust, not only in the UI.
- On Linux release builds the process is non-dumpable (no core dumps, no
  ptrace by other processes of the same user).
- Strict Content Security Policy, no remote content, navigation locked to the
  bundled UI, no plugin APIs exposed to the web UI (file dialogs and links are
  opened from Rust).

## Accepted limitations

- **No password recovery.** If a user forgets the master password and loses
  every device and the Emergency Kit, their data is gone. This is what makes
  the zero-knowledge guarantee possible.
- **Offline devices keep the old master password.** A device that was not
  online when the master password was changed still unlocks its local copy
  with the old one, until it signs in again. Its server session is revoked by
  the change, so it cannot sync until then.
- **A compromised device is out of scope.** Malware running as the user while
  Keyless is unlocked can read what Keyless displays.
- **The web UI's memory cannot be wiped.** Values the user reveals or edits
  stay in the webview's memory until it reuses it.
- **A malicious server can withhold data** or refuse to store it, and it can
  serve stale data for items a device has never seen before. It cannot read,
  forge, roll back or delete data on a device. Keep an encrypted backup.

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately through
GitHub.
