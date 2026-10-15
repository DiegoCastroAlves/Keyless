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
| Recovery key (248 random bits, optional) | The user's printed or saved copy | Never; a proof derived from it is sent while recovering, and the server stores only its SHA-256 hash |

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

## Recovery key

Optional, like 1Password's recovery codes: it gets the user back in when the
master password is forgotten or the Secret Key lost. It is made (and
replaced, or removed) in Settings > Account with the master password, and
offered once after signing in.

```text
proof = HKDF-SHA256(ikm = recovery key, salt = "keyless/v1/recovery", info = "proof")[32]
rkek  = HKDF-SHA256(ikm = recovery key, salt = "keyless/v1/recovery", info = "key encryption key")[32]
private.recovery_keys = { SHA-256(proof), seal(rkek, user key, "recovery-user-key" | user id) }
```

- Recovering takes the account's email and the recovery key. `begin_recovery`
  checks the proof and returns the encrypted user key and key pair; the device
  opens them, makes a new master password, a new Secret Key and the next
  recovery key, and shows them to be saved before sending anything.
  `complete_recovery` checks the proof again, stores the new auth secret (as
  Supabase Auth stores passwords) and user key wrapping, replaces the
  recovery key and ends every session. The user key, and so every vault key,
  stays the same.
- Both functions are open to anyone, so a wrong proof and an unknown email
  fail the same way, failures are limited to 10 an hour per account, and a
  proof is 256 bits from 248 random ones.
- Whoever has the recovery key and knows the email gets in, with no second
  check (Supabase's email delivery cannot be relied on): it must be kept as
  carefully as the Emergency Kit, which is why it is optional.

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
  except `password` and `token_refresh`, and Google as described below (it
  must be enabled in the Supabase dashboard, Authentication > Hooks);
- every Row Level Security policy and RPC also requires a `password` entry in
  the session's `amr` claim.

Even with a stolen session, an attacker cannot read anything, and the
integrity checks above stop them from destroying data.

### Continue with Google

Google only identifies the account; it never replaces the master password or
the Secret Key, and Google never sees either.

- The app runs the OAuth 2.0 authorization code flow with PKCE in the system
  browser, with a loopback redirect (`http://127.0.0.1:<port>/auth/callback`,
  RFC 8252). The code is useless without the verifier, which never leaves the
  app.
- A Google session can read nothing: it has no `password` entry in `amr`.
- The hook issues Google sessions only to accounts that are not set up yet.
  The app uses that session once, to set the auth secret derived from the new
  master password and Secret Key, and then signs in with it like any other
  account. Setting up the account (creating its profile) ends every session
  that did not prove the password.
- For an account that is already set up, the hook refuses the Google session
  and returns only the account's email, to the app that completed the Google
  sign-in. The user then signs in with the Secret Key and master password.
  So whoever controls the Google account can never obtain a session that
  could change the auth secret of an existing Keyless account.

### Devices

Each signed-in app registers itself (`public.devices`): a random id, the
SHA-256 of a random device secret, its Supabase Auth session, and its name,
system and app version sealed with the user key (`"device-info" | user id |
device id`). The server adds the address and country of the device's last
request (from the CDN's headers) and when it was last seen.

- Signing a device out from another one (`revoke_device`) deletes its
  session and refresh tokens. `private.password_session()` also requires the
  session to still exist, so its access token stops working at once rather
  than when it expires.
- The signed-out device notices when the server refuses its session: it asks
  `device_status` with its secret (open to anyone, but only the device knows
  the secret), and on `revoked` it signs out, deleting the Secret Key and the
  account's local data.
- "Sign out all other devices" ends every other session of the account,
  devices of older versions included; they keep their data and need the
  master password to sign in again.

### Signing in with another device

Like 1Password's "Sign in with another device", but the server only relays
(see `keyless_core::device_setup` and the `device_setup` migration):

- The new device leaves a request for the email with an X25519 public key and
  a commitment to a random nonce. A signed-in device answers with its own key
  and nonce; the new device reveals its nonce; both derive a 6-digit code
  from the two keys and nonces, and the user types on the signed-in device
  the code the new device shows. Only then does it send the email and
  Secret Key, sealed with a key from the X25519 exchange.
- A relay that swaps the keys must pick its answer to the new device before
  learning its nonce, so the codes match by chance only (one in a million
  per attempt). Three wrong codes refuse the request; a request lasts 10
  minutes; anyone can ask, so the server allows 3 waiting and 10 an hour per
  account and 20 an hour per address, and an unknown email gets a request no
  device will see.
- What is sent is what an Emergency Kit holds: the master password is still
  needed on the new device.

### Signing in with a QR code

The new device shows a QR code that a signed-in phone reads (see
`keyless_core::qr_sign_in` and the `qr_sign_in` migration):

- The code is a `keyless://sign-in#id=…&key=…&token=…` link: a random
  request id, an X25519 public key and a 16-byte token. The new device leaves
  only the id, the hash of a secret it polls with, and its platform on the
  server; the key and the token travel only through the camera.
- The phone shows where the request comes from (platform, country, address)
  and asks before answering. It then seals the email and Secret Key with a
  key derived from a fresh X25519 exchange and the token (HKDF, salt
  `keyless/v1/qr-sign-in`, info: both public keys and the token), bound to
  the request id, and leaves its public key and the ciphertext on the
  server. The new device takes them once.
- The server sees neither the new device's key nor the token, so it can
  neither read the answer nor replace it with one of its own. Someone else
  who sees the QR code can at most send the new device another account
  (whose email it shows) or refuse the request; polling needs the secret,
  which is not in the code. Requests last 10 minutes, and the server takes
  20 an hour per address.
- As with another device, only what an Emergency Kit holds is sent: the
  master password is still typed on the new device. The phone warns never
  to read a code someone else sent.

### Setup codes

A setup code is the account's email and Secret Key as a
`keyless://setup#email=…&key=…` link (in the fragment, so it stays out of
logs): shown as a QR code by a signed-in device after the master password,
and printed on the Emergency Kit, whose PDF also links the QR code to it.
Keyless reads one from the screen, the clipboard, a picture or the Kit's
PDF (in memory), or takes the link opened or pasted, and keeps it only in
memory until the sign-in.

### Changing the Secret Key or the email

- A new Secret Key wraps the same user key with keys derived from the same
  master password and the new key, committed in the same staged steps as a
  master password change. The new key is kept on the device under a separate
  name until the server has it, so an interrupted change can be finished.
  Every other session ends.
- The email changes through Supabase Auth's secure email change (links to
  both addresses), with a PKCE challenge whose verifier the app drops: the
  links change the email but never create a session. Each device follows the
  email the server has, moving its Secret Key entry.

Libraries: RustCrypto `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`,
`x25519-dalek`, `p256` (passkeys) and `aes-gcm` (the browser bridge);
randomness from the operating system via `getrandom`; memory locking via
`region`.

## What the server stores

- `auth.users`: email, bcrypt hash of the auth secret, timestamps (Supabase Auth).
- `profiles`: KDF parameters, wrapped user key, public key, wrapped private key.
- `vaults`, `vault_members`: wrapped vault keys and encrypted vault metadata.
- `items`: encrypted overview and details, a revision counter and a sync
  sequence number. A deleted item keeps its encrypted content for 30 days
  (Recently Deleted, see above), then only its id and deletion time.
- `item_versions`: the encrypted overview and details each write replaced,
  copied by a trigger (clients can only read them): the newest 30 per item,
  for a year. The client opens and checks them like any item (same vault and
  item, same write, older than the current version), and restoring one saves
  its content as a new version, so rollback protection is unchanged.
- Storage bucket `attachments` (private): item attachments as encrypted
  chunks, named `<vault id>/<attachment id>/<chunk>`. Each file has its own
  random key, kept with its name and size in the item's encrypted details;
  it is encrypted on the device in chunks of 4 MiB (XChaCha20-Poly1305),
  each bound to its attachment, position and whether it is the last, so
  chunks cannot be swapped, reordered, dropped or added. Vault members read
  them, writers add and remove them, the uploader can always remove their
  own, and nothing replaces an object. Each account may keep 250 MiB, a
  limit enforced by the policies. A saved file is written under its final
  name only once every chunk checked out (until then it is a hidden file
  only the current user can read). Attachments are not part of the
  item history (removing one deletes it for good). Backups keep each file's
  chunks as the server has them (their keys are inside the backup's
  encrypted item list), and a restored or imported file is encrypted again
  as a new attachment, with a new id and key.

- `shares`: share links. A snapshot of an item (title, websites, notes and
  the fields with a value; no one-time password secrets, passkeys,
  attachments or password history), encrypted with a random key that exists
  only in the link's fragment (`#<id>.<key>`, which browsers never send), and
  a label encrypted with the owner's key. The owner can list and revoke
  links but never read the snapshot back; anyone with a link opens it with
  `open_share()`, which counts the view, until it expires (30 days at most),
  is revoked or has been viewed as many times as allowed (once, if asked).
  Each account may have 100 active links.

Row Level Security limits every table to the rows of vaults the user belongs
to. Server-managed columns (`seq`, `revision`, timestamps) are set by
triggers and are not writable through the API; `anon` has no access at all.

**Metadata the server can see:** email addresses, how many vaults and items an
account has, approximate item sizes (padded), when items change, and how many
attachments a vault has and their sizes (not their names or contents).

## The desktop app

- All cryptography runs in Rust. The web UI never holds keys; secret field
  values (passwords, card numbers, one-time password secrets) are sent to it
  only when the user explicitly reveals or edits them. Copying happens in Rust.
- Copied secrets are marked so clipboard managers don't keep them
  (`x-kde-passwordManagerHint` on Linux, excluded from history and cloud
  clipboard on Windows) and are cleared after a configurable delay.
- Auto-lock after inactivity, on system sleep and on screen lock. Locking drops
  every key from memory (keys are zeroized on drop), and wipes the decrypted
  item overviews (titles, usernames, websites, tags) and vault names.
  Inactivity is of the whole computer where the system tells Keyless (the
  last input on Windows; the Wayland compositor's input-idle notification,
  which a playing video does not hold back, or the desktop's D-Bus service
  in X11 sessions), or of Keyless only, by choice; if the compositor stops
  telling, only Keyless's own use counts again. The auto-lock can be turned
  off ("never"), and closing the main window can lock. Item windows close
  when Keyless locks.
- Keys (the user key, vault keys, the account's private key and the keys
  derived from them) each live on a 4 KiB memory page of their own, locked
  in RAM (mlock / VirtualLock), so they are never written to a swap or page
  file. A key per page means that freeing one never unlocks another. If the
  system refuses to lock more memory, keys still work, just unlocked.
- Messages to and from the browser extension (which carry passwords, card
  numbers and codes) are wiped from memory once handled.
- Unlock attempts are throttled (exponential back-off after 5 failures,
  persisted across restarts, one attempt at a time).
- Showing the Secret Key, changing the master password, exporting a backup and
  deleting the account always require the master password.
- A backup (`.keyless`) is a zip archive: the items, encrypted with a key
  derived with Argon2id from the backup password, and each attached file's
  encrypted chunks, which only that list's keys open (so files cannot be
  swapped or altered). A backup has no Secret Key, so its password alone
  resists offline guessing: it must reach zxcvbn's top score (4), checked in
  Rust, and its Argon2id uses 256 MiB (four times the account's; the
  parameters are in the file, so older backups still open). Passkeys are
  included unless the user unticks them (for a backup handed to someone
  else: with them, whoever imports it signs in as the user). The archive shows how many files there are and
  their sizes. Backups and exports are written to a hidden file that takes
  its name once complete.
- An unencrypted export (CSV, JSON, a ZIP with the JSON and the attached
  files, the Credential Exchange Format, or a 1Password `.1pux` with the
  files, for moving to another password manager) also requires the master
  password and an explicit confirmation after a warning; the file is
  written readable only by the current user. Folders in the ZIP are named
  after attachment ids only when they are ids Keyless makes. Passkeys are
  never in it (as with 1Password): their private keys would be in plain
  text, and no other password manager imports them. In the
  CSV, a cell a spreadsheet would run as a formula (a website chooses the
  title and user name of a login created with its passkey) starts with `'`,
  which Keyless's own import removes; passwords and notes are kept as they
  are.
- Imports read other password managers' files in memory, in Rust: CSV
  (most managers), JSON (Bitwarden, Keeper, CXF), 1PUX, 1PIF, Dashlane's ZIP,
  and encrypted ones with their password: Bitwarden's password-protected
  JSON (PBKDF2 or Argon2id, its HMAC checked before AES-CBC) and KeePass
  databases (KDBX 3.1 and 4, password and/or key file; the header HMAC or
  the stream start bytes tell a wrong key). Their key derivation parameters
  are bounded before use, sizes are capped (files, decompressed data), and
  nothing from an import is written until the user confirms; the imported
  items are then encrypted like any other. Links between imported items
  (related items, "sign in with" accounts) are kept by giving each item its
  Keyless id while reading.
- Optional unlock with the computer password (Linux packages, via a polkit
  action with `auth_self`: the user's own password or fingerprint, never
  cached, active local session only) or Windows Hello (the system's user
  consent prompt: face, fingerprint or PIN). After the master password unlocked the
  vault, locking can keep the user key, never on disk, so polkit or Windows
  Hello can confirm the user instead. The operating system's answer is only
  a yes or no, so the kept key is sealed (XChaCha20-Poly1305) with a random
  key held outside Keyless's ordinary memory, as 1Password does on Linux: a
  key in the process's kernel keyring that only Keyless can read, with a
  kernel timeout, on Linux; encrypted with `CryptProtectMemory` (same
  process) on Windows. A memory dump or swap file of a locked Keyless does
  not hold the user key. The rest of the account keys are opened from the
  local account with it. The kept key is dropped when Keyless quits, when
  the computer sleeps, on sign out, when the setting is turned off and when
  the master password was last entered too long ago (on Linux the kernel
  deletes the sealing key then too). How long the master password lasts
  for this is the user's choice: one day (the default), 7, 14 or 30 days,
  or until Keyless quits or the computer sleeps, which can only be chosen,
  after checking with the server, for an account with a recovery key (and
  goes back to 30 days if the recovery key is removed). Turning it on
  requires the master password. Where no key can be guarded (a sandbox without the kernel
  keyring), the option is not offered.
- The local database contains what the server stores, plus a few things that
  never leave the device: the refresh token, website icons, the password
  generator history and Sentinel's results (each encrypted with a key
  derived from the user key; icon rows are named by a keyed hash, not by the
  site), and how often and when each item was last used (by its random id).
  Readable without the master password, as on the server: the account's
  email and server address, ids, roles and version counters, settings, the
  names of paired browsers, and pending attachment deletions. File
  permissions are restricted to the current user, and signing out wipes it
  (settings stay).
- The Secret Key is kept in the OS credential store (Windows Credential
  Manager with local-only persistence, Secret Service on Linux). Without one,
  or if it refuses to save it, it falls back to a file readable only by the
  current user (an ACL for the current user only on Windows), the app says
  so in Settings, and the key moves into the credential store as soon as it
  works. A store that is there but fails is asked again a few times and is
  never taken to mean "no Secret Key saved".
- New master passwords must reach a zxcvbn score of 3 ("good") and backup
  passwords a score of 4 ("strong"), checked in Rust, not only in the UI.
- On Linux release builds the process is non-dumpable (no core dumps, no
  ptrace by other processes of the same user). On Windows release builds,
  Windows Error Reporting is off for Keyless (no crash dumps or reports),
  the current folder is not searched for DLLs, and DLLs from network shares
  or low-integrity files are refused.
- Strict Content Security Policy, no remote content, navigation locked to the
  bundled UI, no plugin APIs exposed to the web UI (file dialogs and links are
  opened from Rust). The web UI names files to attach by path, but only files
  the user dropped on the window or chose in the file dialog within the last
  hour can be attached.
- Notes are shown as Markdown without any HTML: the renderer makes React
  elements only, links open in the system browser through Rust (http, https
  and mailto only), and images can only be the item's own attachments, so a
  note cannot load anything from the network.
- Attached images and text files can be previewed: the file (up to 10 MB) is
  decrypted in memory and never written to disk. An image reaches the page
  re-encoded in Rust as a PNG of at most 1600 pixels, so only clean pixels
  do; text (up to 1 MB of UTF-8 without the control characters of binary
  files) is shown as plain text. Other files have to be saved to be opened.
- An icon the user gives an item is decoded in Rust and stored as a new PNG
  of at most 128 pixels, inside the item's encrypted details; the file's
  own bytes are never kept. Saving accepts only a PNG data URL of at most
  96 KB.
- Searching notes and other fields decrypts each item's details in Rust for
  the match, wipes them right after, and gives the page only the ids of the
  items found. Secret values (passwords, card numbers, answers to security
  questions, one-time password secrets) are never searched.
- Printing an item leaves its hidden fields out unless the user includes
  them; one-time password secrets are never printed. The printed page exists
  only while printing.
- Duplicating an item leaves its passkeys and attachments out. Copying it to
  another vault copies the attachments' encrypted chunks on the server (a
  chunk is bound to its attachment, not to the vault), and their keys go
  into the copy's details, encrypted with the other vault's key.
- The words of the system's file dialogs come from the page with each
  command, so they follow the user's language; they are only shown.
- An item can be opened in a window of its own (kept above the others),
  which has the same permissions as the main window. Keyless closes these
  windows when it locks or signs out. The window's title is the item's
  title, which the desktop's window list shows.
- Links to items (`keyless://item/<id>`) are registered for the current
  user as Keyless starts (a desktop entry and `xdg-mime` on Linux,
  `HKEY_CURRENT_USER\Software\Classes` on Windows). Any program or web page
  can open one, so a link can only show an item, by its id, once Keyless
  is unlocked: Keyless takes nothing else from it, and the id must be a
  plain id.
- **Auto-Type** (Quick Access, or the fill shortcut outside a browser)
  types a login's username and password into the window that had the focus
  before Quick Access opened: SendInput on Windows, XTest on X11, and on
  Wayland the desktop's RemoteDesktop portal, which asks the user first; that
  permission is kept in memory only and ends when Keyless locks. Keyless
  refuses to type when the window that would get the keys is one of its own.
  Like any typed text, the target app sees the password; the user picks the
  login and the moment.
- **The fill shortcut** tells the paired browser extensions through their
  status long poll (a counter and a time, nothing else); only an extension
  whose browser window has the focus fills its page, and only for a request
  under three seconds old. Otherwise Quick Access opens to type.
- When the user turns it on, a file attached from disk is moved to the
  system's trash once its encrypted copy is saved (never deleted outright),
  and only files the user just chose or dropped can be attached at all.
- A deleted vault stays on the server, deleted, for 30 days, as before; its
  owner can now restore it from Recently Deleted. Only deletions with a
  valid proof are listed (sync undoes any other).

## SSH agent

Off by default (Settings > Developer). SSH and git ask it to sign with the
SSH keys kept in items; private keys never leave Keyless.

- It listens on `~/.keyless/agent.sock`, in a directory only the user can
  open, with the socket itself readable only by the user, and it refuses
  connections from processes of other users (peer credentials).
- Keys are read from the unlocked vault for each request and are not kept
  after a lock. While Keyless is locked, a request asks to unlock it first.
- Every signature needs the user's approval in a Keyless window that names
  the program asking (and the one that started it), the key and what the
  signature is for: signing in to a server (only when the data is exactly
  an SSH public key sign-in request, whose user name is shown), a git
  commit or tag, other data with its namespace, or data Keyless does not
  recognize. Approval can be remembered until Keyless locks only for
  sign-ins and git signatures, and only for that program, key and purpose:
  letting `ssh` sign in does not let it sign commits. Closing the window,
  or waiting 60 seconds, denies. The window does not take the Enter key, so
  typing in a terminal cannot approve, and "Allow" works only once a request
  has been on screen for a moment, so a double click or a click meant for
  something else cannot approve the next one.
- RSA signatures with SHA-1 (`ssh-rsa`) are refused; only rsa-sha2-256/512,
  Ed25519 and ECDSA.
- The program name comes from the operating system and can be chosen by a
  malicious program of the same user; the approval is a guard against
  surprise use, not against malware already running as the user.

## Sentinel

- Weak and reused passwords, duplicate items (the same website and user
  name, in the same vault), unsecured (`http`) websites, dates due (as far
  ahead as each date field's alert says; a month ahead for expiry dates
  with no alert chosen) and logins imported from LastPass whose password
  was not changed since are found on this device, from the unlocked vault.
  Where an item came from is marked on import ("lastpass", in its
  encrypted overview) and kept when it is edited.
- Nothing about items is sent to compare websites: the public lists of
  breached websites (Have I Been Pwned), of websites with two-factor codes
  (2fa.directory) and of websites that accept passkeys (its Passkeys
  Directory) are downloaded whole once a day while Keyless is unlocked, and
  compared here. They are kept on disk (in the app's data folder, not
  encrypted: they are public), so Sentinel works offline. A new copy
  replaces the old one only once it downloaded whole, reads as the list it
  should be and is not suspiciously short; it is written beside the old one
  and renamed over it, so a failed or broken download keeps the old copy.
  Each list can be turned off on its own in Sentinel (all are on by
  default): it is then not downloaded, its copy on disk is deleted, and its
  alert shows as off. Whether a list is on is checked again before each
  download and, under the same lock that deletes a list turned off, before
  its copy is written, so a download under way cannot bring it back.
- "Learn more" on a breached website shows what that list already says
  about the breach (its name, date, size and the kinds of data that
  leaked); nothing else is fetched for it, and the list's text is shown as
  text, never as HTML.
- Passwords are looked up in Have I Been Pwned with k-anonymity: only the
  first 5 characters of each password's SHA-1 hash leave the device, and
  responses are padded. This runs when the user asks or, with the setting
  (on by default), by itself: every password once a day, and new ones a few
  seconds after they are saved. What it found is kept in the local database,
  encrypted with a key derived from the account key, by a keyed hash of each
  password (so a changed password is checked again and old ones are
  dropped); it is deleted at sign-out and shown only while unlocked.
- While a password is typed in the item editor, its strength and whether
  other items already use it are checked on this device only; partial
  passwords are never sent anywhere (a series of hash prefixes for a
  password being typed could reveal it).
- Ignored alerts are stored in the item's encrypted overview. One that no
  longer applies (the problem was fixed) is marked so and can be removed,
  one by one or all at once (one new version per item). An alert that
  depends on a list turned off or not downloaded yet, or on a password never
  checked online, is never taken for fixed.
- "Use HTTPS" on an unsecured website changes the item's `http://`
  addresses on plain http's own port (none, or an explicit 80, which is
  dropped) to `https://`, and saves the item like any edit: a new version,
  synced. It is not offered for an address on another port, and refused for
  an item in Recently Deleted (saving it would restore it). Keyless does
  not check that the website answers on `https`; it says to open it and
  see.
- The overview can look at one vault instead of all of them, and counts the
  passwords at each strength level (the levels the item view shows); both
  are computed on this device from the same report.
- New serious alerts (breached passwords and websites, dates due, LastPass
  imports) can be announced with a system notification, which says how
  many there are and never which items (notifications can show on a
  locked screen). Which alerts were announced is kept like the checks:
  encrypted, by item id; those from a list that is off or not downloaded
  stay remembered, so turning it back on does not announce them again.
  Notification texts come translated from the page.
- On a website, the browser extension can warn about its logins whose
  password was found in breaches, or that the website lost after the
  password was set. It asks Keyless only about the page it is on (as it
  already does to fill), and only the logins' titles and user names come
  back. "Change password" opens the website's
  `/.well-known/change-password` (checked first with a request without
  cookies; the home page when it has none). "Not now" quiets the website for
  7 days, stored in the extension's own database.
- Secrets in files (Sentinel for developers): only when the user asks,
  Keyless reads `.env` files under the home folder (not in hidden,
  dependency or build folders, at most 256 KB each, a few hundred
  thousand entries and 90 seconds in all), the usual credential files and
  `~/.ssh`. It recognizes about 80 public token formats and variables named
  like secrets, and SSH private keys without a passphrase, of an outdated
  type (DSA) or too short (RSA under 2048 bits). A key's type and length
  come from its public part, which OpenSSH key files keep in clear (or from
  the `.pub` file beside an older key), so no passphrase is asked for. Key
  files whose key is already in a Keyless SSH key item are pointed out, so
  the copy on disk can go. Since that invites deleting the file, it counts
  only private keys on both sides: the SHA-256 fingerprint of the key in
  the file itself (the key, or the public part an OpenSSH key keeps in
  clear) against those of the private keys kept in SSH key items. An item
  with only a public key or a fingerprint, or a `.pub` file beside the key,
  never makes a key "saved", and an older encrypted key, whose key cannot
  be told without its passphrase, never is.
  For a key without a passphrase it offers to copy `ssh-keygen -p -f
  <path>`, which the user runs; Keyless never does. Nothing leaves the
  computer: no secret is ever tried against its service. The page gets
  only where a secret is, what kind it is and a few of its characters.
  Saving one reads the file again and checks it still holds the same secret
  (by hash) before making the item; moving a file to the trash is only for
  files the last search found, and goes to the system's trash. Ignored
  findings are kept encrypted like the checks.

## Share links page

The page that opens share links (`apps/site`, served at
keyless.diegoalves.dev by Cloudflare Pages) is static. It reads the id and
key from the fragment and removes them from the address bar and history
right away, asks before fetching (so link previews do not use up a
one-view link), decrypts in the browser with the same envelope format as
the app, and shows everything as text, never as HTML; only `http` and
`https` websites become links. Its headers allow only its own scripts and
styles, connections only to the Keyless server, no framing and no referrer.
Whoever controls that site could serve a page that leaks keys, so the site
needs the same care as the app's releases.

A link can be only for some emails (`share_recipients` migration). The
server keeps the SHA-256 of each (lowercase), and the owner's encrypted
label keeps the emails themselves. `open_share` then only says the link is
restricted; the page asks for the visitor's email, Supabase Auth sends a
one-time code, and with the session that code gives `open_restricted_share`
hands out the ciphertext if the session's confirmed email is on the list.
The page ends that session right away. Such sessions belong to throwaway
Auth users (marked in their metadata, purged after 30 days unless they
became Keyless accounts): the access token hook allows email-code sessions
only for users without a Keyless account, and they have no `password` in
`amr`, so they read nothing else. A Keyless account's own email cannot be
verified this way (its account signs in only with the master password).
This is a second lock, not encryption: the server, which sees the
ciphertext anyway, decides who gets it; the key still travels only in the
link.

## Web vault

The web vault is off since October 14, 2026: the site publishes none of its
files and the server's passkey sign-in is switched off (`private.switches`).
`apps/site/README.md` says how to turn it back on. When on,
`keyless.diegoalves.dev/vault/` shows the account's items in a browser,
read-only. The keys are derived, the server's answers checked (the same
rules as the desktop sync: content from one write, versions never going
back, deletions with a tombstone) and items decrypted in WebAssembly built
from `crates/keyless-client`, the client the Android app shares; the page
only talks to the server and shows text (never HTML; only `http` and `https`
addresses become links).

- Nothing is kept in the browser except, for convenience, the email. Locking
  (by hand, or after 10 minutes without use) or closing the page forgets
  every key and ends the session on the server.
- Copied values are cleared after 90 seconds while the page has the focus
  (a page cannot clear the clipboard otherwise).
- Its headers allow only its own scripts (and WebAssembly), connections only
  to the Keyless server, no framing and no referrer. As with the share page,
  whoever controls the site could serve a page that leaks what is typed
  there, so the site needs the same care as the app's releases.

### Signing in with a passkey

See `keyless_core::passkey_login` and the `passkeys` migration. The WebAuthn
PRF extension, asked with a fixed salt, gives a secret only the passkey can
produce once the user unlocks it; a proof and a key come from it. The server
keeps the proof's SHA-256 and a bundle sealed with the key that holds the
email, auth secret, user key and Secret Key. `passkey_sign_in` (open to
anyone, 10 failures an hour per passkey) gives the bundle for the right
proof; the browser signs in with the auth secret and opens the account with
the user key. Passkeys are made on the web vault's domain, so the same ones
work wherever that domain's passkeys do; a new auth secret (master password
or Secret Key changed, account recovered) drops them all, by a trigger on
`auth.users`. A passkey is then as strong as the master password and Secret
Key together: whoever can unlock it gets in.
While the switch is off, `passkey_sign_in` answers `passkey_sign_in_off` and
`add_passkey` refuses.

## Android and iOS apps

Both run the same client as the web vault (`crates/keyless-client`, through
JNI on Android and C on iOS): the same key derivation, the same checks on
everything the server sends, and the same decryption.

- What stays on the device: the server's ciphertext (a file, excluded from
  backups, with complete file protection on iOS), and the Secret Key and
  refresh token, encrypted with an Android Keystore key or kept in the iOS
  Keychain (this device only).
- Biometric unlock keeps the user key behind a Keystore key that needs a
  strong biometric for each use (invalidated when biometrics change) or a
  Keychain item tied to the current biometrics. On Android the master
  password is asked again after the phone restarts.
- The screens cannot be captured (Android FLAG_SECURE); copied values are
  marked sensitive and cleared after 90 seconds.
- Autofill (Android) fills a login only for the app or website it names;
  while locked it offers to unlock first. It never fills Keyless itself.
- Passkeys (Android 14 and later, Credential Manager): a browser's origin is
  believed only for Google's list of privileged browsers, checked by
  signing certificate, and must be the site or a subdomain over https; any
  other app must be named, with its signing certificate, in the site's
  Digital Asset Links (`delegate_permission/common.get_login_creds`). New
  passkeys are kept in the site's login and uploaded before the site gets
  them.

## Updates

- The app looks at the public list of releases on GitHub twice a day (this
  can be turned off) and offers to update. Nothing is installed without the
  user's click.
- The release workflow signs every installer with a minisign (Ed25519) key
  that only exists in a GitHub Actions secret and offline with the
  maintainer. Each signature is bound to its version.
- Before installing, the app verifies the signature with the public key built
  into it and checks that the signed version is the announced one, so a
  modified file or an older release (downgrade) is rejected even if GitHub or
  the network is compromised. Windows, AppImage, `.deb` and `.rpm` installs use
  `tauri-plugin-updater` (`requireSignedVersion`); the Arch package is verified
  the same way by Keyless itself and installed with `pkexec pacman -U`.

## The browser extension

The extension never stores vault data or account keys. It asks the desktop
app, which must be running, for what it needs. What it does keep: its own
pairing key and the app's public key (IndexedDB), its settings, and for a few
minutes a login the user just typed, waiting for "Save login?" (see below),
or a password it suggested.

- **Transport.** The browser starts the Keyless executable as a native
  messaging host, which only relays messages to the running app over a local
  socket (Unix socket with mode 0600 and a peer user check on Linux, in a
  folder that must belong to the user; on Windows a named pipe named after
  the user's SID, with an ACL for that user only, that rejects remote
  clients, and whose creator the host checks). Host manifests only allow
  the Keyless extension IDs.
- **Who connects.** The pairing key is stored in the browser profile on
  disk, so the app also checks the process that connects, like 1Password's
  browser helper, once, when it connects: it must be Keyless itself in host
  mode (the same executable, or the same file contents for an AppImage);
  on Linux, not being debugged, with every executable mapping from a system
  file (or, for an AppImage or a development build, from Keyless's own
  folder), no anonymous executable memory, and `LD_PRELOAD`/`LD_AUDIT` only
  naming system files; and it must have been started by a known browser
  installed on the system (owned by root on Linux, where an administrator
  can allow others in `/etc/keyless/allowed_browsers`; on Windows, in
  Program Files or signed by that browser's publisher, looking past the
  `cmd.exe` Chrome and Edge start hosts with). The extension explains a
  refusal. This is a hurdle for a program that copied the pairing key and
  talks to the socket itself, not a wall against malware running as the
  user (see "Accepted limitations").
- **Pairing.** Each browser generates a non-extractable X25519 key pair
  (WebCrypto, stored in IndexedDB). The first connection must be approved in
  the app after checking that the app and the extension show the same 8-digit
  code, derived from both public keys. The extension then pins the app's
  public key; paired browsers are listed in Settings and can be removed.
- **Channel.** Every request and response is encrypted with AES-256-GCM using
  a key from X25519 + HKDF-SHA256 over both public keys, with a direction
  label as associated data. Requests carry a timestamp and a unique ID; stale
  or repeated requests are rejected.
- **Menus inside pages are isolated from them.** The list below a login field
  and the sign-in card are extension pages in iframes, inside a closed shadow
  root. The page cannot read or script them, and in Chromium they run in the
  extension's process. The content script (which runs in the page's process)
  only learns how many logins match the page; it never receives a login
  until the user picks one, and then only to type it into the page.
- **A page cannot drive the menus.** The content script registers a random
  token with the background script and hands it to its menus by
  `postMessage` addressed to the extension origin. The background script
  answers menus only with the token of their tab, so a page that embeds the
  menu page itself gets nothing.
- **A page cannot trick the user into clicking the menus** (clickjacking).
  The menus live in the browser's top layer, above the page, under a random
  tag; changes the page makes to their element are undone. They ignore
  clicks until they have been on screen, unmoved and fully visible, for half
  a second: Chromium reports whether anything covers them or makes them
  see-through (IntersectionObserver v2), and the content script checks the
  styles applied to them and what sits over them. Whenever the page shows a
  dialog, popover or full-screen element of its own (also inside its shadow
  roots), which could sit above the menus even with clicks passing through
  it, the menus refuse clicks, are put back on top and wait again; this is
  what protects Firefox, which lacks IntersectionObserver v2. The list opens by itself
  only in a field the user clicked or reached with Tab, never in card or
  address forms.
- **Frames.** A frame's button and menu act for that frame only: its menus
  present the token its content script registered, tied to the frame and
  its address as the browser reports them, and list, fill and save only for
  that address. They show in frames of the page's site (or of a site that
  shares one account with it, by the same bundled list as below: Apple's
  sign-in frame on iCloud is Apple's own, and the page could be offered its
  logins anyway), and in another site's frames only where the browser
  reports whether the menu is really seen (IntersectionObserver v2, in Chromium): the page around such a frame
  could make it see-through or cover it without the frame noticing, which
  Firefox could not detect, so there frames from other sites are filled only
  from the popup or the keyboard shortcuts. A menu that would be cut off by
  its frame's edges (a payment service's one-field frame, a small sign-in
  box), or that the browser never reports as seen whole (the page around
  the frame blurs or fades it, as iCloud's does with Apple's sign-in), is
  shown by the page instead, still acting only for the frame and taking
  clicks only as the page's own menus do: where the frame can be found by
  its address and size, under its field, otherwise at the top. The popup fills a frame from another site than the page only after
  the user confirms a warning naming both sites (the shortcut skips such
  frames). The sign-in card and the "Save login?" prompt are the page's
  only. Sandboxed frames are never filled, and a frame that navigated
  meanwhile refuses the fill.
- **Only visible fields are filled.** A field that is tiny, transparent
  (counting its parents' opacity), clipped away, moved off the page or out
  of a box that hides its overflow, or covered by something else ("honeypot"
  fields that collect what a password manager fills) is skipped, and each
  value goes into one field only. The one exception is the field the user is
  in (clicked or reached with Tab, then the Keyless menu): some pages keep a
  field transparent until it has focus, and the user chose it. Fields inside
  shadow roots are found too, closed ones through the browser's
  `chrome.dom` API, which only the extension has. What a field is for comes
  from its type, autocomplete, name, label and the text around it, scored;
  it decides which menu shows, never which site gets a login. The tests in
  `apps/extension/test` check that on a few hundred generated pages.
- **Pages get only their own logins.** The background script reports the page
  URL from the browser (not from the page), and the app returns credentials
  only if that URL matches the item's website (same registrable domain, using
  the Public Suffix List; numeric addresses and hosts where anyone can
  publish pages, like script.google.com, must match exactly). Websites that
  share one account count as the same site: iCloud signs in on apple.com,
  for example. They come from Apple's password-manager-resources list
  (curated by password managers together, bundled with the app, never
  downloaded) plus a few big services it leaves out (Apple, Google,
  Microsoft, Amazon and the like), and never apply to an exact-host rule or
  to a plain `http` page. Each website of
  an item can be narrowed to its exact host, or set to never fill. A login
  saved for an `https` address is never
  offered to, or filled into, a plain `http` page. Filling a login saved for
  another site is possible only from the toolbar popup, which a page cannot
  cover, after the user confirms a warning naming both sites; the menus in
  the page list only the page's own logins. Before typing, the content
  script checks that the page is still on the origin the credentials were
  checked against.
- **Signing in after filling, and sign-ins in steps.** With "Sign in after
  filling" on (the default), a filled login form is sent with its own
  button, only when no other field the user can see is still empty (a
  captcha, say) and never in a sign-up or change-password form. When the
  page asked only for part of the login (the username first, the password
  or a one-time code on the next page or view), the background keeps which
  login it was, the address it was filled into and what is left, for 30
  seconds; only the item id, never a secret. A frame of the same site asks
  for the next step once its field shows up, empty and visible; the app
  checks the login against that frame's address again, as for any fill.
  Each step is filled once (a page that shows the password field again
  after a wrong password gets nothing more), and the user typing in a login
  field, the tab going to another site or the time running out ends it.
  Logins of another site, filled from the popup after its warning, never
  continue.
- **Unlocking from the browser.** The extension never sees the master
  password. When it asks Keyless to unlock, the app asks the user itself: the
  operating system's password prompt when "Unlock with the computer password"
  can be used, otherwise a small Keyless window for the master password
  (throttled like the lock screen). The main window stays hidden.
- **Saving logins.** When the user sends a login or sign-up form (a form
  sent by a page script does not count), the content script reports the
  username and password the user typed (it can read them anyway, as the page
  can); card codes, PINs and one-time codes are left out. They wait in the
  browser's session storage, which is kept in memory, for at most 5 minutes.
  The "Save login?" prompt appears only once signing in worked (the form went
  away, or the next page has no login form) and only on the same site (as
  the app works it out with the Public Suffix List, like frames from another
  site: alice.github.io and bob.github.io are different sites). The
  app compares them with the saved logins; nothing is saved until the user
  chooses to in the prompt, an extension page the web page cannot drive, and
  the prompt itself never receives the password. Only a login saved for that
  site, one the prompt offered, can be updated; in a change-password form the
  current password typed picks which one. Updating keeps the old password in
  the item's history.
- **Suggested passwords** are generated by the app. The background script
  keeps the one shown in the menu and fills only that one, into the page's
  new-password fields. They follow the site's rules where it has any (length,
  required and allowed characters): the field's `passwordrules` attribute,
  otherwise Apple's password-manager-resources list of sites' rules (bundled
  with the app, never downloaded), and the field's maximum length. A page
  can only weaken the password suggested for itself, which it receives
  anyway. Rules that cannot be read or met fall back to the usual generator.
- **Cards and addresses.** Menus list credit cards with only their last
  four digits; the full card goes to the page only after the user picks it,
  and only on secure pages (`https`, or the local computer). Identities fill
  address forms the same way. Shops often have a payment service hold the
  card's fields in frames of its own (one per field, often): a card picked
  in a frame's menu also goes to the tab's frames with card fields that are
  of the same site as that frame or the page, or of a known payment service
  (a short list: Stripe, Braintree, Adyen, PayPal, Mercado Pago and the
  like), asked right then which have such fields; never to other sites'
  frames, like ads, that happen to ask for a card.
- **Passkeys.** A script in the page's own world replaces
  `navigator.credentials.create/get` and only relays the request; the
  extension takes the origin from the browser (https or localhost), and the
  app checks the relying party id against it: the host or a parent domain,
  never a public suffix (Public Suffix List, private entries included), an
  IP address or a single label. The user decides in Keyless's prompt at the
  top of the page, over the page dimmed (like 1Password's): an extension
  page the web page cannot read or drive, protected against clickjacking
  like the menus that fill passwords (see above), which only shows the
  request the background holds for that tab and passes on the choice. Where
  the page cannot show it, a separate Keyless window does. The user can
  hand the request back to the browser ("another device", or closing the
  prompt or window, as in Bitwarden); the window's Cancel refuses it. A
  site that names another site's relying party is refused before the
  prompt opens. It opens even when Keyless has no passkey for the site (as
  in Bitwarden), so a page cannot learn without the user whether Keyless
  has one. Keys are ES256,
  created and used in the app, stored in the item like any other secret;
  responses use "none" attestation, a counter that stays 0 and the backup
  flags of a synced passkey. User verification is reported because Keyless
  is unlocked and the user chose in its window or menu (Bitwarden does the
  same); Keyless does not ask for the master password again.
  - *In frames*, the request is the frame's, checked against the frame's
    origin. A frame of another origin than the page (or than any frame
    between them) may sign in only where the page allows passkeys in it
    (its Permissions Policy, read where the page's scripts cannot change
    it); `clientDataJSON` then says so (`crossOrigin`, `topOrigin`) and the
    prompt names the page. Creating a passkey in such a frame, and anything
    where the browser cannot tell what the page allows (Firefox), is left to
    the browser.
  - *Offered in the page's fields* (conditional mediation): no window opens;
    the passkeys are listed in the Keyless menu under fields that ask for
    them (autocomplete "webauthn") and in the sign-in card, with the same
    protection against clickjacking as any menu, while the browser's own
    suggestions stay available; whichever the user picks wins, and the other
    is called off. Passkeys made quietly after a password sign-in
    (conditional create) are left to the browser.
  - *Extensions*: `credProps` is answered (always discoverable) and `prf` is
    supported: for each input the site gives, an HMAC-SHA-256 over the input
    hashed as browsers do (`"WebAuthn PRF" || 0 || input`), keyed with a
    secret derived (HKDF) from the passkey's private key and id, so every
    passkey has one and it goes wherever the passkey goes. Others are not
    supported.
  Keyless versions before passkeys drop them when they edit the item, and
  the same goes for per-website fill rules; versions since then keep
  whatever a later version added to an item (wiped from memory like the
  rest) when they edit it.
- **Pinned app key.** If the app answers with a different key than the one
  pinned at pairing, the extension refuses to talk to it until the user pairs
  again.
- **One-time codes** are filled into the field the page asks for them
  (next to the password, or on the sign-in's next step, also from the card
  and a keyboard shortcut of their own); when a login is filled where no
  field asks for its code yet, the code is copied instead, ready for the
  next step.
- **Copying** from the popup, and of the one-time password after filling a
  login, is done by the app, so the clipboard is kept out of history and
  cleared automatically.
- **Extension settings** (sites where Keyless is hidden or never offers to
  save, and the like) stay in the extension's own storage in that browser,
  which content scripts cannot read; pages only learn what applies to them.
  Turning off the browser's own password manager needs the optional
  `privacy` permission, asked only when the user chooses to.
- **Vaults per browser.** The user can choose which vaults a browser uses.
  The extension sends that list with each request and the app leaves the
  other vaults out of every answer (matches, searches, cards and
  identities, passkeys, save choices) and refuses requests for their items
  by id.
- **Asking before filling.** A login on a page without encryption (`http`,
  except this computer) is filled only after the user confirms, from the
  popup or the menu; the keyboard shortcut opens the popup instead. A login
  saved for another site is filled from the popup only after a warning,
  which can also add the page's site to the login (the app adds the page's
  origin, nothing else). Cards and personal details can be confirmed every
  time, by choice. Each website of a login can say whether filling signs in,
  overriding the extension's setting.
- **Pasted passwords and the Secret Key.** When a password is pasted into a
  password field, the extension asks the app (over the same channel)
  whether it belongs to a login for that page; if it is another site's
  login, the page warns, names those logins, and offers to take the paste
  back (or, for a single login, to add the page's site to it). Text shaped
  like a Keyless Secret Key pasted into any website but Keyless's own warns
  the same way. Nothing is checked online.
- **Two-factor setup QR codes.** "Read the QR code on this page" takes a
  picture of the visible tab (for this the extension holds the
  `<all_urls>` host permission; its scripts still run in http and https
  pages only) and sends it to the app, which decodes it in memory and keeps
  only a valid `otpauth://` address; the code is saved only in a login for
  that page.
- **SSH public keys** of the vault's SSH key items are offered in a site's
  box for one (its name or hint says SSH key). Private keys never leave the
  app.
- **Cards and identities typed in forms** are offered for saving like
  logins (not when Keyless already has the same card or identity, and not
  on sites where saving is off), and saved only when the user says so.
- **Context menu**: open the Keyless menu at a field, save the login typed
  in its form now, hide Keyless on the site, lock. The field's menu offers
  the same "save now" when a password typed by hand (not filled by
  Keyless) is in the form.
- **The browser's own sign-in window** (HTTP Basic/Digest) is answered
  from an extension window that lists the logins for that address only;
  the credentials go to the browser through `webRequestAuthProvider`
  (Chromium) or a blocking `onAuthRequired` (Firefox), never through a
  page.
- **"Sign in with" logins** (Google, Apple, Microsoft…) are filled by
  pressing the page's button for the provider. On the provider's own sign-in
  pages that follow (a fixed list of hosts per provider), the content
  script is told the account's email to pick, and only there, for three
  minutes. A provider button the user presses on a site without such a
  login is remembered for ten minutes in session storage; back on the site,
  Keyless offers to save one (linked to the provider's login the user filled
  there, or the only one Keyless has for it).
- **Every kind of item in the popup.** The popup lists and shows any item
  (cards, notes, SSH keys…), within the vaults that browser may use. The app
  sends secret values (concealed fields, PINs, card numbers, old passwords)
  only when the user asks to see one, and copies them itself. It can also
  favorite, archive or move items to the trash (several at once, restorable
  in the app), save an attached file through the app's own save dialog, and
  open an item in the app's editor; it never edits items itself. Notes are
  rendered from Markdown into DOM nodes only, with no HTML from the note and
  nothing loaded from the network.
- **API keys copied on a page.** A copied word (by keyboard, or the page's
  own "Copy" button next to it) that could be a key goes to the app, which
  checks its shape against the known formats (`secret_patterns`) and
  answers only whether it is one and whether it is saved already. Keyless
  offers to save a new one as an API credential noting the site; it is never
  used to fill pages.
- **The tutorial** (keyless.diegoalves.dev/tutorial/, opened once after
  installing and from the popup's menu) is a static page whose practice forms
  send nothing (`form-action 'none'`, `connect-src 'none'`); it tells
  Keyless's fills from typing only by the browser's trusted-event flag.
- Turning off "Browser integration" in Settings removes the host manifests,
  so browsers can no longer start the bridge.

## Accepted limitations

- **No recovery without the recovery key.** A user without one who forgets
  the master password, or loses the Secret Key (the Emergency Kit and every
  device), loses their data. This is what makes the zero-knowledge guarantee
  possible.
- **Offline devices keep the old master password.** A device that was not
  online when the master password was changed still unlocks its local copy
  with the old one, until it signs in again. Its server session is revoked by
  the change, so it cannot sync until then.
- **A compromised device is out of scope.** Malware running as the user while
  Keyless is unlocked can read what Keyless displays.
- **The web UI's memory cannot be wiped.** Values the user reveals or edits
  stay in the webview's memory until it reuses it.
- **Unlock with the computer password trades some security for comfort.**
  When it is on, anyone who knows the computer password can open Keyless
  while it is running. It is off by default.
- **Filled passwords belong to the page.** Once a password is filled into a
  site, that site's scripts can read it, as with any password manager. A
  compromised browser can also act as the paired extension while the app is
  unlocked.
- **Malware running as the user can get past the bridge's process checks**
  while Keyless is unlocked: they look at the host once, when it connects,
  and everything they look at is the user's to control. For example, it can
  start a real browser with its own library injected (only the host is
  checked, not the browser), point the browser's host manifest (a file in
  the user's folders) at a wrapper around the real host, load a copy of the
  extension (its id is fixed by a public key) in a browser profile of its
  own, take over the host after the check (it is not hardened on Linux, and
  Windows has no process ACL), run a copied AppImage with libraries of its
  own, or, on Windows, use a scriptable program signed by a browser
  publisher renamed as that browser. With the pairing key from the browser
  profile it can then ask for any login. As with 1Password, a device
  compromised while unlocked is out of scope; the checks stop programs that
  only copied the key.
- **A malicious server can withhold data** or refuse to store it, and it can
  serve stale data for items a device has never seen before. It cannot read,
  forge, roll back or delete data on a device. Keep an encrypted backup.
- **Attachments need the network.** Backups and exports leave out (and
  report) files they cannot download, and an account deleted for good
  leaves its attachment objects
  behind until an administrator removes them (Storage objects can only be
  deleted through the Storage API, not by the daily purge).

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately through
GitHub.
