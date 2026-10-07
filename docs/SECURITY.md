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

Libraries: RustCrypto `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`
and `x25519-dalek`; randomness from the operating system via `getrandom`.

## What the server stores

- `auth.users`: email, bcrypt hash of the auth secret, timestamps (Supabase Auth).
- `profiles`: KDF parameters, wrapped user key, public key, wrapped private key.
- `vaults`, `vault_members`: wrapped vault keys and encrypted vault metadata.
- `items`: encrypted overview and details, a revision counter and a sync
  sequence number. Deleted items keep only their id and deletion time.
- `item_versions`: the encrypted overview and details each write replaced,
  copied by a trigger (clients can only read them): the newest 30 per item,
  for a year. The client opens and checks them like any item (same vault and
  item, same write, older than the current version), and restoring one saves
  its content as a new version, so rollback protection is unchanged.

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
- Showing the Secret Key, changing the master password, exporting a backup and
  deleting the account always require the master password.
- Optional unlock with the computer password (Linux packages, via a polkit
  action with `auth_self`: the user's own password or fingerprint, never
  cached, active local session only). After the master password unlocked the
  vault, locking can keep the account keys in memory, never on disk, so polkit
  can confirm the user instead. The kept keys are dropped when Keyless quits,
  when the computer sleeps, on sign out, when the setting is turned off and 24
  hours after the master password was last entered. Turning it on requires the
  master password.
- The local database contains what the server stores, plus a few things that
  never leave the device: the refresh token, website icons and the password
  generator history (each encrypted with a key derived from the user key; icon
  rows are named by a keyed hash, not by the site), and how often each item
  was used (by its random id). File permissions are restricted to the current
  user, and signing out wipes it.
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

The extension never stores vault data or keys. It asks the desktop app, which
must be running, for what it needs.

- **Transport.** The browser starts the Keyless executable as a native
  messaging host, which only relays messages to the running app over a local
  socket (Unix socket with mode 0600 and a peer user check on Linux, a named
  pipe on Windows). Host manifests only allow the Keyless extension IDs.
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
  styles applied to them and what sits over them. The list opens by itself
  only in a field the user clicked or reached with Tab, never in card or
  address forms.
- **Only visible fields are filled.** A field that is tiny, transparent,
  moved off the page or covered by something else ("honeypot" fields that
  collect what a password manager fills) is skipped, and each value goes
  into one field only.
- **Pages get only their own logins.** The background script reports the page
  URL from the browser (not from the page), and the app returns credentials
  only if that URL matches the item's website (same registrable domain, using
  the Public Suffix List; numeric addresses and hosts where anyone can
  publish pages, like script.google.com, must match exactly). Each website of
  an item can be narrowed to its exact host, or set to never fill. A login
  saved for an `https` address is never
  offered to, or filled into, a plain `http` page. Filling a login saved for
  another site is possible only from the toolbar popup, which a page cannot
  cover, after the user confirms a warning naming both sites; the menus in
  the page list only the page's own logins. Before typing, the content
  script checks that the page is still on the origin the credentials were
  checked against.
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
  away, or the next page has no login form) and only on the same site. The
  app compares them with the saved logins; nothing is saved until the user
  chooses to in the prompt, an extension page the web page cannot drive, and
  the prompt itself never receives the password. Only a login saved for that
  site, one the prompt offered, can be updated; in a change-password form the
  current password typed picks which one. Updating keeps the old password in
  the item's history.
- **Suggested passwords** are generated by the app. The background script
  keeps the one shown in the menu and fills only that one, into the page's
  new-password fields.
- **Cards and addresses.** Menus list credit cards with only their last
  four digits; the full card goes to the page only after the user picks it,
  and only on secure pages (`https`, or the local computer). Identities fill
  address forms the same way.
- **Pinned app key.** If the app answers with a different key than the one
  pinned at pairing, the extension refuses to talk to it until the user pairs
  again.
- **Copying** from the popup, and of the one-time password after filling a
  login, is done by the app, so the clipboard is kept out of history and
  cleared automatically.
- **Extension settings** (sites where Keyless is hidden or never offers to
  save, and the like) stay in the extension's own storage in that browser,
  which content scripts cannot read; pages only learn what applies to them.
  Turning off the browser's own password manager needs the optional
  `privacy` permission, asked only when the user chooses to.
- Turning off "Browser integration" in Settings removes the host manifests,
  so browsers can no longer start the bridge.

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
- **Unlock with the computer password trades some security for comfort.**
  When it is on, anyone who knows the computer password can open Keyless
  while it is running. It is off by default.
- **Filled passwords belong to the page.** Once a password is filled into a
  site, that site's scripts can read it, as with any password manager. A
  compromised browser can also act as the paired extension while the app is
  unlocked.
- **A malicious server can withhold data** or refuse to store it, and it can
  serve stale data for items a device has never seen before. It cannot read,
  forge, roll back or delete data on a device. Keep an encrypted backup.

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately through
GitHub.
