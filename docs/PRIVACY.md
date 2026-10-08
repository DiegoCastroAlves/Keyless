# Keyless privacy policy

Last updated: October 8, 2026

Keyless is a zero-knowledge password manager. Everything you store in your
vaults is encrypted on your device before it is sent anywhere, with keys that
are derived from your master password and your Secret Key. Neither of them
ever leaves your devices, so nobody else, including whoever runs the Keyless
server, can read your vaults.

## What the server stores

- Your email address, used to identify your account.
- Your encrypted vault data (ciphertext), your public key and your encrypted
  keys.
- Technical metadata needed to sync: how many vaults and items you have,
  approximate item sizes, and when they change.
- Connection logs kept by our hosting provider (IP address, time, request
  type) for security and operations.

## Sign in with Google

If you choose to continue with Google, Keyless receives your verified email
address, your name and your profile picture from Google. They are stored with
your account and used only to identify it. Keyless does not request access to
any other Google data or service, and a Google sign-in never gives access to
your vaults: unlocking them always requires your master password and Secret
Key.

## Third parties

- **Supabase** hosts the Keyless server (authentication and database).
- **Have I Been Pwned** checks whether a password appears in known breaches
  for Sentinel: once a day and when you save a new password (you can turn
  this off in Sentinel), or when you ask. Only the first 5 characters of the
  password's SHA-1 hash are sent (k-anonymity); the password itself never
  leaves your device.
- **Have I Been Pwned** and **2fa.directory** publish the lists of breached
  websites, and of websites with two-factor codes or passkeys, that Sentinel
  downloads whole once a day and keeps on your device to compare there.
  Nothing about your items is sent to them; like any download, they see the
  request's IP address.

Keyless has no ads, no analytics or tracking, and never sells or shares your
data.

## Deleting your data

You can delete your account in the app (Settings > Account). The account and
everything stored with it are permanently deleted after 7 days, a window in
which you can cancel by signing in again. Items you delete are kept, still
encrypted, for 30 days in Recently Deleted.

## Contact

Questions about this policy: diego.castroalves1@gmail.com.
