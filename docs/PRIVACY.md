# Keyless privacy policy

Last updated: October 6, 2026

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
  when you use Watchtower. Only the first 5 characters of the password's
  SHA-1 hash are sent (k-anonymity); the password itself never leaves your
  device.

Keyless has no ads, no analytics or tracking, and never sells or shares your
data.

## Deleting your data

You can delete your account in the app (Settings > Account). The account and
everything stored with it are permanently deleted after 7 days, a window in
which you can cancel by signing in again. Items you delete are kept, still
encrypted, for 30 days in Recently Deleted.

## Contact

Questions about this policy: diego.castroalves1@gmail.com.
