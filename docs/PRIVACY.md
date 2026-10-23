# Keyless privacy policy

Last updated: October 23, 2026

Keyless is a zero-knowledge password manager. Everything you store in your
vaults is encrypted on your device before it is sent anywhere, with keys that
are derived from your master password and your Secret Key. Neither of them
ever leaves your devices, so nobody else, including whoever runs the Keyless
server, can read your vaults.

## What the server stores

- Your email address, used to identify your account, and the app's language
  when you created it, used only to write the account emails in it.
- Your encrypted vault data (ciphertext), your public key and your encrypted
  keys, and the settings that follow your account to your other devices (how
  suggested passwords are made), encrypted the same way.
- Technical metadata needed to sync: how many vaults and items you have,
  approximate item sizes, and when they change.
- Connection logs kept by our hosting provider (IP address, time, request
  type) for security and operations.
- For each device signed in to your account: the IP address and country of
  its last connection and when it was last used, so you can see where your
  account is open and sign a device out. The device's name and system are
  encrypted like your vaults.
- For each passkey you add to sign in: its credential ID, when it was added
  and last used, and its name and an encrypted copy of what signing in needs
  (readable only with the passkey).

## Accounts created with Google

Keyless no longer offers signing in with Google. Accounts created with it
before keep the verified email address, name and profile picture Google sent
then, stored with the account and used only to identify it, until the account
is deleted. Keyless never had access to any other Google data or service.

## Links shared with specific emails

When someone shares an item only with some email addresses, the server keeps
a hash (SHA-256) of each address, not the address itself. To open such a
link, you enter your email and receive a one-time code. For that, the server
keeps your email address and the language of the page you used, and deletes
them 30 days after your last code. This gives no access to anything other
than the items shared with that address.

## The browser extension

- The extension talks only to the Keyless app on the same computer (the
  browser's native messaging), over a channel encrypted with keys set up when
  you pair them. Logins, cards and other details reach a page only when you
  fill them, or when a setting you turned on fills them.
- It reads the pages you visit to find sign-in, payment and address forms and
  to offer Keyless there. What it finds stays in your browser and the app.
- Text you copy on a page that looks like an API key goes to the app on your
  computer, which checks its shape to offer saving it.
- When you choose to change a breached password, it opens the website's
  `/.well-known/change-password` address.
- It has no analytics and no remote code. What you save through it goes to
  the app, which syncs it end-to-end encrypted with the rest of your vault.

## Third parties

- **Supabase** hosts the Keyless server (authentication and database).
- **Resend** delivers the account emails (confirmations and one-time codes):
  it receives the address and the email's text.
- **Have I Been Pwned** checks whether a password appears in known breaches
  for Sentinel: once a day and when you save a new password (you can turn
  this off in Sentinel), or when you ask. Only the first 5 characters of the
  password's SHA-1 hash are sent (k-anonymity); the password itself never
  leaves your device.
- **Have I Been Pwned** and **2fa.directory** publish the lists of breached
  websites, and of websites with two-factor codes or passkeys, that Sentinel
  downloads whole once a day and keeps on your device to compare there.
  Nothing about your items is sent to them; like any download, they see the
  request's IP address. Each list can be turned off in Sentinel: it is then
  not downloaded, and the copy on your device is deleted.
- **The websites of your logins** give their own icons: the desktop and
  Android apps download each login's website icon from that website
  (never through a service that would learn which sites you have), keep it
  encrypted on the device, and ask again once a month. The website sees the
  request's IP address, as when you visit it. Turn this off in the app's
  settings ("Show website icons"); the icons kept are then deleted.

Keyless has no ads, no analytics or tracking, and never sells or shares your
data.

## Deleting your data

You can delete your account in the app (Settings > Account). The account and
everything stored with it are permanently deleted after 7 days, a window in
which you can cancel by signing in again. Items you delete are kept, still
encrypted, for 30 days in Recently Deleted.

## Contact

Questions about this policy: diego.castroalves1@gmail.com.
