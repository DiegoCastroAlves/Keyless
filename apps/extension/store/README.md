# Publishing the browser extension

Everything for the stores is ready here; publishing needs the developer
accounts (Chrome Web Store, Microsoft Partner Center for Edge, and
addons.mozilla.org).

## 1. Build the packages

```sh
cd apps/extension
pnpm install --frozen-lockfile
pnpm package
```

This writes, in `dist/`:

- `keyless-chrome-<version>.zip`: Chrome Web Store and Edge Add-ons (without
  the manifest's `key`, which the stores refuse);
- `keyless-firefox-<version>.zip`: addons.mozilla.org;
- `keyless-source-<version>.zip`: the source Mozilla asks for (the files git
  tracks in this folder, built as described in `listing.md`).

The version comes from `package.json`; raise it before each new upload.

## 2. Chrome Web Store

1. Developer Dashboard → New item → upload `keyless-chrome-<version>.zip`.
2. Store listing: the texts in `listing.md` (add the Portuguese and Spanish
   ones as localized listings), the category, and the images in `images/`.
3. Privacy practices: the single purpose, the permission justifications and
   the data use answers in `listing.md`; privacy policy
   `https://keyless.diegoalves.dev/privacy/`.
4. Submit for review.

## 3. Tell the app the store's extension id

The store gives the extension an id of its own (shown in the dashboard).
The app only lets known extensions connect: add the id to
`CHROME_EXTENSION_IDS` in `apps/desktop/src-tauri/src/bridge/mod.rs`, next to
the one of the builds loaded by hand, and release the app. The Chrome Web
Store's id, `hcmaplniiophbidhkclpbicbpleonhja`, is there (added after
0.1.10). Same for Edge, which gives yet another id. Until users have that app version, the extension
from the store cannot connect (the popup says the app is missing).

## 4. Edge Add-ons

Partner Center → Edge → New extension → upload the same Chrome package; the
same texts, images and privacy answers. Then step 3 with Edge's id.

## 5. Firefox (addons.mozilla.org)

1. Developer Hub → Submit a new add-on → "On this site" → upload
   `keyless-firefox-<version>.zip`. The id is fixed by the manifest
   (`keyless@diegocastroalves.github.io`), so the app already knows it.
2. "Do you need to submit source code?" → Yes → upload
   `keyless-source-<version>.zip`, with the build notes from `listing.md`.
3. Listing: the texts, category and screenshots from `listing.md`; privacy
   policy URL as above. The manifest already declares that no data is
   collected (`data_collection_permissions`).

## Before each release

- `pnpm test` and `pnpm test:firefox` pass.
- The screenshots still match the extension (`images/`; they were taken
  in Chromium at 1280×944 and cut to the page area).
- The privacy policy still describes the extension (`docs/PRIVACY.md`, with
  `PRIVACY.pt-BR.md` and `PRIVACY.es.md`; the site's `/privacy/` page is
  built from them).
