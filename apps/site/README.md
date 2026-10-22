# Keyless site

The public site at keyless.diegoalves.dev, served by Cloudflare Pages from
this folder:

- build command: `pnpm install --frozen-lockfile && pnpm build`;
- output: `dist`.

It has these pages:

- the home page;
- `/share/`, which opens share links;
- `/tutorial/`, the browser extension's tutorial;
- `/privacy/`, the privacy policy, built from `docs/PRIVACY.md` and its
  translations (`docs/PRIVACY.pt-BR.md`, `docs/PRIVACY.es.md`) by
  `policy.mjs`: change the policy there, in the three languages;
- `/email-changed/`, where the links confirming an email change lead;
- `/email-confirmed/`, what a new account sees once its email is confirmed
  (the confirmation link leads to the home page, which ends the session it
  brings and comes here);
- `/vault/`, the web vault, which is off.

`pnpm build` runs `build.mjs`, which writes `dist/` and its `_headers`
(security headers per page).

Link previews (WhatsApp, Telegram, social networks) show `static/og.png`,
named by the Open Graph tags of the home page, `/share/`, `/tutorial/` and
`/privacy/`. The image is made from `scripts/og-image.html`, which says how
to make it again.

## Web vault (off)

The web vault's code stays here (`src/vault/`, `static/vault/`, and the
WebAssembly client in `vendor/`), but it is not published.

- The build leaves out every file of it, so `/vault/` is a 404.
- The build drops the home page's link to it. Any link to it must carry
  `data-web-vault`, so that the build removes it.
- The server's passkey sign-in is switched off. Passkeys for Keyless are
  made for this site's domain, by the web vault or by the Android app (which
  `static/.well-known/assetlinks.json` lets use them: it names the app's
  release signing key). Turning the switch on (step 2 below) is enough for
  the Android app; the web vault can stay off.

To turn the web vault back on:

1. In Cloudflare Pages, add the environment variable `KEYLESS_WEB_VAULT` with
   the value `on` (Settings → Variables and Secrets) and deploy again.
   Locally: `KEYLESS_WEB_VAULT=on pnpm build`.
2. In Supabase (SQL editor), turn passkey sign-in back on:

   ```sql
   update private.switches set enabled = true where name = 'passkey_sign_in';
   ```

3. Check `https://keyless.diegoalves.dev/vault/` opens. Signing in there
   changes nothing on the server.

The vault's WebAssembly is rebuilt with `scripts/build-wasm.sh` after
`crates/keyless-client` changes.
