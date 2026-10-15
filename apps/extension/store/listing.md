# Store listing

Texts for the Chrome Web Store, Edge Add-ons and addons.mozilla.org. The
name and the short description also live in the extension itself
(`static/_locales/*/messages.json`, `name` and `description`).

## Name

Keyless

## Short description (132 characters at most)

- **en:** Fill passwords from Keyless, the zero-knowledge password manager.
- **pt_BR:** Preencha senhas com o Keyless, o gerenciador de senhas de conhecimento zero.
- **es:** Rellena contraseñas desde Keyless, el gestor de contraseñas de conocimiento cero.

## Description

### en

Keyless fills your logins, passkeys, cards and addresses in the browser,
from the Keyless app on your computer (Windows and Linux).

- Sign in with a click: pick a login in the field, or from the card at the
  top of the page. Two-step sign-ins, one-time codes and "Sign in with
  Google" logins included.
- Passkeys: create and use them from Keyless, on any website.
- Save as you go: Keyless offers to save logins, cards and addresses you
  type, and suggests strong passwords when you create an account.
- Safer filling: it asks before filling on unencrypted pages or on websites a
  login was not saved for, and warns when a password you paste belongs to
  another website.
- Sentinel warnings on the websites whose passwords appeared in breaches.
- The whole vault in the toolbar: every kind of item, notes, files and
  password history.

Everything is encrypted on your computer before it goes anywhere. The
extension talks only to the Keyless app on the same computer, over a channel
encrypted with keys set up when you pair them; it has no analytics and sends
nothing to us.

Needs the Keyless app: https://keyless.diegoalves.dev

### pt_BR

O Keyless preenche seus logins, chaves de acesso, cartões e endereços no
navegador, a partir do app do Keyless no seu computador (Windows e Linux).

- Entre com um clique: escolha um login no campo ou no cartão que aparece no
  topo da página. Inclui login em etapas, códigos de verificação e logins do
  tipo "Entrar com o Google".
- Chaves de acesso: crie e use pelo Keyless, em qualquer site.
- Salve enquanto usa: o Keyless oferece salvar os logins, cartões e endereços
  que você digita, e sugere senhas fortes quando você cria uma conta.
- Preenchimento mais seguro: ele pergunta antes de preencher em páginas sem
  criptografia ou em sites para os quais o login não foi salvo, e avisa quando
  uma senha colada é de outro site.
- Avisos do Sentinela nos sites cujas senhas apareceram em vazamentos.
- O cofre inteiro na barra do navegador: todos os tipos de item, notas,
  anexos e histórico de senhas.

Tudo é criptografado no seu computador antes de sair dele. A extensão
conversa apenas com o app do Keyless no mesmo computador, por um canal
criptografado com chaves combinadas quando você os conecta; ela não tem
análise de uso e não nos envia nada.

Precisa do app do Keyless: https://keyless.diegoalves.dev

### es

Keyless rellena tus inicios de sesión, llaves de acceso, tarjetas y
direcciones en el navegador, desde la app de Keyless en tu ordenador (Windows
y Linux).

- Inicia sesión con un clic: elige un inicio de sesión en el campo o en la
  tarjeta que aparece arriba en la página. Incluye inicios de sesión en
  varios pasos, códigos de verificación e inicios de sesión con Google.
- Llaves de acceso: créalas y úsalas desde Keyless, en cualquier sitio.
- Guarda sobre la marcha: Keyless ofrece guardar los inicios de sesión,
  tarjetas y direcciones que escribes, y sugiere contraseñas seguras al crear
  una cuenta.
- Relleno más seguro: pregunta antes de rellenar en páginas sin cifrado o en
  sitios para los que no se guardó el inicio de sesión, y avisa cuando una
  contraseña que pegas es de otro sitio.
- Avisos de Centinela en los sitios cuyas contraseñas aparecieron en
  filtraciones.
- Toda la bóveda en la barra del navegador: todos los tipos de elemento,
  notas, archivos e historial de contraseñas.

Todo se cifra en tu ordenador antes de salir de él. La extensión solo habla
con la app de Keyless en el mismo ordenador, por un canal cifrado con claves
acordadas al conectarlas; no tiene analítica y no nos envía nada.

Necesita la app de Keyless: https://keyless.diegoalves.dev

## Category

Chrome Web Store: Productivity › Tools. Edge: Productivity. Firefox: Privacy
& Security.

## Images

`store/images/`:

- store icon, 128×128: `store-icon-128.png` (the logo at 96×96 with 16 px of
  transparent padding, as the Chrome Web Store asks; rendered from
  `apps/desktop/assets/logo.svg`);
- screenshots, 1280×800: `1-suggest-password.png`, `2-save-login.png`,
  `3-sign-in-card.png`, `4-fill-menu.png`, `5-popup.png` (a made-up site,
  northwind.example, and a made-up account);
- small promo tile, 440×280: `promo-440x280.png` (from `promo.html`).

## Privacy (Chrome Web Store "Privacy practices")

**Single purpose:** fill and save the user's logins, passkeys, cards and
addresses from the Keyless password manager app on the same computer.

**Permissions:**

| Permission | Why |
| --- | --- |
| `nativeMessaging` | Talks to the Keyless app on the same computer, where the vault is; nothing goes to a server. |
| `tabs` | Knows the page in the active tab, to suggest its logins in the popup and fill the right tab. |
| `storage` | Keeps the extension's settings and its pairing with the app. |
| `contextMenus` | Adds "Show Keyless", "Save this login", "Hide on this site" and "Lock" to the page's menu. |
| `webRequest`, `webRequestAuthProvider` (Firefox: `webRequestBlocking`) | Answers a website's own sign-in window (HTTP authentication) with a login the user picks. |
| `favicon` | Shows the websites' icons, from the browser's cache, next to the logins. |
| host permission `<all_urls>` | Finds and fills the sign-in, payment and address forms on the websites the user visits, and reads a two-factor setup QR code on the visible page when asked. |
| `privacy` (optional) | Only if the user chooses to turn off the browser's own password manager. |

**Remote code:** none.

**Data use:** the extension handles authentication information (logins and
passkeys), personal information (addresses) and financial information
(cards) to fill them, only between the page and the Keyless app on the
user's computer. None of it is sent to the developer or anyone else, sold,
or used for anything else. Privacy policy:
https://keyless.diegoalves.dev/privacy/

## Notes for reviewers

Keyless works with the Keyless desktop app (open source:
https://github.com/DiegoCastroAlves/Keyless), which holds the encrypted
vault; without it, the extension shows how to install it. To try it: install
the app from https://keyless.diegoalves.dev, create an account, click
"Connect" in the extension's popup and approve the code in the app. The
tutorial at https://keyless.diegoalves.dev/tutorial/ has practice forms.

For Mozilla: the published files are built from TypeScript with esbuild
(not minified). The source package (`keyless-source-<version>.zip`) builds
with `pnpm install --frozen-lockfile && pnpm build` (Node 22 or newer, pnpm
from `packageManager` in package.json); the result is `dist/firefox`.
