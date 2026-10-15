# The Android app's look

The phone app has the desktop app's (`apps/desktop`) colors, font, icons and
component shapes, laid out the way phone apps are: tabs at the bottom, a
search and the account at the top, groups of rows on a surface over the
screen, and the main action floating over the content. Nothing here is drawn
from scratch; when the desktop changes its look, change these with it.

## Where each part comes from

| Part | Desktop | Android |
| --- | --- | --- |
| Colors, light and dark | `src/styles.css` (`:root`, `.dark`) | `res/values/colors.xml`, `res/values-night/colors.xml`, same role names (`panel`, `line`, `muted`, `accent`...), plus the phone's layers (`screen`, `nav_bar`, `search_pill`) |
| Font | Inter Variable (`@fontsource-variable/inter`) | `res/font/inter.ttf`: its Latin `wght` file, turned from WOFF2 into TTF with fontTools (`TTFont(woff2).flavor = None`); `res/font/inter_family.xml`, `Context.inter(weight)` |
| Icons | Lucide (`lucide-react`) | `res/drawable/ic_*.xml`, made by `scripts/lucide_icons.py` from the desktop's copy |
| Category icons and tints | `src/lib/categories.ts` | `Look.kt` (`CATEGORY_LOOK`, `itemIcon`) |
| A login's icon, letter and color | `ItemIcon`, `avatarColor` (`src/lib/format.ts`), website icons (`site_icons.rs`) | `itemIcon`, `avatarColor` (the same hash, so an item has the same color on both), `SiteIcons` |
| Website icons | `src-tauri/src/site_icons.rs` | `SiteIcons.kt`; both on `keyless_core::site_icons` (which sites, which links, the keys) |
| Names of the item groups | `sidebar` in `src/i18n` | `Labels.t("sidebar.…")` (copied by `scripts/labels.mjs`) |
| Buttons, fields | `src/components/ui` | `Ui.kt` (`primaryButton`, `secondaryButton`, `plainButton`, `field`) |
| Colored passwords | `PasswordText` | `passwordText` |
| QR codes one Keyless app shows another (signing in, setup codes) | `branded_qr_svg` (`src-tauri/src/items.rs`) | `BrandedQrView`; both draw `keyless_core::qr::art` (other QR codes stay plain: `QrView`) |
| Numbered steps (what to do on the other device) | the sign-in's QR code screen | `numberedStep` |

The theme (`res/values/themes.xml`) only sets these colors and Inter on the
platform's widgets. Settings > General > Theme applies to every screen
through `KeylessActivity`, which every activity extends.

## The structure

- **Tabs** (`Home.kt`): Home, Items and Sentinel, in the bottom bar
  (`bottomBar`). Each tab has the search pill (`searchPill`, it opens the
  search) and the account's letter (`accountButton`, it opens the account's
  menu: sign in on another device, generator, sync, settings, lock).
- **Home**: what still needs setting up on this phone (biometrics, autofill,
  passkeys: `setupSteps`), Sentinel when it has serious alerts, favorites,
  recently used (ids kept on the phone) and recently added. Customize home
  hides any of them.
- **Items**: all items and favorites, then vaults, categories and tags, then
  the archive and recently deleted. Each opens the list (`showList`), with
  Back, its name, the filter and the order.
- **New item** (`Fab`, on Home, Items and the list): the categories as tiles
  (`categoryTile`), the most used first, with a search.
- **Settings** (`SettingsScreens.kt`): a list of groups (account, general,
  security, autofill, import and export, about), each with its own page.
- Sign-in and unlock screens sit on `app_bg`, as the desktop's lock screen;
  everything else on `screen`.

## Shapes

- Screens are `screen` (a light gray, or near black); groups are `panel`
  over it, with 16 dp corners and no line around (`group`, `card`,
  `panel`). An item's fields (`card`) have a hairline between them, from
  their text on.
- Row icons are 40 dp: a website's icon, a letter on its color, a category's
  icon on its tint, or `roundIcon` (an icon on a round tint of its `Hue`)
  for groups and settings.
- Corners: 10 dp for buttons and fields, 16 dp for groups and tiles, the
  search pill and the bottom bar's tab pills fully round; an item's icon a
  quarter of its size.
- Touch sizes: rows of 56 to 64 dp, icon buttons of 44 dp, buttons of 48 dp,
  the floating button 56 dp. Actions the desktop shows on hover (copy, show)
  are always shown.

## Rules

- No color, size or font in a screen's code that a helper already gives:
  use `getColor(R.color.<role>)`, `group()`, `groupRow()`, `heading()`,
  `roundIcon()`, and so on.
- An icon button always has a description (`iconButton(res, description)`):
  screen readers say it, and the end-to-end runs tap it by that name. So do
  the tabs, the account's letter, the floating button and the tiles.
- Add icons to `ICONS` in `scripts/lucide_icons.py` and run it; do not
  draw new ones.
- A plain `View` that wraps its content fills the space left in its
  parent: give dividers their own layout (`addView(divider())`) and use
  `Space` for gaps.
