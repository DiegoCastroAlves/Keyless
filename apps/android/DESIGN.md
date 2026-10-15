# The Android app's look

The phone app follows the desktop app (`apps/desktop`): the same colors,
font, icons and component shapes, grown for touch. Nothing here is drawn
from scratch; when the desktop changes its look, change these with it.

## Where each part comes from

| Part | Desktop | Android |
| --- | --- | --- |
| Colors, light and dark | `src/styles.css` (`:root`, `.dark`) | `res/values/colors.xml`, `res/values-night/colors.xml`, same role names (`panel`, `line`, `muted`, `accent`...) |
| Font | Inter Variable (`@fontsource-variable/inter`) | `res/font/inter.ttf`: its Latin `wght` file, turned from WOFF2 into TTF with fontTools (`TTFont(woff2).flavor = None`); `res/font/inter_family.xml`, `Context.inter(weight)` |
| Icons | Lucide (`lucide-react`) | `res/drawable/ic_*.xml`, made by `scripts/lucide_icons.py` from the desktop's copy |
| Category icons and tints | `src/lib/categories.ts` | `Look.kt` (`CATEGORY_LOOK`, `itemIcon`) |
| A login's letter and color | `ItemIcon`, `avatarColor` (`src/lib/format.ts`) | `itemIcon`, `avatarColor`: the same hash, so an item has the same color on both |
| Buttons, fields, cards | `src/components/ui` | `Ui.kt` (`primaryButton`, `secondaryButton`, `plainButton`, `field`) and `Look.kt` (`card`, `listRow`, `fieldRow`, `chip`, `searchField`, `topBar`) |
| Colored passwords | `PasswordText` | `passwordText` |

The theme (`res/values/themes.xml`) only sets these colors and Inter on the
platform's widgets. Settings > Theme applies to every screen through
`KeylessActivity`, which every activity extends.

## Shapes

- Corners: 10 dp for buttons and fields, 12 dp for cards, the item icon a
  quarter of its size (the desktop's `rounded-lg`, `rounded-xl`).
- Cards have a hairline (`line`) around and between their rows, like the
  desktop's `divide-y` groups. An item's fields are rows with the name
  (12 sp, `subtle`) over the value.
- Touch sizes: rows of 56 to 64 dp, icon buttons of 44 dp, buttons of
  48 dp. Actions the desktop shows on hover (copy, show) are always shown.
- Screens are `panel` (white or dark gray), as the desktop's panes; the
  sign-in and unlock screens sit on `app_bg`, as its lock screen.

## Rules

- No color, size or font in a screen's code that a helper already gives:
  use `getColor(R.color.<role>)`, `card()`, `sectionTitle()`, and so on.
- An icon button always has a description (`iconButton(res, description)`):
  screen readers say it, and the end-to-end runs tap it by that name.
- Add icons to `ICONS` in `scripts/lucide_icons.py` and run it; do not
  draw new ones.
- A plain `View` that wraps its content fills the space left in its
  parent: give dividers their own layout (`addView(divider())`) and use
  `Space` for gaps.
