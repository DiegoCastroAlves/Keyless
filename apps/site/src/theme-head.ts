// /theme.js: a classic script in each page's <head>, after the color
// metas. It sets the theme chosen on this browser before the first paint,
// so that a page never flashes in the other one (a module would run only
// after the page is parsed).

import { applyTheme, storedTheme } from "./theme";

applyTheme(storedTheme());
