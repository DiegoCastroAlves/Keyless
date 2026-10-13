import { useEffect } from "react";

/** Applies the list density to the document. (The zoom is the window's,
 * set from Rust.) */
export function useDensity(density: string | undefined) {
  useEffect(() => {
    document.documentElement.dataset.density = density === "compact" ? "compact" : "comfortable";
  }, [density]);
}

/** Applies the theme setting ("system", "light" or "dark") to the document. */
export function useTheme(theme: string | undefined) {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const dark = theme === "dark" || ((theme ?? "system") === "system" && media.matches);
      document.documentElement.classList.toggle("dark", dark);
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
}
