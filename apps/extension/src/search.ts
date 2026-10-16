/**
 * Searching as people type: without minding case, accents or how a
 * character was written ("mae" finds "Mãe", "acao" finds "Ação", "strasse"
 * finds "Straße"). The same rule as keyless-core's `search::fold`, the
 * desktop's (lib/search.ts), Android's and iOS's: change them together.
 */

/** Letters that do not decompose, spelled out; curly quotes and dashes as their plain forms. */
const SPELLED: Record<string, string> = {
  ß: "ss",
  ẞ: "ss",
  æ: "ae",
  Æ: "ae",
  œ: "oe",
  Œ: "oe",
  ø: "o",
  Ø: "o",
  ł: "l",
  Ł: "l",
  đ: "d",
  Đ: "d",
  ı: "i",
  "‘": "'",
  "’": "'",
  "‛": "'",
  "′": "'",
  "“": '"',
  "”": '"',
  "‟": '"',
  "″": '"',
};

/** `text` folded for searching: lowercase, without accents, special letters spelled out. */
export function fold(text: string): string {
  return text
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .replace(/[ßẞæÆœŒøØłŁđĐı‘’‛′“”‟″]/g, (c) => SPELLED[c])
    .replace(/[‐-―−]/g, "-")
    .toLowerCase();
}

/** The words typed in a search, folded. */
export function searchWords(query: string): string[] {
  return fold(query).split(/\s+/).filter(Boolean);
}

/** Whether every word is somewhere in `texts` (folded). */
export function hasWords(words: string[], texts: string[]): boolean {
  const text = fold(texts.join(" "));
  return words.every((word) => text.includes(word));
}
