package io.github.diegocastroalves.keyless

import java.text.Normalizer

/*
 * Searching as people type: without minding case, accents or how a
 * character was written ("mae" finds "Mãe", "acao" finds "Ação", "strasse"
 * finds "Straße"). The same rule as keyless-core's `search::fold`, the
 * desktop's and the extension's (search.ts) and iOS's: change them together.
 */

private val MARKS = Regex("\\p{M}+")

/** Letters that do not decompose, spelled out; curly quotes and dashes as their plain forms. */
private val SPELLED = mapOf(
    'ß' to "ss", 'ẞ' to "ss", 'æ' to "ae", 'Æ' to "ae", 'œ' to "oe", 'Œ' to "oe", 'ø' to "o", 'Ø' to "o",
    'ł' to "l", 'Ł' to "l", 'đ' to "d", 'Đ' to "d", 'ı' to "i",
    '‘' to "'", '’' to "'", '‛' to "'", '′' to "'",
    '“' to "\"", '”' to "\"", '‟' to "\"", '″' to "\"",
)

/** `text` folded for searching: lowercase, without accents, special letters spelled out. */
fun fold(text: String): String {
    val bare = MARKS.replace(Normalizer.normalize(text, Normalizer.Form.NFKD), "")
    val out = StringBuilder(bare.length)
    for (c in bare) {
        when {
            c in SPELLED -> out.append(SPELLED.getValue(c))
            c in '‐'..'―' || c == '−' -> out.append('-')
            else -> out.append(c)
        }
    }
    return out.toString().lowercase()
}

/** The words typed in a search, folded. */
fun searchWords(query: String): List<String> = fold(query).split(Regex("\\s+")).filter { it.isNotEmpty() }

/** Whether every word is somewhere in `texts` (folded). */
fun hasWords(words: List<String>, texts: List<String>): Boolean {
    val text = fold(texts.joinToString(" "))
    return words.all { text.contains(it) }
}
