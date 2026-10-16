import Foundation

/// Searching as people type: without minding case, accents or how a
/// character was written ("mae" finds "Mãe", "acao" finds "Ação", "strasse"
/// finds "Straße"). The same rule as keyless-core's `search::fold`, the
/// desktop's and the extension's (search.ts) and Android's (Search.kt):
/// change them together.
enum Search {
    /// Letters that do not decompose, spelled out; curly quotes as their plain forms.
    private static let spelled: [Character: String] = [
        "ß": "ss", "ẞ": "ss", "æ": "ae", "Æ": "ae", "œ": "oe", "Œ": "oe", "ø": "o", "Ø": "o",
        "ł": "l", "Ł": "l", "đ": "d", "Đ": "d", "ı": "i",
        "\u{2018}": "'", "\u{2019}": "'", "\u{201B}": "'", "\u{2032}": "'",
        "\u{201C}": "\"", "\u{201D}": "\"", "\u{201F}": "\"", "\u{2033}": "\"",
    ]

    /// `text` folded for searching: lowercase, without accents, special letters spelled out.
    static func fold(_ text: String) -> String {
        var out = ""
        for scalar in text.decomposedStringWithCompatibilityMapping.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .nonspacingMark, .spacingMark, .enclosingMark:
                continue
            default:
                break
            }
            if let spelledOut = spelled[Character(scalar)] {
                out += spelledOut
            } else if (0x2010...0x2015).contains(scalar.value) || scalar.value == 0x2212 {
                out += "-"
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out.lowercased()
    }

    /// The words typed in a search, folded.
    static func words(_ query: String) -> [String] {
        fold(query).split(whereSeparator: { $0.isWhitespace }).map(String.init)
    }

    /// Whether every word is somewhere in `texts` (folded).
    static func has(_ words: [String], in texts: [String]) -> Bool {
        let text = fold(texts.joined(separator: " "))
        return words.allSatisfy { text.contains($0) }
    }
}
