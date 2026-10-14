package io.github.diegocastroalves.keyless

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** The sign-in fields of a screen, and where it comes from (an app, or a website in a browser). */
class ParsedFields(val packageName: String) {
    val usernames = ArrayList<AutofillId>()
    val passwords = ArrayList<AutofillId>()
    var webDomain: String? = null
    val all: List<AutofillId> get() = usernames + passwords
}

/**
 * Finds username and password fields: by the hints apps give, the HTML of
 * web pages, the input type, and the field's id or hint as a last resort.
 * Without a username field, the text field right before the first password
 * is taken.
 */
object AutofillParser {
    private enum class Kind { USERNAME, PASSWORD, TEXT, NONE }

    private val passwordWords = listOf("password", "passwd", "pass", "senha", "contrase", "pwd", "pin")
    private val usernameWords = listOf("user", "email", "e-mail", "login", "usuario", "usuário", "correo", "account", "conta", "cpf")

    fun parse(structure: AssistStructure): ParsedFields {
        val parsed = ParsedFields(structure.activityComponent?.packageName ?: "")
        val order = ArrayList<Pair<AutofillId, Kind>>()
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode, parsed, order)
        for ((id, kind) in order) {
            when (kind) {
                Kind.USERNAME -> parsed.usernames.add(id)
                Kind.PASSWORD -> parsed.passwords.add(id)
                else -> {}
            }
        }
        if (parsed.usernames.isEmpty() && parsed.passwords.isNotEmpty()) {
            val first = order.indexOfFirst { it.second == Kind.PASSWORD }
            order.subList(0, first).lastOrNull { it.second == Kind.TEXT }?.let { parsed.usernames.add(it.first) }
        }
        return parsed
    }

    /** What the fields hold (for saving what was typed). */
    fun values(structure: AssistStructure): Map<AutofillId, String> {
        val out = HashMap<AutofillId, String>()
        fun walk(node: AssistStructure.ViewNode) {
            val id = node.autofillId
            val value = node.autofillValue
            if (id != null && value != null && value.isText) out[id] = value.textValue.toString()
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)
        return out
    }

    private fun visit(node: AssistStructure.ViewNode, parsed: ParsedFields, order: MutableList<Pair<AutofillId, Kind>>) {
        val domain = node.webDomain
        if (parsed.webDomain == null && !domain.isNullOrBlank()) parsed.webDomain = domain
        val id = node.autofillId
        if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.visibility == View.VISIBLE) {
            val kind = kind(node)
            if (kind != Kind.NONE) order.add(id to kind)
        }
        for (i in 0 until node.childCount) visit(node.getChildAt(i), parsed, order)
    }

    private fun kind(node: AssistStructure.ViewNode): Kind {
        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        if (hints.any { it.contains("password") }) return Kind.PASSWORD
        if (hints.any { it.contains("username") || it.contains("email") }) return Kind.USERNAME
        val html = node.htmlInfo
        if (html != null) {
            if (!html.tag.equals("input", ignoreCase = true)) return Kind.NONE
            val attributes = html.attributes?.associate { it.first.lowercase() to (it.second ?: "").lowercase() } ?: emptyMap()
            val type = attributes["type"] ?: "text"
            val autocomplete = attributes["autocomplete"] ?: ""
            return when {
                type == "password" -> Kind.PASSWORD
                type == "email" || autocomplete.contains("username") || autocomplete.contains("email") -> Kind.USERNAME
                type == "hidden" || type == "submit" || type == "button" || type == "checkbox" || type == "radio" -> Kind.NONE
                else -> byWords(listOf(attributes["name"], attributes["id"], node.hint).joinToString(" ").lowercase()) ?: Kind.TEXT
            }
        }
        val type = node.inputType
        val variation = type and InputType.TYPE_MASK_VARIATION
        when (type and InputType.TYPE_MASK_CLASS) {
            InputType.TYPE_CLASS_TEXT -> {
                if (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) return Kind.PASSWORD
                if (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) return Kind.USERNAME
            }
            InputType.TYPE_CLASS_NUMBER -> if (variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) return Kind.PASSWORD
            else -> if (type != 0) return Kind.NONE
        }
        if (node.className?.contains("EditText") != true && type == 0) return Kind.NONE
        return byWords(listOf(node.idEntry, node.hint).joinToString(" ").lowercase()) ?: Kind.TEXT
    }

    private fun byWords(text: String): Kind? = when {
        passwordWords.any { text.contains(it) } -> Kind.PASSWORD
        usernameWords.any { text.contains(it) } -> Kind.USERNAME
        else -> null
    }
}
