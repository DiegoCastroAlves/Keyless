package io.github.diegocastroalves.keyless

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import org.json.JSONArray
import org.json.JSONObject

/** A field a card or an identity may fill, described for the client (see crates/keyless-client/src/autofill.rs). */
class FormField(val id: AutofillId, val json: JSONObject)

/** The sign-in fields of a screen, its card and address fields, and where it comes from (an app, or a website in a browser). */
class ParsedFields(val packageName: String) {
    val usernames = ArrayList<AutofillId>()
    val passwords = ArrayList<AutofillId>()

    /** Those of a sign-up or change-password form that take the new password (and its confirmation). */
    val newPasswords = ArrayList<AutofillId>()

    /** The most characters the fields a suggested password goes in take (0: no limit). */
    var passwordMaxLength = 0

    /** Whether those fields take digits only (a PIN). */
    var passwordDigits = false
    var webDomain: String? = null
    var webScheme: String? = null

    /** Every field a card or an identity could fill, and what each asks for ("cardNumber", "city"... or null). */
    val formFields = ArrayList<FormField>()
    var parts: List<String?> = emptyList()
    var cards = false
    var identities = false

    /** Card and address fields of the form. */
    val formIds: List<AutofillId> get() = formFields.filterIndexed { i, _ -> parts.getOrNull(i) != null }.map { it.id }
    val all: List<AutofillId> get() = (usernames + passwords + formIds).distinct()
    val logins: Boolean get() = usernames.isNotEmpty() || passwords.isNotEmpty()

    /** A form for a new password: its suggestion comes first. */
    val signUp: Boolean get() = newPasswords.isNotEmpty()

    /** Where a suggested password goes: the new password's fields, or the only one there is. */
    val suggestionFields: List<AutofillId> get() = newPasswords.ifEmpty { passwords }

    /** A change-password form: the current password, then the new one. */
    val changesPassword: Boolean get() = newPasswords.isNotEmpty() && newPasswords.size < passwords.size

    /** Where a saved login's password goes: the current password's field on a change-password form. */
    val loginPasswords: List<AutofillId> get() = if (changesPassword) passwords - newPasswords.toSet() else passwords
    val anything: Boolean get() = logins || formIds.isNotEmpty()

    fun formJson(): JSONObject = JSONObject().put("fields", JSONArray(formFields.map { it.json }))
}

/**
 * Finds username and password fields: by the hints apps give, the HTML of
 * web pages, the input type, and the field's id or hint as a last resort.
 * Without a username field, the text field right before the first password
 * is taken. Card and address fields are recognised by the client; a card's
 * fields are never a login's.
 *
 * A password field is for a new password when it says so (the
 * "newPassword" hint, autocomplete="new-password", words like "confirm" or
 * "nova"), or by the form's shape when none says: two password fields are
 * a password and its confirmation, and of three, the first is the current
 * one.
 */
object AutofillParser {
    private enum class Kind { USERNAME, PASSWORD, TEXT, NONE }

    /** A password field: whether it says it is for a new password (null: it does not say), and what it takes. */
    private class PasswordField(val new: Boolean?, val maxLength: Int, val digits: Boolean)

    private val passwordWords = listOf("password", "passwd", "pass", "senha", "contrase", "pwd", "pin")
    private val usernameWords = listOf("user", "email", "e-mail", "login", "usuario", "usuário", "correo", "account", "conta", "cpf")

    // Whole words of a field's id, name, hint or label (a word starting with
    // one of five letters or more counts: "confirmar", "repetir").
    private val newWords = listOf(
        "new", "nova", "novo", "nueva", "nuevo", "confirm", "repeat", "repet", "again", "retype", "reenter", "verify",
        "create", "crie", "criar", "crear", "cree", "choose", "escolha", "elija", "register", "registr", "signup", "cadastr",
    )
    private val currentWords = listOf("current", "old", "atual", "antiga", "anterior", "actual", "existing")

    fun parse(structure: AssistStructure): ParsedFields {
        val parsed = ParsedFields(structure.activityComponent?.packageName ?: "")
        val order = ArrayList<Pair<AutofillId, Kind>>()
        val passwordFields = HashMap<AutofillId, PasswordField>()
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode, parsed, order, passwordFields, null)
        classifyForms(parsed)
        val cardFields = if (parsed.cards) {
            parsed.formFields.filterIndexed { i, _ -> parsed.parts.getOrNull(i)?.startsWith("card") == true }.map { it.id }.toSet()
        } else {
            emptySet()
        }
        if (cardFields.isNotEmpty()) order.removeAll { it.first in cardFields }
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
        parsed.newPasswords.addAll(newPasswords(parsed.passwords, passwordFields))
        val suggested = parsed.suggestionFields.mapNotNull { passwordFields[it] }
        parsed.passwordMaxLength = suggested.map { it.maxLength }.filter { it > 0 }.minOrNull() ?: 0
        parsed.passwordDigits = suggested.any { it.digits }
        return parsed
    }

    /** The fields of `passwords` (in screen order) that take a new password. */
    private fun newPasswords(passwords: List<AutofillId>, fields: Map<AutofillId, PasswordField>): List<AutofillId> {
        val said = passwords.map { fields[it]?.new }
        return when {
            // Those not marked current.
            said.any { it == false } -> passwords.filterIndexed { i, _ -> said[i] != false }
            // Of three or more, the first unmarked one is the current password.
            passwords.size >= 3 && said[0] == null -> passwords.drop(1)
            said.any { it == true } || passwords.size == 2 -> passwords
            else -> emptyList()
        }
    }

    /** What the form's fields ask for, from the client (no vault needed). */
    private fun classifyForms(parsed: ParsedFields) {
        if (parsed.formFields.isEmpty()) return
        try {
            val answer = Native.obj("autofillFields", parsed.formJson())
            val parts = answer.optJSONArray("parts") ?: JSONArray()
            parsed.parts = (0 until parsed.formFields.size).map { i -> if (parts.isNull(i)) null else parts.optString(i).ifEmpty { null } }
            parsed.cards = answer.optBoolean("cards")
            parsed.identities = answer.optBoolean("identities")
        } catch (e: Exception) {
            parsed.parts = emptyList()
        }
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

    private fun visit(
        node: AssistStructure.ViewNode,
        parsed: ParsedFields,
        order: MutableList<Pair<AutofillId, Kind>>,
        passwordFields: MutableMap<AutofillId, PasswordField>,
        labelBefore: String?,
    ) {
        val domain = node.webDomain
        if (parsed.webDomain == null && !domain.isNullOrBlank()) {
            parsed.webDomain = domain
            parsed.webScheme = node.webScheme
        }
        val id = node.autofillId
        if (id != null && node.visibility == View.VISIBLE) {
            if (node.autofillType == View.AUTOFILL_TYPE_TEXT) {
                val kind = kind(node)
                if (kind != Kind.NONE) order.add(id to kind)
                if (kind == Kind.PASSWORD) passwordFields[id] = passwordField(node, labelBefore)
            }
            if (node.autofillType == View.AUTOFILL_TYPE_TEXT || node.autofillType == View.AUTOFILL_TYPE_LIST || node.autofillType == View.AUTOFILL_TYPE_DATE) {
                parsed.formFields.add(FormField(id, describe(node, labelBefore)))
            }
        }
        // Text shown before a field is often its label.
        var label: String? = null
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i)
            visit(child, parsed, order, passwordFields, label)
            label = labelOf(child)
        }
    }

    private fun labelOf(node: AssistStructure.ViewNode): String? {
        if (node.autofillType != View.AUTOFILL_TYPE_NONE || node.childCount > 0) return null
        val text = node.text?.toString()?.trim()
        return if (text.isNullOrEmpty() || text.length > 60) null else text
    }

    /** A field as the client reads it. */
    private fun describe(node: AssistStructure.ViewNode, labelBefore: String?): JSONObject {
        val json = JSONObject()
        node.autofillHints?.let { json.put("hints", JSONArray(it.toList())) }
        node.htmlInfo?.let { html ->
            json.put("htmlTag", html.tag.lowercase())
            val attributes = JSONObject()
            html.attributes?.forEach { attributes.put(it.first.lowercase(), it.second ?: "") }
            json.put("html", attributes)
        }
        node.idEntry?.let { json.put("idEntry", it) }
        node.hint?.let { json.put("hint", it.toString()) }
        json.put("label", listOfNotNull(labelBefore, node.contentDescription?.toString()).joinToString(" "))
        json.put("inputType", node.inputType)
        json.put(
            "autofillType",
            when (node.autofillType) {
                View.AUTOFILL_TYPE_LIST -> "list"
                View.AUTOFILL_TYPE_DATE -> "date"
                else -> "text"
            },
        )
        node.autofillOptions?.let { options -> json.put("options", JSONArray(options.map { it.toString() })) }
        if (node.maxTextLength > 0) json.put("maxLength", node.maxTextLength)
        return json
    }

    private fun kind(node: AssistStructure.ViewNode): Kind {
        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        if (hints.any { it.contains("password") }) return Kind.PASSWORD
        if (hints.any { it.contains("username") || it.contains("email") }) return Kind.USERNAME
        if (hints.any { it.startsWith("creditcard") || it.startsWith("cc-") || it.startsWith("postal") || it.startsWith("phone") || it.startsWith("person") || it.startsWith("address") }) {
            return Kind.NONE
        }
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

    private fun passwordField(node: AssistStructure.ViewNode, labelBefore: String?): PasswordField {
        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        // As written: their case splits words ("newPassword").
        val raw = node.htmlInfo?.attributes?.associate { it.first.lowercase() to (it.second ?: "") } ?: emptyMap()
        val attributes = raw.mapValues { it.value.lowercase() }
        val autocomplete = attributes["autocomplete"] ?: ""
        val words = words(listOfNotNull(node.idEntry, node.hint?.toString(), raw["name"], raw["id"], raw["placeholder"], labelBefore, node.contentDescription?.toString()))
        val new = when {
            hints.any { it.contains("newpassword") || it.contains("new-password") } || autocomplete.contains("new-password") -> true
            autocomplete.contains("current-password") -> false
            words.any { word -> currentWords.any { matches(word, it) } } -> false
            words.any { word -> newWords.any { matches(word, it) } } -> true
            else -> null
        }
        val maxLength = maxOf(node.maxTextLength, attributes["maxlength"]?.toIntOrNull() ?: 0)
        val digits = node.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_NUMBER ||
            attributes["inputmode"] == "numeric" || attributes["pattern"].let { it == "[0-9]*" || it == "\\d*" }
        return PasswordField(new, maxLength, digits)
    }

    /** The words of `texts`, lower case, camelCase and snake_case split ("confirmPassword": confirm, password). */
    private fun words(texts: List<String>): List<String> =
        texts.flatMap { text ->
            text.replace(Regex("([a-z])([A-Z])"), "$1 $2").lowercase().split(Regex("[^\\p{L}\\p{N}]+")).filter { it.isNotEmpty() }
        }

    private fun matches(word: String, known: String): Boolean = word == known || (known.length >= 5 && word.startsWith(known))

    private fun byWords(text: String): Kind? = when {
        passwordWords.any { text.contains(it) } -> Kind.PASSWORD
        usernameWords.any { text.contains(it) } -> Kind.USERNAME
        else -> null
    }
}
