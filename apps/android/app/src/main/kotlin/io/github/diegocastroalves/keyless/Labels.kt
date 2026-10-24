package io.github.diegocastroalves.keyless

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Field, field kind and category names in the phone's language, and the
 * templates new items start from (from the desktop app, assets/labels.json).
 */
object Labels {
    private var all: JSONObject? = null
    private var names: JSONObject? = null

    private fun all(context: Context): JSONObject =
        all ?: JSONObject(context.assets.open("labels.json").bufferedReader().use { it.readText() }).also { all = it }

    private fun names(context: Context): JSONObject {
        names?.let { return it }
        val locale = Locale.getDefault()
        val lang = when {
            locale.language == "pt" -> "pt-BR"
            locale.language == "es" -> "es"
            else -> "en"
        }
        return all(context).getJSONObject(lang).also { names = it }
    }

    fun field(context: Context, label: String): String = names(context).optJSONObject("fieldLabels")?.optString(label, label)?.ifEmpty { label } ?: label

    fun fieldKind(context: Context, kind: String): String = names(context).optJSONObject("fieldKinds")?.optString(kind, kind)?.ifEmpty { kind } ?: kind

    fun category(context: Context, category: String): String =
        names(context).optJSONObject("categories")?.optString(category, category)?.ifEmpty { category } ?: category

    fun categoryPlural(context: Context, category: String): String =
        names(context).optJSONObject("categoriesPlural")?.optString(category, "")?.ifEmpty { category(context, category) } ?: category

    /**
     * A desktop text by its path ("sentinel.weak"), with `{{name}}` filled
     * from `vars` and, given a `count`, its plural form (`_one`, `_other`,
     * and `_zero` where the text has one, as i18next does).
     */
    fun t(context: Context, path: String, vars: Map<String, Any> = emptyMap()): String {
        var node: Any? = names(context)
        val count = (vars["count"] as? Number)?.toLong()
        val parts = path.split(".")
        for ((i, part) in parts.withIndex()) {
            val obj = node as? JSONObject ?: return path
            node = if (i == parts.lastIndex && count != null && !obj.has(part)) {
                (if (count == 0L) obj.opt("${part}_zero") else null)
                    ?: obj.opt(if (count == 1L) "${part}_one" else "${part}_other") ?: obj.opt("${part}_other")
            } else {
                obj.opt(part)
            }
        }
        var text = node as? String ?: return path
        for ((name, value) in vars) text = text.replace("{{$name}}", value.toString())
        return text
    }

    /** The categories a new item can have, as the desktop lists them. */
    fun templates(context: Context): List<JSONObject> {
        val list = all(context).optJSONArray("templates") ?: JSONArray()
        return (0 until list.length()).map { list.getJSONObject(it) }.filter { !it.optBoolean("hidden") }
    }

    fun template(context: Context, category: String): JSONObject? =
        all(context).optJSONArray("templates")?.let { list -> (0 until list.length()).map { list.getJSONObject(it) }.firstOrNull { it.optString("id") == category } }

    /** A new item's fields for `category`, labelled in the phone's language (as the desktop does). */
    fun templateFields(context: Context, category: String): JSONArray {
        val fields = JSONArray()
        val template = template(context, category) ?: return fields
        val list = template.optJSONArray("fields") ?: return fields
        for (i in 0 until list.length()) {
            val f = list.getJSONObject(i)
            fields.put(
                JSONObject().put("id", "").put("label", field(context, f.getString("label"))).put("kind", f.getString("kind")).put("value", "")
                    .apply { if (!f.isNull("purpose")) put("purpose", f.getString("purpose")) },
            )
        }
        return fields
    }

    /** Field kinds in the editor's "Add field" menu, as the desktop's. */
    val FIELD_KINDS = listOf("text", "concealed", "email", "url", "phone", "totp", "date", "month_year", "card_number", "pin", "multiline")

    /** The usual name of a field of each kind, kept in English as the templates' (and shown translated). */
    private val USUAL_LABELS = mapOf(
        "concealed" to "password", "email" to "email", "url" to "URL", "phone" to "phone", "totp" to "one-time password", "date" to "date",
        "card_number" to "number", "pin" to "PIN", "address" to "address", "location" to "location", "file" to "document",
    )

    /**
     * The label a new field of `kind` starts with, as the desktop's: its
     * usual name, or the kind's. None for a security question, whose label
     * is the question.
     */
    fun defaultFieldLabel(context: Context, kind: String): String =
        if (kind == "security_question") "" else USUAL_LABELS[kind] ?: fieldKind(context, kind).lowercase(Locale.getDefault())
}

/** A desktop text in the phone's language (see `Labels.t`). */
internal fun Context.t(path: String, vars: Map<String, Any> = emptyMap()): String = Labels.t(this, path, vars)
