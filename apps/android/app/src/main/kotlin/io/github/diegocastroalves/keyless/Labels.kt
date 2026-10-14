package io.github.diegocastroalves.keyless

import android.content.Context
import org.json.JSONObject
import java.util.Locale

/** Field and category names in the phone's language (from the desktop app's translations, assets/labels.json). */
object Labels {
    private var names: JSONObject? = null

    private fun names(context: Context): JSONObject {
        names?.let { return it }
        val all = JSONObject(context.assets.open("labels.json").bufferedReader().use { it.readText() })
        val locale = Locale.getDefault()
        val lang = when {
            locale.language == "pt" -> "pt-BR"
            locale.language == "es" -> "es"
            else -> "en"
        }
        return all.getJSONObject(lang).also { names = it }
    }

    fun field(context: Context, label: String): String = names(context).optJSONObject("fieldLabels")?.optString(label, label)?.ifEmpty { label } ?: label

    fun category(context: Context, category: String): String =
        names(context).optJSONObject("categories")?.optString(category, category)?.ifEmpty { category } ?: category

    fun categoryPlural(context: Context, category: String): String =
        names(context).optJSONObject("categoriesPlural")?.optString(category, "")?.ifEmpty { category(context, category) } ?: category
}
