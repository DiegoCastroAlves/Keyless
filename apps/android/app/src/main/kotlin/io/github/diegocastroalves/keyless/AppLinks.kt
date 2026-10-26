package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import org.json.JSONArray
import org.json.JSONObject
import java.text.Collator
import kotlin.concurrent.thread

/**
 * Android apps linked to a login, kept among its addresses as
 * "android://<package>": the client matches those against the app asking
 * (crates/keyless-client/src/matching.rs). A login saved for a website only
 * (an import, the computer) has none, so its app finds nothing until the
 * user links it: in the editor, or by picking the login for the app from
 * autofill or Credential Manager. Apps whose name or package fits the
 * login's website or title are suggested first, and the other way round.
 */
object AppLinks {
    class App(val packageName: String, val label: String)

    /** The app an address names (android://<package>, androidapp://<package>, Chrome's android://<hash>@<package>), or null. */
    fun packageOf(href: String): String? {
        val text = href.trim()
        for (scheme in listOf("android://", "androidapp://")) {
            if (!text.regionMatches(0, scheme, 0, scheme.length, ignoreCase = true)) continue
            val name = text.substring(scheme.length).substringAfterLast('@').split('/', '?', '#').first()
            return name.ifEmpty { null }
        }
        return null
    }

    fun href(packageName: String) = "android://$packageName"

    /** The packages of the apps among `urls`. */
    fun linked(urls: JSONArray?): List<String> =
        if (urls == null) emptyList() else (0 until urls.length()).mapNotNull { packageOf(urls.optJSONObject(it)?.optString("href") ?: "") }

    /** An app's name as kept with its address by the phone that linked it: for an app not installed here. */
    fun savedName(urls: JSONArray?, packageName: String): String? =
        if (urls == null) null else (0 until urls.length()).mapNotNull { urls.optJSONObject(it) }
            .firstOrNull { packageOf(it.optString("href")).equals(packageName, ignoreCase = true) }
            ?.optString("label")?.ifBlank { null }

    /** The first website among an item's addresses (not an app), for its icon. */
    fun firstWebsite(urls: JSONArray?): String? =
        if (urls == null) null else (0 until urls.length()).map { urls.optJSONObject(it)?.optString("href") ?: "" }.firstOrNull { it.isNotBlank() && packageOf(it) == null }

    /** The apps on the phone with a launcher icon, Keyless aside, by name. */
    fun installed(context: Context): List<App> {
        val pm = context.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val collator = Collator.getInstance()
        return pm.queryIntentActivities(launcher, 0)
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != context.packageName }
            .map { App(it, label(context, it) ?: it) }
            .sortedWith { a, b -> collator.compare(a.label, b.label) }
    }

    fun label(context: Context, packageName: String): String? = try {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
    } catch (e: Exception) {
        null
    }

    fun icon(context: Context, packageName: String): Drawable? = try {
        context.packageManager.getApplicationIcon(packageName)
    } catch (e: Exception) {
        null
    }

    /** Words too common to tell an app or a site: "com", "android", "www"… */
    private val COMMON = setOf(
        "com", "net", "org", "www", "app", "apps", "android", "mobile", "the", "and", "for", "with", "inc", "ltd", "llc",
        "login", "signin", "account", "accounts", "conta", "contas", "cuenta", "auth", "secure", "sso", "client", "beta", "lite", "official",
    )

    /** What names a site, an app or a login: "instagram" for instagram.com, com.instagram.android or "Instagram". */
    fun words(vararg texts: String?): Set<String> =
        texts.filterNotNull()
            .flatMap { it.lowercase().split(Regex("[^\\p{L}\\p{N}]+")) }
            .filter { it.length >= 3 && it !in COMMON }
            .toSet()

    /** A login's words: its title and its websites' hosts. */
    fun loginWords(title: String, urls: JSONArray?): Set<String> {
        val hosts = if (urls == null) emptyList() else (0 until urls.length()).mapNotNull { i ->
            urls.optJSONObject(i)?.optString("href")?.takeIf { it.isNotBlank() && packageOf(it) == null }?.let { hostOf(it) }
        }
        return words(title, *hosts.toTypedArray())
    }

    /** An app's words: its name and its package. */
    fun appWords(app: App): Set<String> = words(app.label, app.packageName)

    /**
     * Adds the app (or the website) to a login's addresses, unless it has it
     * already; an app with its name (`label`), for the other devices, which
     * cannot look it up. Uploads: call off the main thread.
     */
    fun link(itemId: String, packageName: String?, domain: String?, label: String? = null) {
        val draft = Keyless.draftOf(itemId)
        val urls = draft.optJSONArray("urls") ?: JSONArray().also { draft.put("urls", it) }
        val hrefs = (0 until urls.length()).map { urls.optJSONObject(it)?.optString("href") ?: "" }
        val href = when {
            packageName != null -> if (hrefs.any { packageOf(it).equals(packageName, ignoreCase = true) }) return else href(packageName)
            domain != null -> if (hrefs.any { packageOf(it) == null && hostOf(it).equals(domain.removePrefix("www."), ignoreCase = true) }) return else "https://$domain"
            else -> return
        }
        urls.put(JSONObject().put("href", href).apply { if (packageName != null && !label.isNullOrBlank()) put("label", label) })
        Keyless.saveDraft(draft)
    }
}

private fun EditText.onText(block: (String) -> Unit) {
    addTextChangedListener(object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: Editable?) = block(s?.toString() ?: "")
    })
}

/** An app's icon, `size` dp (Android's default icon when it is not installed). */
internal fun Context.appIcon(packageName: String, size: Int = 40): ImageView = ImageView(this).apply {
    setImageDrawable(AppLinks.icon(this@appIcon, packageName) ?: packageManager.defaultActivityIcon)
    scaleType = ImageView.ScaleType.FIT_CENTER
    layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
}

/** At most this many rows in a list to choose from; the search narrows it. */
private const val PICK_ROWS = 80

/**
 * Asks which installed app to link to a login: those fitting `loginWords`
 * first ("Suggested"), then all, with a search. `exclude`: linked already.
 */
internal fun Context.pickApp(loginWords: Set<String>, exclude: Set<String>, onPick: (AppLinks.App) -> Unit) {
    val search = searchField(getString(R.string.search_apps))
    val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val scroll = ScrollView(this).apply {
        addView(list)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (resources.displayMetrics.heightPixels * 0.55f).toInt())
    }
    val content = column(16).apply {
        add(search)
        add(scroll, top = 8)
    }
    val dialog = AlertDialog.Builder(this)
        .setTitle(R.string.link_app)
        .setView(content)
        .setNegativeButton(R.string.cancel, null)
        .create()
    list.add(label(getString(R.string.loading), 14f, muted = true))
    dialog.show()

    thread {
        val apps = AppLinks.installed(this).filter { it.packageName !in exclude }
        val fits = apps.associateWith { app -> AppLinks.appWords(app).count { it in loginWords } }
        val suggested = apps.filter { fits.getValue(it) > 0 }.sortedByDescending { fits.getValue(it) }
        val show = { query: String ->
            val words = searchWords(query)
            list.removeAllViews()
            fun rows(title: String, of: List<AppLinks.App>) {
                val found = of.filter { hasWords(words, listOf(it.label, it.packageName)) }.take(PICK_ROWS)
                if (found.isEmpty()) return
                list.add(sectionTitle(title), top = if (list.childCount == 0) 0 else 12)
                for (app in found) {
                    list.add(listRow(appIcon(app.packageName), app.label, app.packageName).apply {
                        setOnClickListener {
                            dialog.dismiss()
                            onPick(app)
                        }
                    })
                }
            }
            if (suggested.isNotEmpty()) rows(getString(R.string.suggested), suggested)
            rows(getString(R.string.all_apps), apps)
            if (list.childCount == 0) list.add(label(getString(R.string.no_results), 14f, muted = true))
        }
        (this as? Activity)?.runOnUiThread {
            show("")
            search.onText { show(it) }
        }
    }
}

/**
 * Choosing a login for an app (or a site) that has none of its own: a
 * search over the logins, those fitting the app first, and a switch to
 * link the app to the chosen login so it shows by itself next time.
 */
internal fun Activity.loginPicker(packageName: String?, domain: String?, onPick: (Summary, Boolean) -> Unit, onCancel: () -> Unit): View {
    val appName = packageName?.let { AppLinks.label(this, it) ?: it }
    val target = appName ?: domain ?: ""
    val targetWords = if (packageName != null) AppLinks.words(appName, packageName) else AppLinks.words(domain?.let { hostOf(it) })
    val logins = Keyless.items.filter { it.category == "login" }
    val fits = logins.associateWith { login -> AppLinks.loginWords(login.title, login.overview.optJSONArray("urls")).count { it in targetWords } }
    val suggested = logins.filter { fits.getValue(it) > 0 }.sortedByDescending { fits.getValue(it) }
    val collator = Collator.getInstance()
    val all = logins.sortedWith { a, b -> collator.compare(a.title, b.title) }

    val page = column(20)
    page.add(brandHeader(getString(R.string.pick_login_title), if (target.isEmpty()) null else getString(R.string.pick_login_for, target)))
    val link = Switch(this).apply {
        text = if (packageName != null) getString(R.string.link_app_to_login, target) else getString(R.string.link_site_to_login, target)
        isChecked = true
        visibility = if (target.isEmpty()) View.GONE else View.VISIBLE
    }
    page.add(link, top = 12)
    val search = searchField(getString(R.string.search_logins))
    page.add(search, top = 12)
    val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(list, top = 8)
    page.add(plainButton(getString(R.string.cancel)) { onCancel() }, top = 12)

    val show = { query: String ->
        val words = searchWords(query)
        list.removeAllViews()
        fun rows(title: String, of: List<Summary>) {
            val found = of.filter { login ->
                val urls = login.overview.optJSONArray("urls")
                val hrefs = if (urls == null) emptyList() else (0 until urls.length()).map { urls.optJSONObject(it)?.optString("href") ?: "" }
                hasWords(words, listOf(login.title, login.subtitle) + hrefs)
            }.take(PICK_ROWS)
            if (found.isEmpty()) return
            list.add(sectionTitle(title), top = if (list.childCount == 0) 0 else 12)
            for (login in found) {
                val icon = loginIcon(login.category, login.title, login.overview.optJSONArray("urls"), login.iconUrl)
                list.add(listRow(icon, login.title, login.subtitle).apply {
                    setOnClickListener { onPick(login, link.isChecked && link.visibility == View.VISIBLE) }
                })
            }
        }
        if (suggested.isNotEmpty()) rows(getString(R.string.suggested), suggested)
        rows(getString(R.string.all_logins), all)
        if (list.childCount == 0) list.add(label(getString(R.string.no_results), 14f, muted = true))
    }
    show("")
    search.onText { show(it) }
    return ScrollView(this).apply { addView(page) }
}
