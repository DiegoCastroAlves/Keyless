package io.github.diegocastroalves.keyless

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.autofill.AutofillManager
import android.widget.CheckBox
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject

/*
 * The vault's main screens, as phone apps lay them out: three tabs (Home,
 * Items, Sentinel) under the search and the account's menu, with New item
 * floating over Home and Items.
 */

internal fun MainActivity.tabs(): List<Tab> = listOf(
    Tab("home", R.drawable.ic_home, getString(R.string.tab_home)),
    Tab("items", R.drawable.ic_items, getString(R.string.tab_items)),
    Tab("sentinel", R.drawable.ic_shield, Labels.t(this, "sentinel.title")),
)

internal fun MainActivity.showTab(id: String) {
    when (id) {
        "items" -> showItemsTab()
        "sentinel" -> showSentinel(null)
        else -> showHome()
    }
}

/** A tab: the search and the account at the top, `content` scrolling under them, the tabs at the bottom. */
internal fun MainActivity.tabScreen(id: String, content: LinearLayout, withNewItem: Boolean) {
    tab = id
    listOpen = false
    dropListPage()
    val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val top = row().apply { setPadding(dp(16), dp(10), dp(16), dp(8)) }
    top.add(searchPill(getString(R.string.search_keyless)) { showSearch() }, width = 0, weight = 1f)
    lateinit var account: View
    account = accountButton(Keyless.email, getString(R.string.account_menu)) { accountMenu(account) }
    top.addView(account, LinearLayout.LayoutParams(dp(40), dp(40)).apply { marginStart = dp(12) })
    column.addView(top)
    content.setPadding(dp(16), dp(8), dp(16), dp(if (withNewItem) 104 else 24))
    val scroll = ScrollView(this).apply {
        isFillViewport = true
        addView(content)
    }
    val area = FrameLayout(this)
    area.addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    if (withNewItem && Keyless.writableVaults().isNotEmpty()) {
        val fab = Fab(this, getString(R.string.new_item)) { newItem(favorite = false) }
        area.addView(fab, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM or Gravity.END).apply { setMargins(dp(16), dp(16), dp(16), dp(16)) })
        scroll.setOnScrollChangeListener { _, _, y, _, before ->
            if (y > before + 4) fab.fold(true) else if (y < before - 4) fab.fold(false)
        }
    }
    column.addView(area, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    column.addView(bottomBar(tabs(), id) { chosen -> if (chosen == id) scroll.smoothScrollTo(0, 0) else showTab(chosen) })
    show(id, column, scroll = false)
}

/** The account's menu: who is signed in, and what is done with the account. */
private fun MainActivity.accountMenu(anchor: View) {
    val menu = PopupMenu(this, anchor)
    menu.menu.add(0, 0, 0, Keyless.email).isEnabled = false
    menu.menu.add(0, 1, 1, R.string.sign_in_other)
    menu.menu.add(0, 2, 2, R.string.generator)
    menu.menu.add(0, 3, 3, R.string.sync)
    menu.menu.add(0, 4, 4, R.string.settings)
    menu.menu.add(0, 5, 5, R.string.lock)
    menu.setOnMenuItemClickListener { choice ->
        when (choice.itemId) {
            1 -> signInOnOtherDevice()
            2 -> showGenerator(onUse = null, copy = { copy(getString(R.string.generated_password), it) })
            3 -> if (screen == "home") showHome(sync = true) else sync(label("")) { if (screen == tab) showTab(tab) }
            4 -> showSettings()
            5 -> {
                Keyless.lock()
                route()
            }
        }
        true
    }
    menu.show()
}

// ----- home ----------------------------------------------------------------------------

private fun Context.homePrefs() = getSharedPreferences("keyless", Context.MODE_PRIVATE)

/** Home's parts the user hid (Customize home). */
private fun Context.homeHidden(): Set<String> = homePrefs().getStringSet("home_hidden", emptySet()) ?: emptySet()

private val HOME_PARTS = listOf("setup", "sentinel", "favorites", "recent", "added")

/** Items opened last on this phone (their ids only), newest first. */
internal fun Context.noteOpened(id: String) {
    val list = (listOf(id) + openedIds().filter { it != id }).take(20)
    homePrefs().edit().putString("recent_items", JSONArray(list).toString()).apply()
}

internal fun Context.forgetOpened() = homePrefs().edit().remove("recent_items").apply()

internal fun Context.openedIds(): List<String> = try {
    val saved = JSONArray(homePrefs().getString("recent_items", "[]"))
    (0 until saved.length()).map { saved.getString(it) }
} catch (e: Exception) {
    emptyList()
}

/** A row for an item: its icon, title and subtitle; opens it. */
internal fun MainActivity.itemRow(item: Summary): LinearLayout {
    val url = item.overview.optJSONArray("urls")?.optJSONObject(0)?.optString("href")
    return groupRow(itemIcon(item.category, item.title, url), item.title, item.subtitle) { showItem(item.id) }
}

internal fun MainActivity.showHome(sync: Boolean = false) {
    if (!Keyless.isUnlocked) return route()
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val status = label("", 12f, muted = true).apply { visibility = View.GONE }
    page.add(status)
    val requests = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(requests)
    checkDeviceRequests(requests)
    val hidden = homeHidden()

    if ("setup" !in hidden) {
        val left = setupSteps().count { !it.done }
        if (left > 0) {
            val card = group()
            card.add(groupRow(roundIcon(R.drawable.ic_setup, Hues.teal), getString(R.string.setup_title), null, badge(resources.getQuantityString(R.plurals.setup_steps_left, left, left))) { showSetup() }.wrapTitle())
            page.add(card, top = 8)
        }
    }
    if ("sentinel" !in hidden) {
        val holder = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        page.add(holder, top = 8)
        sentinelCard(holder, onlyAlerts = true)
    }

    val items = Keyless.items
    if ("favorites" !in hidden) {
        val favorites = items.filter { it.favorite }.sortedBy { it.title.lowercase() }
        page.add(foldingGroup("favorites", roundIcon(R.drawable.ic_star_filled, Hues.amber), getString(R.string.favorites), favorites, getString(R.string.home_empty_favorites)), top = 12)
    }
    if ("recent" !in hidden) {
        val byId = items.associateBy { it.id }
        val opened = openedIds().mapNotNull { byId[it] }.take(5)
        if (opened.isNotEmpty()) page.add(foldingGroup("recent", roundIcon(R.drawable.ic_history, Hues.cyan), getString(R.string.recently_used), opened, null), top = 12)
    }
    if ("added" !in hidden) {
        val added = items.sortedByDescending { it.overview.optLong("created_at") }.take(5)
        if (added.isNotEmpty()) page.add(foldingGroup("added", roundIcon(R.drawable.ic_sparkles, Hues.green), getString(R.string.recently_added), added, null), top = 12)
    }
    page.addCentered(quietButton(getString(R.string.customize_home), R.drawable.ic_customize) { showCustomizeHome() }, top = 16)

    tabScreen("home", page, withNewItem = true)
    SiteIcons.refresh(this)
    if (sync || items.isEmpty()) sync(status) { if (screen == "home") showHome() }
    runPending()
}

/** A group of items under a title that folds it (remembered). */
private fun MainActivity.foldingGroup(id: String, icon: View, title: String, items: List<Summary>, emptyText: String?): LinearLayout {
    val card = group()
    val folded = homePrefs().getStringSet("home_folded", emptySet())?.contains(id) == true
    card.add(groupHeader(icon, title, !folded, {
        val set = (homePrefs().getStringSet("home_folded", emptySet()) ?: emptySet()).toMutableSet()
        if (!set.remove(id)) set.add(id)
        homePrefs().edit().putStringSet("home_folded", set).apply()
        showHome()
    }))
    if (!folded) {
        if (items.isEmpty() && emptyText != null) {
            card.add(label(emptyText, 14f, muted = true).apply { setPadding(dp(16), dp(4), dp(16), dp(12)) })
        }
        for (item in items) card.add(itemRow(item))
    }
    return card
}

/** Customize home: which parts it shows. */
internal fun MainActivity.showCustomizeHome() {
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(topBar(getString(R.string.customize_home), { showHome() }))
    val body = column(16)
    body.add(label(getString(R.string.customize_home_hint), 14f, muted = true))
    val names = mapOf(
        "setup" to (R.drawable.ic_setup to Hues.teal) to getString(R.string.setup_title),
        "sentinel" to (R.drawable.ic_shield to Hues.green) to Labels.t(this, "sentinel.title"),
        "favorites" to (R.drawable.ic_star_filled to Hues.amber) to getString(R.string.favorites),
        "recent" to (R.drawable.ic_history to Hues.cyan) to getString(R.string.recently_used),
        "added" to (R.drawable.ic_sparkles to Hues.green) to getString(R.string.recently_added),
    )
    val card = group()
    for ((key, name) in names) {
        val (id, look) = key
        val box = CheckBox(this).apply {
            isChecked = id !in homeHidden()
            contentDescription = name
            setOnCheckedChangeListener { _, on ->
                val set = homeHidden().toMutableSet()
                if (on) set.remove(id) else set.add(id)
                homePrefs().edit().putStringSet("home_hidden", set).apply()
            }
        }
        val rowView = groupRow(roundIcon(look.first, look.second, 36), name, null, box) { box.toggle() }
        card.add(rowView)
    }
    body.add(card, top = 12)
    page.add(body)
    show("customize", page)
}

// ----- setting up this phone ----------------------------------------------------------

/** A step of setting up the phone: biometrics, autofill, passkeys. */
internal class SetupStep(val icon: Int, val hue: Hue, val title: String, val hint: String, val done: Boolean, val start: () -> Unit)

internal fun MainActivity.setupSteps(): List<SetupStep> {
    val steps = mutableListOf<SetupStep>()
    if (biometricAvailable()) {
        steps.add(SetupStep(R.drawable.ic_fingerprint, Hues.violet, getString(R.string.step_biometric), getString(R.string.step_biometric_hint), SecureStore.biometricEnabled(this)) {
            enableBiometric { if (screen == "setup") showSetup() }
        })
    }
    val autofill = getSystemService(AutofillManager::class.java)
    if (autofill?.isAutofillSupported == true) {
        steps.add(SetupStep(R.drawable.ic_autofill, Hues.blue, getString(R.string.step_autofill), getString(R.string.step_autofill_hint), autofill.hasEnabledAutofillServices()) {
            try {
                startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:$packageName")))
            } catch (e: Exception) {
                // No autofill settings on this phone.
            }
        })
    }
    if (Build.VERSION.SDK_INT >= 34) {
        steps.add(SetupStep(R.drawable.ic_cat_login, Hues.amber, getString(R.string.step_passkeys), getString(R.string.step_passkeys_hint), passkeysOn()) {
            try {
                startActivity(Intent("android.settings.CREDENTIAL_PROVIDER").setData(Uri.parse("package:$packageName")))
            } catch (e: Exception) {
                // No such settings screen on this phone.
            }
        })
    }
    return steps
}

/** Whether Android uses Keyless for passkeys (Android 14 and later). */
internal fun Context.passkeysOn(): Boolean {
    if (Build.VERSION.SDK_INT < 34) return false
    return try {
        getSystemService(android.credentials.CredentialManager::class.java)
            ?.isEnabledCredentialProviderService(ComponentName(this, KeylessCredentialService::class.java)) == true
    } catch (e: Exception) {
        false
    }
}

internal fun MainActivity.showSetup() {
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(topBar(getString(R.string.setup_screen_title), { showHome() }))
    val body = column(16)
    body.add(label(getString(R.string.setup_hint), 14f, muted = true))
    val card = group()
    for (step in setupSteps()) {
        val end: View = if (step.done) {
            row().apply {
                addView(icon(R.drawable.ic_check, getColor(R.color.success), 18))
                addView(label(getString(R.string.step_on), 14f).apply {
                    setTextColor(getColor(R.color.success))
                    setPadding(dp(6), 0, dp(8), 0)
                })
            }
        } else {
            plainButton(getString(R.string.turn_on)) { step.start() }
        }
        card.add(groupRow(roundIcon(step.icon, step.hue), step.title, step.hint, end).wrapTitle().wrapSubtitle(6))
    }
    body.add(card, top = 12)
    body.addCentered(quietButton(getString(R.string.hide_setup)) {
        homePrefs().edit().putStringSet("home_hidden", homeHidden() + "setup").apply()
        showHome()
    }, top = 12)
    page.add(body)
    show("setup", page)
}

// ----- items ---------------------------------------------------------------------------

/** A vault's letter on its color (its name's, as the desktop does for items). */
internal fun Context.vaultIcon(name: String, size: Int = 40): TextView = TextView(this).apply {
    text = Regex("[\\p{L}\\p{N}]").find(name)?.value?.uppercase() ?: "?"
    gravity = Gravity.CENTER
    setTextColor(android.graphics.Color.WHITE)
    setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, size * 0.4f)
    weight(600)
    background = android.graphics.drawable.GradientDrawable().apply {
        shape = android.graphics.drawable.GradientDrawable.OVAL
        setColor(avatarColor(name))
    }
    layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
}

/** The Items tab: every item, the vaults, categories and tags, then the archive and recently deleted. */
internal fun MainActivity.showItemsTab() {
    if (!Keyless.isUnlocked) return route()
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    val items = Keyless.items
    val side = { key: String -> Labels.t(this, "sidebar.$key") }

    val first = group()
    first.add(groupRow(roundIcon(R.drawable.ic_items, Hues.teal), getString(R.string.all_items), null, countText(items.size)) { openList("all") })
    first.add(groupRow(roundIcon(R.drawable.ic_star_filled, Hues.amber), getString(R.string.favorites), null, countText(items.count { it.favorite })) { openList("favorites") })
    if (withPasskeys.isNotEmpty()) {
        first.add(groupRow(roundIcon(R.drawable.ic_cat_login, Hues.violet), Labels.t(this, "filters.passkey"), null, countText(items.count { it.id in withPasskeys })) { openList("all", passkeys = true) })
    }
    page.add(first, top = 8)

    val vaults = (0 until Keyless.vaults.length()).map { Keyless.vaults.getJSONObject(it) }
    if (vaults.size > 1) {
        page.add(heading(side("vaults")), top = 16)
        val card = group()
        for (vault in vaults) {
            val id = vault.optString("id")
            val name = vault.optString("name")
            card.add(groupRow(vaultIcon(name), name, null, countText(items.count { it.vaultId == id })) { openList("all", vault = id) })
        }
        page.add(card)
    }

    val categories = items.groupBy { it.category }.toList().sortedBy { Labels.categoryPlural(this, it.first) }
    if (categories.isNotEmpty()) {
        page.add(heading(side("categories")), top = 16)
        val card = group()
        for ((category, list) in categories) {
            card.add(groupRow(itemIcon(category, "", null, 40), Labels.categoryPlural(this, category), null, countText(list.size)) { openList("category:$category") })
        }
        page.add(card)
    }

    val tags = items.flatMap { item -> item.overview.optJSONArray("tags")?.let { t -> (0 until t.length()).map { t.optString(it) } } ?: emptyList() }
        .filter { it.isNotBlank() }.groupingBy { it }.eachCount().toList().sortedBy { it.first.lowercase() }
    if (tags.isNotEmpty()) {
        page.add(heading(side("tags")), top = 16)
        val card = group()
        for ((name, count) in tags) {
            card.add(groupRow(roundIcon(R.drawable.ic_tag, Hues.indigo, 36), name, null, countText(count)) { openList("all", tag = name) })
        }
        page.add(card)
    }

    if (Keyless.archived.isNotEmpty() || Keyless.trashed.isNotEmpty()) {
        val card = group()
        if (Keyless.archived.isNotEmpty()) card.add(groupRow(roundIcon(R.drawable.ic_archive, Hues.slate), getString(R.string.archived_items), null, countText(Keyless.archived.size)) { openList("archive") })
        if (Keyless.trashed.isNotEmpty()) card.add(groupRow(roundIcon(R.drawable.ic_trash, Hues.red), getString(R.string.trash), null, countText(Keyless.trashed.size)) { openList("trash") })
        page.add(card, top = 16)
    }
    tabScreen("items", page, withNewItem = true)
}

// ----- a new item ------------------------------------------------------------------------

/** The categories shown first when adding an item; the rest come with Show more. */
private val FIRST_CATEGORIES = listOf("login", "secure_note", "credit_card", "identity", "password", "document")

/** New item: the categories as tiles (the most used first), with a search over them. */
internal fun MainActivity.showNewItem(favorite: Boolean, all: Boolean = false, typed: String = "") {
    val templates = Labels.templates(this)
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(topBar(getString(R.string.new_item), { showMain() }))
    val body = column(16).apply { setPadding(dp(16), 0, dp(16), dp(24)) }
    val search = searchField(getString(R.string.choose_category)).apply {
        setText(typed)
        background = shape(getColor(R.color.search_pill), 24f)
        minHeight = dp(48)
        setPadding(dp(16), dp(8), dp(16), dp(8))
    }
    body.add(search)
    val grid = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    body.add(grid, top = 12)
    val more = plainButton(getString(if (all) R.string.show_less else R.string.show_more)) { showNewItem(favorite, !all, search.text.toString()) }
    body.addCentered(more, top = 8)

    fun fill() {
        grid.removeAllViews()
        val words = search.text.toString().trim().lowercase()
        val shown = templates.map { it.getString("id") }
            .filter { words.isNotEmpty() || all || it in FIRST_CATEGORIES }
            .sortedBy { if (it in FIRST_CATEGORIES) FIRST_CATEGORIES.indexOf(it) else 100 }
            .filter { words.isEmpty() || Labels.category(this, it).lowercase().contains(words) }
        more.visibility = if (words.isEmpty()) View.VISIBLE else View.GONE
        for (pair in shown.chunked(2)) {
            val line = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            for ((i, category) in pair.withIndex()) {
                line.addView(categoryTile(category, Labels.category(this, category)) { startDraft(category, favorite) }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { if (i == 1) marginStart = dp(12) })
            }
            if (pair.size == 1) line.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f).apply { marginStart = dp(12) })
            grid.add(line, top = if (grid.childCount == 0) 0 else 12)
        }
    }
    search.addTextChangedListener(object : android.text.TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: android.text.Editable?) = fill()
    })
    fill()
    body.addCentered(quietButton(Labels.t(this, "importer.title"), R.drawable.ic_file_down) { showImport() }, top = 16)
    page.add(body)
    show("new-item", page)
}

/** Starts the editor on a new item of `category`, with its template's fields. */
internal fun MainActivity.startDraft(category: String, favorite: Boolean) {
    val vaults = Keyless.writableVaults()
    if (vaults.isEmpty()) return
    val fields = Labels.templateFields(this, category)
    if (category == "login") prefillUsername(fields)
    val draft = JSONObject()
        .put("vaultId", vaults[0].getString("id"))
        .put("title", "")
        .put("category", category)
        .put("fields", fields)
        .put("sections", JSONArray())
        .put("urls", JSONArray())
        .put("tags", JSONArray())
        .put("notes", "")
        .put("favorite", favorite)
    showEditor(draft)
}
