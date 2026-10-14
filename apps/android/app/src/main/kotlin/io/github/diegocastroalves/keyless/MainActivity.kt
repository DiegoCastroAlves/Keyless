package io.github.diegocastroalves.keyless

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.PopupMenu
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/**
 * The app's one screen at a time: signing in (with the Secret Key, a setup
 * link or another device), unlocking, the items, an item, and settings.
 */
class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var root: FrameLayout
    internal var screen = "none"
        private set

    /** What Back does in the editor (asks before dropping changes). */
    internal var editorBack: (() -> Unit)? = null

    /** Where a scanned QR code goes. */
    private var onScanned: ((String) -> Unit)? = null

    /** Scans a QR code holding what is `wanted` (QrScanActivity.WANT_*). */
    @Suppress("DEPRECATION")
    internal fun scanQr(wanted: String, onResult: (String) -> Unit) {
        onScanned = onResult
        startActivityForResult(Intent(this, QrScanActivity::class.java).putExtra(QrScanActivity.EXTRA_WANTED, wanted), SCAN_QR)
    }

    /** What waits for other activities' answers (files picked or created), by request code. */
    private val waiting = mutableMapOf<Int, (Int, Intent?) -> Unit>()
    private var nextRequest = 100

    /** Starts `intent` (a file picker...) and calls `onResult` with its answer. */
    @Suppress("DEPRECATION")
    internal fun startForResult(intent: Intent, onResult: (resultCode: Int, data: Intent?) -> Unit) {
        val code = nextRequest++
        waiting[code] = onResult
        try {
            startActivityForResult(intent, code)
        } catch (e: android.content.ActivityNotFoundException) {
            waiting.remove(code)
            Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        waiting.remove(requestCode)?.let { it(resultCode, data); return }
        if (requestCode != SCAN_QR) return
        val content = data?.getStringExtra(QrScanActivity.EXTRA_CONTENT)
        val callback = onScanned
        onScanned = null
        if (resultCode == RESULT_OK && content != null) callback?.invoke(content)
    }

    /** The email and Secret Key from a setup link or another device. */
    private var received: Pair<String, String>? = null
    private var notice: String? = null
    private var query = ""
    private var filter = "all"

    /** The list's other filters (as the desktop's Filter menu) and its order. */
    private var vaultFilter: String? = null
    private var tagFilter: String? = null
    private var passkeyFilter = false
    private var withPasskeys: Set<String> = emptySet()

    /** Items whose notes or other fields hold the query (searched off the main thread). */
    private var detailMatches: Set<String> = emptySet()
    private var detailSearch: Runnable? = null
    private var deviceRequest: Keyless.DeviceRequest? = null
    private var ticking: Runnable? = null

    /** A launcher shortcut's screen, opened once the vault is unlocked. */
    private var pendingAction: String? = null

    private fun takeAction(intent: Intent?) {
        val action = intent?.action ?: return
        if (action.startsWith("$packageName.")) pendingAction = action.removePrefix("$packageName.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // The theme setting: as the system, light or dark.
        when (getSharedPreferences("keyless", MODE_PRIVATE).getString("theme", "system")) {
            "light" -> setTheme(R.style.Theme_Keyless_Light)
            "dark" -> setTheme(R.style.Theme_Keyless_Dark)
        }
        super.onCreate(savedInstanceState)
        takeAction(intent)
        // No screenshots, and no previews of the vault in the recent apps.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) window.setDecorFitsSystemWindows(false)
        root = FrameLayout(this)
        root.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        setContentView(root)
        handleLink(intent)
        if (reopenSettings && Keyless.isUnlocked) {
            reopenSettings = false
            showSettings()
        } else {
            route()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        takeAction(intent)
        if (handleLink(intent) || pendingAction != null) route()
    }

    override fun onResume() {
        super.onResume()
        if (screen !in listOf("signin", "device", "unlock", "recover") && !Keyless.isUnlocked) route()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        if (screen in listOf("list", "item", "settings", "editor", "devices", "history", "transfer", "recovery-key") || screen.startsWith("sentinel")) Keyless.touch()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        when (screen) {
            "item", "settings" -> showList()
            "history" -> showItem(lastItemId)
            "devices", "recovery-key", "transfer" -> showSettings()
            "recover" -> leaveRecovery()
            "sentinel" -> showList()
            "sentinel-list" -> showSentinel(null)
            "editor" -> editorBack?.invoke() ?: showList()
            "device" -> {
                deviceRequest?.let { request -> thread { Keyless.cancelDeviceSetup(request) } }
                deviceRequest = null
                showSignIn()
            }
            else -> @Suppress("DEPRECATION") super.onBackPressed()
        }
    }

    /** A keyless://setup link fills the sign-in form. */
    private fun handleLink(intent: Intent?): Boolean {
        val data = intent?.data?.toString() ?: return false
        if (!data.lowercase().startsWith("keyless://setup")) return false
        return try {
            val parsed = Native.obj("parseSetupLink", JSONObject().put("text", data))
            received = parsed.getString("email") to parsed.getString("secretKey")
            if (Keyless.hasAccount) false else true
        } catch (e: KeylessException) {
            notice = errorText(e)
            true
        }
    }

    internal fun route() {
        when {
            !Keyless.hasAccount -> showSignIn()
            !Keyless.isUnlocked -> showUnlock()
            else -> showList()
        }
    }

    /** The list, kept beside the item on wide screens (tablets, unfolded phones). */
    private var listPage: View? = null

    private val wide: Boolean get() = resources.configuration.screenWidthDp >= 720

    internal fun show(name: String, view: View, scroll: Boolean = true) {
        ticking?.let { handler.removeCallbacks(it) }
        ticking = null
        if (name != "editor") editorBack = null
        screen = name
        root.removeAllViews()
        (listPage?.parent as? ViewGroup)?.removeView(listPage)
        // Locked or signed out: the list (and its titles) goes.
        if (name in listOf("signin", "unlock", "device", "recover")) listPage = null
        val content = if (scroll) ScrollView(this).apply { addView(view) } else view
        val list = listPage
        val beside = wide && list != null && (name == "list" || name == "item" || name == "history" || name == "editor")
        if (beside && list != null) {
            val panes = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            if (name == "list") {
                panes.addView(view, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 2f))
                panes.addView(label(getString(R.string.select_item), 15f, muted = true).apply { gravity = android.view.Gravity.CENTER }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 3f))
            } else {
                panes.addView(list, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 2f))
                panes.addView(content, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 3f))
            }
            root.addView(panes, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        } else {
            root.addView(content, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        }
        root.requestApplyInsets()
    }

    internal fun scrollPosition(): Int = (root.getChildAt(0) as? ScrollView)?.scrollY ?: 0

    internal fun restoreScroll(y: Int) {
        val scroll = root.getChildAt(0) as? ScrollView ?: return
        scroll.post { scroll.scrollTo(0, y) }
    }

    // ----- signing in ----------------------------------------------------------

    private fun showSignIn(error: String? = null) {
        val form = column()
        val email = field(getString(R.string.email), TEXT_EMAIL)
        email.setText(received?.first ?: "")
        val secretKey = field("K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX", TEXT_KEY, secret = true)
        val password = field(getString(R.string.master_password), TEXT_PASSWORD, secret = true)
        val errorLine = label(error ?: "", 14f).apply { setTextColor(getColor(R.color.danger)) }
        form.add(label(getString(R.string.sign_in_title), 22f, bold = true))
        form.add(label(getString(R.string.sign_in_intro), 14f, muted = true), top = 6)
        notice?.let { form.add(label(it, 14f).apply { setTextColor(accent()) }, top = 12) }
        form.add(email, top = 20)
        val current = received
        if (current != null) {
            val line = row()
            line.add(label("✓ " + getString(R.string.key_received), 14f).apply { setTextColor(accent()) }, width = 0, weight = 1f)
            line.add(plainButton(getString(R.string.type_key_instead)) {
                received = null
                notice = null
                showSignIn()
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            form.add(line, top = 8)
        } else {
            form.add(secretKey, top = 8)
            form.add(label(getString(R.string.secret_key_hint), 12f, muted = true), top = 2)
            form.add(plainButton(getString(R.string.scan_emergency_kit)) {
                scanQr(QrScanActivity.WANT_SETUP) { link ->
                    try {
                        val parsed = Native.obj("parseSetupLink", JSONObject().put("text", link))
                        received = parsed.getString("email") to parsed.getString("secretKey")
                        showSignIn()
                    } catch (e: KeylessException) {
                        errorLine.text = errorText(e)
                    }
                }
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            secretKey.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    val text = s?.toString() ?: return
                    if (!text.trim().lowercase().startsWith("keyless://setup")) return
                    try {
                        val parsed = Native.obj("parseSetupLink", JSONObject().put("text", text))
                        received = parsed.getString("email") to parsed.getString("secretKey")
                        showSignIn()
                    } catch (e: KeylessException) {
                        secretKey.setText("")
                        errorLine.text = errorText(e)
                    }
                }
            })
        }
        form.add(password, top = 8)
        form.add(errorLine, top = 6)
        lateinit var submit: Button
        submit = primaryButton(getString(R.string.sign_in)) {
            val key = received?.second ?: secretKey.text.toString()
            val address = email.text.toString().trim()
            val typed = password.text.toString()
            if (address.isEmpty() || key.isEmpty() || typed.isEmpty()) return@primaryButton
            submit.isEnabled = false
            submit.text = getString(R.string.signing_in)
            errorLine.text = ""
            thread {
                val failure = try {
                    Keyless.signIn(address, key, typed)
                    null
                } catch (e: Exception) {
                    e
                }
                runOnUiThread {
                    if (failure == null) {
                        received = null
                        notice = null
                        notePasswordTyped()
                        showList()
                    } else {
                        submit.isEnabled = true
                        submit.text = getString(R.string.sign_in)
                        errorLine.text = errorText(failure)
                    }
                }
            }
        }
        form.add(submit, top = 8)
        form.add(plainButton(getString(R.string.with_passkey)) {
            passkeySignIn(errorLine) {
                received = null
                notice = null
                showList()
            }
        }, top = 4)
        form.add(plainButton(getString(R.string.use_other_device)) {
            val address = email.text.toString().trim().lowercase()
            if (!address.contains("@")) {
                errorLine.text = getString(R.string.email_first)
            } else {
                showDevice(address)
            }
        }, top = 4)
        form.add(plainButton(Labels.t(this, "recovery.forgot")) { showRecover() }, top = 4)
        show("signin", form)
    }

    private fun showDevice(email: String) {
        val form = column()
        val status = label(getString(R.string.device_waiting), 15f, muted = true)
        form.add(label(getString(R.string.use_other_device), 22f, bold = true))
        form.add(label(getString(R.string.device_body, email), 14f, muted = true), top = 6)
        form.add(status, top = 24)
        form.add(plainButton(getString(R.string.cancel)) {
            deviceRequest?.let { request -> thread { Keyless.cancelDeviceSetup(request) } }
            deviceRequest = null
            showSignIn()
        }, top = 16)
        show("device", form)
        thread {
            val request = try {
                Keyless.requestDeviceSetup(email)
            } catch (e: Exception) {
                runOnUiThread { if (screen == "device") status.text = errorText(e) }
                return@thread
            }
            deviceRequest = request
            val revealed = booleanArrayOf(false)
            while (deviceRequest === request) {
                Thread.sleep(2000)
                if (deviceRequest !== request) return@thread
                val state = try {
                    Keyless.pollDeviceSetup(request, revealed)
                } catch (e: Exception) {
                    runOnUiThread { status.text = errorText(e) }
                    return@thread
                }
                when (state.getString("status")) {
                    "code" -> runOnUiThread {
                        val code = state.getString("code")
                        status.text = getString(R.string.device_code) + "\n\n" + code.substring(0, 3) + " " + code.substring(3)
                        status.textSize = 28f
                    }
                    "approved" -> {
                        deviceRequest = null
                        runOnUiThread {
                            received = state.getString("email") to state.getString("secretKey")
                            notice = getString(R.string.device_done)
                            showSignIn()
                        }
                        return@thread
                    }
                    "denied", "expired" -> {
                        deviceRequest = null
                        runOnUiThread {
                            status.text = getString(if (state.getString("status") == "denied") R.string.device_denied else R.string.device_expired)
                            status.textSize = 15f
                        }
                        return@thread
                    }
                }
            }
        }
    }

    // ----- unlocking --------------------------------------------------------------

    private fun showUnlock() {
        show("unlock", unlockForm(onUnlocked = { showList() }, onSignOut = { signOut() }))
    }

    private fun signOut() {
        thread {
            try {
                Keyless.signOut()
            } catch (e: Exception) {
                // Removed here anyway.
            }
            runOnUiThread { showSignIn() }
        }
    }

    // ----- the items -----------------------------------------------------------------

    internal fun showList() {
        if (!Keyless.isUnlocked) return route()
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val header = row().apply { setPadding(dp(16), dp(8), dp(8), dp(4)) }
        header.add(label("Keyless", 20f, bold = true), width = 0, weight = 1f)
        val status = label("", 12f, muted = true)
        if (Keyless.writableVaults().isNotEmpty()) {
            header.add(plainButton("+") { newItem(favorite = filter == "favorites") }.apply {
                textSize = 22f
                contentDescription = getString(R.string.new_item)
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        header.add(plainButton(getString(R.string.lock)) {
            Keyless.lock()
            route()
        }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        lateinit var more: Button
        more = plainButton("⋮") {
            val menu = PopupMenu(this, more)
            menu.menu.add(0, 1, 0, R.string.sync)
            menu.menu.add(0, 4, 1, Labels.t(this, "sentinel.title"))
            menu.menu.add(0, 2, 2, R.string.generator)
            menu.menu.add(0, 3, 3, R.string.settings)
            menu.setOnMenuItemClickListener { choice ->
                when (choice.itemId) {
                    1 -> sync(status)
                    2 -> showGenerator(onUse = null, copy = { copy(getString(R.string.generated_password), it) })
                    3 -> showSettings()
                    4 -> showSentinel(null)
                }
                true
            }
            menu.show()
        }.apply { contentDescription = getString(R.string.more) }
        header.add(more, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(header)
        val search = EditText(this).apply {
            hint = getString(R.string.search)
            setSingleLine(true)
            setText(query)
        }
        // The search, with the Filter menu and the order beside it.
        val searchLine = row().apply { setPadding(dp(16), 0, dp(8), 0) }
        searchLine.add(search, width = 0, weight = 1f)
        val filterButton = plainButton(Labels.t(this, "filters.title")) {}
        searchLine.add(filterButton, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        val sortButton = plainButton("⇅") {}.apply { contentDescription = Labels.t(this@MainActivity, "list.sort.title") }
        searchLine.add(sortButton, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(searchLine)
        val filters = row().apply { setPadding(dp(12), dp(4), dp(12), dp(4)) }
        page.add(HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(filters) })
        val recent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), 0, dp(16), 0)
        }
        page.add(recent)
        page.add(LinearLayout(this).apply { setPadding(dp(16), 0, dp(16), 0); addView(status) })
        val requests = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), 0, dp(16), dp(4))
        }
        page.add(requests)
        checkDeviceRequests(requests)
        val sentinel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), 0, dp(16), dp(4))
        }
        page.add(sentinel)
        sentinelCard(sentinel)
        val list = ListView(this)
        val adapter = ItemsAdapter()
        list.adapter = adapter
        page.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        fun showRecent() {
            recent.removeAllViews()
            val searches = recentSearches()
            if (query.isNotEmpty() || !search.hasFocus() || searches.isEmpty()) return
            val head = row()
            head.add(label(Labels.t(this, "list.recentSearches"), 12f, bold = true, muted = true), width = 0, weight = 1f)
            head.add(plainButton(Labels.t(this, "list.clearRecent")) {
                getSharedPreferences("keyless", MODE_PRIVATE).edit().remove("recent_searches").apply()
                recent.removeAllViews()
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            recent.add(head)
            for (text in searches) recent.add(plainButton(text) { search.setText(text); search.setSelection(text.length) }.apply { gravity = android.view.Gravity.START or android.view.Gravity.CENTER_VERTICAL })
        }
        search.setOnFocusChangeListener { _, _ -> showRecent() }
        list.setOnItemClickListener { _, _, position, _ ->
            if (query.trim().length >= 2) rememberSearch(query.trim())
            showItem(adapter.shown[position].id)
        }

        fun refresh() {
            adapter.update()
            filters.removeAllViews()
            val active = vaultFilter != null || tagFilter != null || passkeyFilter
            filterButton.text = (if (active) "● " else "") + Labels.t(this, "filters.title")
            val choices = mutableListOf("all" to getString(R.string.all_items), "favorites" to getString(R.string.favorites))
            Keyless.items.map { it.category }.distinct().sortedBy { Labels.categoryPlural(this, it) }.forEach { choices.add("category:$it" to Labels.categoryPlural(this, it)) }
            if (Keyless.archived.isNotEmpty() || filter == "archive") choices.add("archive" to getString(R.string.archived_items))
            if (Keyless.trashed.isNotEmpty() || filter == "trash") choices.add("trash" to getString(R.string.trash))
            for ((id, name) in choices) {
                val chip = plainButton(name) {
                    filter = id
                    refresh()
                }
                if (id == filter) chip.setTextColor(getColor(android.R.color.white))
                if (id == filter) chip.backgroundTintList = android.content.res.ColorStateList.valueOf(accent())
                filters.addView(chip)
            }
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString() ?: ""
                adapter.update()
                showRecent()
                searchDetailsSoon(query) { adapter.update() }
            }
        })
        search.setOnEditorActionListener { _, _, _ ->
            if (query.trim().length >= 2) rememberSearch(query.trim())
            false
        }
        filterButton.setOnClickListener { chooseFilters { refresh() } }
        sortButton.setOnClickListener { chooseSort { adapter.update() } }
        refresh()
        listPage = page
        show("list", page, scroll = false)
        if (Keyless.items.isEmpty()) sync(status) { refresh() }
        listRefresh = { refresh() }
        when (pendingAction.also { pendingAction = null }) {
            "SEARCH" -> search.post {
                search.requestFocus()
                getSystemService(android.view.inputmethod.InputMethodManager::class.java)?.showSoftInput(search, 0)
            }
            "NEW_ITEM" -> if (Keyless.writableVaults().isNotEmpty()) newItem(favorite = false)
            "GENERATOR" -> showGenerator(onUse = null, copy = { copy(getString(R.string.generated_password), it) })
        }
    }

    private var listRefresh: (() -> Unit)? = null

    private fun tagsOf(item: Summary): List<String> {
        val tags = item.overview.optJSONArray("tags") ?: return emptyList()
        return (0 until tags.length()).map { tags.optString(it) }
    }

    /** Searches inside the items a moment after typing stops, then calls `then`. */
    private fun searchDetailsSoon(text: String, then: () -> Unit) {
        detailSearch?.let { handler.removeCallbacks(it) }
        if (text.trim().length < 2) {
            detailMatches = emptySet()
            return
        }
        val run = Runnable {
            thread {
                val found = try {
                    Keyless.searchDetails(text.trim())
                } catch (e: Exception) {
                    emptySet()
                }
                runOnUiThread {
                    if (query == text) {
                        detailMatches = found
                        then()
                    }
                }
            }
        }
        detailSearch = run
        handler.postDelayed(run, 250)
    }

    private fun recentSearches(): List<String> {
        val saved = getSharedPreferences("keyless", MODE_PRIVATE).getString("recent_searches", null) ?: return emptyList()
        return try {
            val list = org.json.JSONArray(saved)
            (0 until list.length()).map { list.getString(it) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun rememberSearch(text: String) {
        val list = (listOf(text) + recentSearches().filter { it != text }).take(5)
        getSharedPreferences("keyless", MODE_PRIVATE).edit().putString("recent_searches", org.json.JSONArray(list).toString()).apply()
    }

    /** The list's order (as the desktop's): title, created or modified, either way. */
    private fun sorted(list: List<Summary>): List<Summary> {
        val prefs = getSharedPreferences("keyless", MODE_PRIVATE)
        val by = prefs.getString("sort_by", "title")
        val reverse = prefs.getBoolean("sort_reverse", false)
        val ordered = when (by) {
            "created" -> list.sortedByDescending { it.overview.optLong("created_at") }
            "modified" -> list.sortedByDescending { it.overview.optLong("updated_at") }
            else -> list.sortedBy { it.title.lowercase() }
        }
        return if (reverse) ordered.reversed() else ordered
    }

    private fun chooseSort(then: () -> Unit) {
        val prefs = getSharedPreferences("keyless", MODE_PRIVATE)
        val choices = listOf(
            Triple("title", false, "list.order.az"), Triple("title", true, "list.order.za"),
            Triple("modified", false, "list.order.newest"), Triple("modified", true, "list.order.oldest"),
            Triple("created", false, "list.order.newest"), Triple("created", true, "list.order.oldest"),
        )
        val names = choices.map { (by, _, order) -> Labels.t(this, "list.sort.$by") + " · " + Labels.t(this, order) }.toTypedArray()
        val current = choices.indexOfFirst { it.first == prefs.getString("sort_by", "title") && it.second == prefs.getBoolean("sort_reverse", false) }
        android.app.AlertDialog.Builder(this)
            .setTitle(Labels.t(this, "list.sort.title"))
            .setSingleChoiceItems(names, current) { dialog, which ->
                prefs.edit().putString("sort_by", choices[which].first).putBoolean("sort_reverse", choices[which].second).apply()
                dialog.dismiss()
                then()
            }
            .show()
    }

    /** The Filter menu: vault, tag and passkeys. */
    private fun chooseFilters(then: () -> Unit) {
        val box = column(20)
        val vaultList = (0 until Keyless.vaults.length()).map { Keyless.vaults.getJSONObject(it) }
        val vaultGroup = RadioGroup(this)
        if (vaultList.size > 1) {
            box.add(label(Labels.t(this, "filters.vault"), 14f, bold = true))
            vaultGroup.addView(RadioButton(this).apply { text = Labels.t(this@MainActivity, "filters.any"); id = View.generateViewId(); tag = ""; isChecked = vaultFilter == null })
            for (vault in vaultList) {
                vaultGroup.addView(RadioButton(this).apply { text = vault.optString("name"); id = View.generateViewId(); tag = vault.optString("id"); isChecked = vaultFilter == vault.optString("id") })
            }
            box.add(vaultGroup, top = 2)
        }
        val allTags = (Keyless.items + Keyless.archived).flatMap { tagsOf(it) }.distinct().sortedBy { it.lowercase() }
        val tagGroup = RadioGroup(this)
        if (allTags.isNotEmpty()) {
            box.add(label(Labels.t(this, "filters.tag"), 14f, bold = true), top = 12)
            tagGroup.addView(RadioButton(this).apply { text = Labels.t(this@MainActivity, "filters.any"); id = View.generateViewId(); tag = null; isChecked = tagFilter == null })
            tagGroup.addView(RadioButton(this).apply { text = Labels.t(this@MainActivity, "filters.untagged"); id = View.generateViewId(); tag = ""; isChecked = tagFilter == "" })
            for (name in allTags) tagGroup.addView(RadioButton(this).apply { text = name; id = View.generateViewId(); tag = name; isChecked = tagFilter == name })
            box.add(tagGroup, top = 2)
        }
        val passkeys = Switch(this).apply { text = Labels.t(this@MainActivity, "filters.passkey"); isChecked = passkeyFilter }
        box.add(passkeys, top = 12)
        android.app.AlertDialog.Builder(this)
            .setTitle(Labels.t(this, "filters.title"))
            .setView(ScrollView(this).apply { addView(box) })
            .setPositiveButton(Labels.t(this, "common.done")) { _, _ ->
                vaultFilter = (vaultGroup.findViewById<RadioButton>(vaultGroup.checkedRadioButtonId)?.tag as? String)?.ifEmpty { null }
                tagFilter = tagGroup.findViewById<RadioButton>(tagGroup.checkedRadioButtonId)?.tag as? String
                passkeyFilter = passkeys.isChecked
                withPasskeys = if (passkeyFilter) (try { Keyless.itemsWithPasskeys() } catch (e: Exception) { emptySet() }) else emptySet()
                then()
            }
            .setNeutralButton(Labels.t(this, "filters.clear")) { _, _ ->
                vaultFilter = null
                tagFilter = null
                passkeyFilter = false
                then()
            }
            .show()
    }

    private fun sync(status: TextView, then: (() -> Unit)? = null) {
        status.text = getString(R.string.syncing)
        thread {
            val failure = try {
                Keyless.sync()
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                status.text = failure?.let { errorText(it) } ?: ""
                if (screen == "list") (then ?: listRefresh)?.invoke()
            }
            // Sentinel's daily downloads, after the items are fresh.
            if (failure == null) SentinelData.refresh(this, force = false)
        }
    }

    private inner class ItemsAdapter : BaseAdapter() {
        var shown: List<Summary> = emptyList()

        fun update() {
            val words = query.lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
            val source = when (filter) {
                "archive" -> Keyless.archived
                "trash" -> Keyless.trashed
                else -> Keyless.items
            }
            val inDetails = if (query.trim().length >= 2) detailMatches else emptySet()
            shown = source.filter { item ->
                when {
                    filter == "favorites" && !item.favorite -> false
                    filter.startsWith("category:") && item.category != filter.removePrefix("category:") -> false
                    vaultFilter != null && item.vaultId != vaultFilter -> false
                    tagFilter == "" && (item.overview.optJSONArray("tags")?.length() ?: 0) > 0 -> false
                    !tagFilter.isNullOrEmpty() && !tagsOf(item).contains(tagFilter) -> false
                    passkeyFilter && item.id !in withPasskeys -> false
                    else -> {
                        val urls = item.overview.optJSONArray("urls")
                        val tags = item.overview.optJSONArray("tags")
                        val text = buildString {
                            append(item.title).append(' ').append(item.subtitle)
                            if (urls != null) for (i in 0 until urls.length()) append(' ').append(urls.getJSONObject(i).optString("href"))
                            if (tags != null) for (i in 0 until tags.length()) append(' ').append(tags.optString(i))
                        }.lowercase()
                        words.all { text.contains(it) } || item.id in inDetails
                    }
                }
            }
            shown = sorted(shown)
            notifyDataSetChanged()
        }

        override fun getCount(): Int = shown.size
        override fun getItem(position: Int): Any = shown[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val item = shown[position]
            val line = row().apply { setPadding(dp(16), dp(10), dp(16), dp(10)) }
            line.addView(avatar(item.title), LinearLayout.LayoutParams(dp(38), dp(38)))
            val texts = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, 0, 0)
            }
            texts.addView(label(item.title, 16f).apply { setSingleLine(true) })
            if (item.subtitle.isNotEmpty()) texts.addView(label(item.subtitle, 13f, muted = true).apply { setSingleLine(true) })
            line.addView(texts, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            return line
        }
    }

    // ----- an item ---------------------------------------------------------------------

    /** The item shown last (where Back goes from its history). */
    private var lastItemId = ""

    internal fun showItem(id: String) {
        if (!Keyless.isUnlocked) return route()
        lastItemId = id
        val item = try {
            Keyless.item(id)
        } catch (e: KeylessException) {
            Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
            return
        }
        val overview = item.getJSONObject("overview")
        val details = item.getJSONObject("details")
        val trashed = overview.has("trashed_at") && !overview.isNull("trashed_at")
        val archived = overview.optBoolean("archived")
        val writable = Keyless.canWrite(item.optString("vaultId"))
        val title = overview.optString("title")
        val page = column(20)
        val bar = row()
        bar.add(plainButton("← " + getString(R.string.back)) { showList() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        bar.add(View(this), width = 0, weight = 1f)
        if (writable && !trashed) {
            val favorite = overview.optBoolean("favorite")
            bar.add(plainButton(if (favorite) "★" else "☆") {
                act({ Keyless.setFavorite(id, !favorite) }) { showItem(id) }
            }.apply {
                textSize = 20f
                contentDescription = getString(if (favorite) R.string.unfavorite else R.string.favorite)
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            bar.add(plainButton(getString(R.string.edit)) { editItem(id) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        if (!trashed) {
            lateinit var more: Button
            more = plainButton("⋮") {
                val menu = PopupMenu(this, more)
                if (writable) {
                    menu.menu.add(0, 1, 0, R.string.duplicate)
                    menu.menu.add(0, 2, 1, if (archived) R.string.unarchive else R.string.archive)
                    menu.menu.add(0, 3, 2, R.string.move_to_trash)
                    menu.menu.add(0, 7, 6, Labels.t(this, "item.attach"))
                }
                menu.menu.add(0, 4, 3, Labels.t(this, "itemHistory.title"))
                menu.menu.add(0, 5, 4, Labels.t(this, "share.action"))
                if (overview.optString("category") == "wireless_router") menu.menu.add(0, 6, 5, Labels.t(this, "item.wifiQr"))
                menu.setOnMenuItemClickListener { choice ->
                    when (choice.itemId) {
                        1 -> {
                            var copyId = ""
                            act({ copyId = Keyless.duplicate(id, getString(R.string.copy_title, title)) }) { showItem(copyId) }
                        }
                        2 -> act({ Keyless.setArchived(id, !archived) }) { showItem(id) }
                        3 -> act({ Keyless.setTrashed(id, true) }) { showList() }
                        4 -> showHistory(id, writable)
                        5 -> shareItem(id, title)
                        6 -> showWifiQr(id)
                        7 -> attachFile(id)
                    }
                    true
                }
                menu.show()
            }.apply { contentDescription = getString(R.string.more) }
            bar.add(more, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        page.add(bar)
        if (trashed) {
            val since = DateFormat.getDateInstance().format(Date(overview.optLong("trashed_at") * 1000))
            page.add(label(getString(R.string.trashed_note, since), 13f, muted = true), top = 8)
            if (writable) {
                val actions = row()
                actions.add(primaryButton(getString(R.string.restore)) {
                    act({ Keyless.setTrashed(id, false) }) { showItem(id) }
                }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                actions.add(plainButton(getString(R.string.delete_forever)) {
                    android.app.AlertDialog.Builder(this)
                        .setTitle(R.string.delete_forever)
                        .setMessage(getString(R.string.delete_forever_body, title))
                        .setPositiveButton(R.string.delete_forever) { _, _ -> act({ Keyless.deleteForGood(id) }) { showList() } }
                        .setNegativeButton(R.string.cancel, null)
                        .show()
                }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                page.add(actions, top = 4)
            }
        } else if (archived) {
            page.add(label(getString(R.string.archived_note), 13f, muted = true), top = 8)
        }
        page.add(label(Labels.category(this, overview.optString("category")), 13f, muted = true), top = 8)
        page.add(label(overview.optString("title"), 24f, bold = true), top = 2)
        val updaters = mutableListOf<() -> Unit>()

        fun group(fields: org.json.JSONArray?) {
            if (fields == null) return
            val panel = panel()
            var count = 0
            for (i in 0 until fields.length()) {
                val f = fields.getJSONObject(i)
                val value = f.optString("value")
                if (value.isEmpty()) continue
                panel.add(fieldView(f, updaters), top = if (count == 0) 0 else 4)
                count++
            }
            if (count > 0) page.add(panel, top = 16)
        }

        group(details.optJSONArray("fields"))
        val sections = details.optJSONArray("sections")
        if (sections != null) for (i in 0 until sections.length()) {
            val section = sections.getJSONObject(i)
            val title = section.optString("title")
            if (title.isNotEmpty()) page.add(label(title.uppercase(), 12f, bold = true, muted = true), top = 20)
            group(section.optJSONArray("fields"))
        }
        val urls = overview.optJSONArray("urls")
        if (urls != null && urls.length() > 0) {
            page.add(label(getString(R.string.websites).uppercase(), 12f, bold = true, muted = true), top = 20)
            val panel = panel()
            for (i in 0 until urls.length()) {
                val href = urls.getJSONObject(i).optString("href")
                if (href.isEmpty()) continue
                val line = row()
                line.add(label(href, 15f).apply { setTextIsSelectable(true) }, width = 0, weight = 1f)
                val target = if (href.startsWith("http://") || href.startsWith("https://")) href else "https://$href"
                line.add(plainButton(getString(R.string.open)) {
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(target)))
                    } catch (e: Exception) {
                        // No browser.
                    }
                }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                panel.add(line)
            }
            page.add(panel, top = 6)
        }
        val notes = details.optString("notes")
        if (notes.isNotEmpty()) {
            page.add(label(getString(R.string.notes).uppercase(), 12f, bold = true, muted = true), top = 20)
            page.add(panel().apply { add(label(notes, 15f).apply { setTextIsSelectable(true) }) }, top = 6)
        }
        attachmentsSection(page, id, writable && !trashed)
        val tags = overview.optJSONArray("tags")
        if (tags != null && tags.length() > 0) {
            page.add(label(getString(R.string.tags).uppercase(), 12f, bold = true, muted = true), top = 20)
            page.add(label((0 until tags.length()).joinToString(" · ") { tags.getString(it) }, 14f), top = 4)
        }
        val updated = overview.optLong("updated_at")
        if (updated > 0) page.add(label(getString(R.string.modified, DateFormat.getDateTimeInstance().format(Date(updated * 1000))), 12f, muted = true), top = 20)
        if (!writable) page.add(label(getString(R.string.vault_read_only_note), 12f, muted = true), top = 4)
        show("item", page)
        if (updaters.isNotEmpty()) {
            val tick = object : Runnable {
                override fun run() {
                    updaters.forEach { it() }
                    handler.postDelayed(this, 1000)
                }
            }
            ticking = tick
            handler.post(tick)
        }
    }

    private fun fieldView(field: JSONObject, updaters: MutableList<() -> Unit>): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(6), 0, dp(6))
        }
        val name = fieldName(field.optString("label"))
        box.add(label(name, 12f, muted = true))
        val line = row()
        val value = label("", 16f)
        line.add(value, width = 0, weight = 1f)
        val kind = field.optString("kind")
        val secret = field.optString("value")
        when (kind) {
            "totp" -> {
                value.typeface = android.graphics.Typeface.MONOSPACE
                var code = ""
                val update = {
                    try {
                        val answer = Keyless.totp(secret)
                        code = answer.getString("code")
                        value.text = code.chunked((code.length + 1) / 2).joinToString(" ") + "   ·  " + answer.getInt("remaining") + "s"
                    } catch (e: KeylessException) {
                        value.text = "—"
                    }
                }
                update()
                updaters.add(update)
                line.add(plainButton(getString(R.string.copy)) { copy(name, code) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            }
            "concealed", "pin", "card_number", "security_question" -> {
                value.typeface = android.graphics.Typeface.MONOSPACE
                value.text = "••••••••••••"
                var shown = false
                lateinit var toggle: Button
                toggle = plainButton(getString(R.string.show)) {
                    shown = !shown
                    value.text = if (shown) secret else "••••••••••••"
                    toggle.text = getString(if (shown) R.string.hide else R.string.show)
                }
                line.add(toggle, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                line.add(plainButton(getString(R.string.copy)) { copy(name, secret) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            }
            else -> {
                value.text = secret
                value.setTextIsSelectable(true)
                line.add(plainButton(getString(R.string.copy)) { copy(name, secret) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            }
        }
        box.add(line)
        if (kind != "totp") {
            box.setOnLongClickListener {
                val menu = PopupMenu(this, box)
                menu.menu.add(0, 1, 0, R.string.copy)
                menu.menu.add(0, 2, 1, Labels.t(this, "largeType.show"))
                menu.setOnMenuItemClickListener { choice ->
                    if (choice.itemId == 1) copy(name, secret) else showLargeType(secret)
                    true
                }
                menu.show()
                true
            }
        }
        return box
    }

    /** Field labels the apps save in English ("username", "password"...), translated. */
    private fun fieldName(label: String): String = Labels.field(this, label)

    internal fun copy(name: String, value: String) {
        if (value.isEmpty()) return
        val clipboard = getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(CLIP_LABEL, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, getString(R.string.copied, name), Toast.LENGTH_SHORT).show()
        handler.postDelayed({
            try {
                if (clipboard.primaryClipDescription?.label == CLIP_LABEL) clipboard.clearPrimaryClip()
            } catch (e: Exception) {
                // Not readable in the background.
            }
        }, 90_000)
    }

    // ----- settings -----------------------------------------------------------------------

    internal fun showSettings() {
        if (!Keyless.isUnlocked) return route()
        val page = column(20)
        page.add(plainButton("← " + getString(R.string.back)) { showList() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(label(getString(R.string.settings), 24f, bold = true), top = 8)

        if (biometricAvailable()) {
            val toggle = Switch(this).apply {
                text = getString(R.string.biometric_unlock)
                isChecked = SecureStore.biometricEnabled(this@MainActivity)
            }
            toggle.setOnCheckedChangeListener { _, checked ->
                if (!checked) {
                    SecureStore.disableBiometric(this)
                    return@setOnCheckedChangeListener
                }
                val cipher = try {
                    SecureStore.biometricEncryptCipher()
                } catch (e: Exception) {
                    toggle.isChecked = false
                    Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
                    return@setOnCheckedChangeListener
                }
                biometric(getString(R.string.biometric_enable_title), cipher) { authenticated ->
                    if (authenticated == null) {
                        toggle.isChecked = false
                    } else {
                        SecureStore.saveBiometric(this, authenticated, Keyless.exportUserKey())
                    }
                }
            }
            page.add(toggle, top = 20)
            page.add(label(getString(R.string.biometric_unlock_hint), 13f, muted = true), top = 2)
        }

        page.add(label(getString(R.string.auto_lock), 16f, bold = true), top = 24)
        val minutes = RadioGroup(this)
        for (m in listOf(1, 5, 10, 30)) {
            minutes.addView(RadioButton(this).apply {
                text = getString(R.string.minutes, m)
                id = View.generateViewId()
                isChecked = Keyless.autoLockMinutes == m
                setOnClickListener { Keyless.autoLockMinutes = m }
            })
        }
        page.add(minutes, top = 4)
        page.add(Switch(this).apply {
            text = getString(R.string.lock_on_screen_off)
            isChecked = Keyless.lockOnScreenOff
            setOnCheckedChangeListener { _, checked -> Keyless.lockOnScreenOff = checked }
        }, top = 8)

        if (biometricAvailable()) {
            page.add(label(getString(R.string.master_password_every), 16f, bold = true), top = 24)
            val days = RadioGroup(this)
            for (d in listOf(1, 7, 14, 30)) {
                days.addView(RadioButton(this).apply {
                    text = if (d == 1) getString(R.string.every_day) else getString(R.string.every_days, d)
                    id = View.generateViewId()
                    isChecked = Keyless.masterPasswordDays == d
                    setOnClickListener { Keyless.masterPasswordDays = d }
                })
            }
            page.add(days, top = 4)
            page.add(label(getString(R.string.master_password_every_hint), 13f, muted = true), top = 2)
        }

        page.add(label(getString(R.string.theme), 16f, bold = true), top = 24)
        val themes = RadioGroup(this)
        val prefs = getSharedPreferences("keyless", MODE_PRIVATE)
        for ((value, name) in listOf("system" to R.string.theme_system, "light" to R.string.theme_light, "dark" to R.string.theme_dark)) {
            themes.addView(RadioButton(this).apply {
                text = getString(name)
                id = View.generateViewId()
                isChecked = prefs.getString("theme", "system") == value
                setOnClickListener {
                    if (prefs.getString("theme", "system") != value) {
                        prefs.edit().putString("theme", value).apply()
                        reopenSettings = true
                        recreate()
                    }
                }
            })
        }
        page.add(themes, top = 4)

        page.add(label(getString(R.string.autofill), 16f, bold = true), top = 24)
        val autofill = getSystemService(AutofillManager::class.java)
        if (autofill?.hasEnabledAutofillServices() == true) {
            page.add(label(getString(R.string.autofill_on), 14f).apply { setTextColor(accent()) }, top = 4)
        } else {
            page.add(label(getString(R.string.autofill_hint), 13f, muted = true), top = 4)
            page.add(primaryButton(getString(R.string.autofill_enable)) {
                try {
                    startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:$packageName")))
                } catch (e: Exception) {
                    // No autofill settings on this phone.
                }
            }, top = 8)
        }

        if (Build.VERSION.SDK_INT >= 34) {
            page.add(label(getString(R.string.passkeys), 16f, bold = true), top = 24)
            page.add(label(getString(R.string.passkeys_hint), 13f, muted = true), top = 4)
            page.add(primaryButton(getString(R.string.passkeys_enable)) {
                try {
                    startActivity(Intent("android.settings.CREDENTIAL_PROVIDER").setData(Uri.parse("package:$packageName")))
                } catch (e: Exception) {
                    // No such settings screen on this phone.
                }
            }, top = 8)
        }

        signInPasskeysSection(page)

        page.add(label(getString(R.string.account), 16f, bold = true), top = 24)
        page.add(label(Keyless.email, 14f, muted = true), top = 4)
        page.add(plainButton(getString(R.string.devices)) { showDevices() }, width = ViewGroup.LayoutParams.WRAP_CONTENT, top = 4)
        page.add(plainButton(Labels.t(this, "recovery.title")) { showRecoveryKey() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(plainButton(Labels.t(this, "importer.title")) { showImport() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(plainButton(Labels.t(this, "importer.exportDialogTitle")) { showExport() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(plainButton(getString(R.string.sign_out)) {
            android.app.AlertDialog.Builder(this)
                .setTitle(R.string.sign_out)
                .setMessage(R.string.sign_out_body)
                .setPositiveButton(R.string.sign_out) { _, _ -> signOut() }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }, width = ViewGroup.LayoutParams.WRAP_CONTENT, top = 4)
        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: ""
        } catch (e: Exception) {
            ""
        }
        page.add(label(getString(R.string.version, version), 12f, muted = true), top = 24)
        show("settings", page)
    }

    companion object {
        const val CLIP_LABEL = "keyless"
        private const val SCAN_QR = 10

        /** Back to Settings after the theme changed (the screen is made again). */
        private var reopenSettings = false
    }
}
