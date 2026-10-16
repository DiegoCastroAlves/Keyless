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
import android.widget.ImageView
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
/** A secret's value until it is shown. */
private const val HIDDEN = "••••••••••••"

class MainActivity : KeylessActivity() {
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
        if (resultCode != RESULT_OK || content == null) return
        if (callback != null) return callback(content)
        // Android ended Keyless while the scanner (or its file picker) was
        // open, and the callback with it: a new device's code waits for the
        // vault, as when its link is opened.
        if (content.lowercase().startsWith("keyless://sign-in") && Keyless.hasAccount) {
            pendingSignInLink = content
            if (Keyless.isUnlocked) runPending() else route()
        }
    }

    /** The email and Secret Key from a setup link or another device. */
    private var received: Pair<String, String>? = null
    private var notice: String? = null
    internal var query = ""
    internal var filter = "all"

    /** The tab shown (home, items, sentinel), and whether a list was opened from it. */
    internal var tab = "home"
    internal var listOpen = false

    /** The list opened to search (its field first, no title). */
    private var searching = false

    /** The list's other filters (as the desktop's Filter menu) and its order. */
    internal var vaultFilter: String? = null
    internal var tagFilter: String? = null
    internal var passkeyFilter = false
    internal var withPasskeys: Set<String> = emptySet()

    /** Items whose notes or other fields hold the query (searched off the main thread). */
    private var detailMatches: Set<String> = emptySet()
    private var detailSearch: Runnable? = null
    private var deviceRequest: Keyless.DeviceRequest? = null
    private var qrRequest: Keyless.QrSignIn? = null

    /** A new device's sign-in code (keyless://sign-in) opened here, answered once unlocked. */
    private var pendingSignInLink: String? = null
    private var ticking: Runnable? = null

    /** A launcher shortcut's screen, opened once the vault is unlocked. */
    private var pendingAction: String? = null

    private fun takeAction(intent: Intent?) {
        val action = intent?.action ?: return
        if (action.startsWith("$packageName.")) pendingAction = action.removePrefix("$packageName.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
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
        // New website icons: into the letters on screen waiting for them, in
        // place (drawing the screen again would close a menu, lose a tap).
        SiteIcons.changed = { runOnUiThread { root.fillSiteIcons() } }
        handleLink(intent)
        val reopen = reopenSettings
        if (reopen != null && Keyless.isUnlocked) {
            reopenSettings = null
            showSettingsPage(reopen)
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
        if (screen !in AUTH_SCREENS && !Keyless.isUnlocked) route()
        // Back from Android's settings (autofill, passkeys): the steps done since.
        else if (screen == "setup") showSetup()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        if (screen !in AUTH_SCREENS && screen != "none") Keyless.touch()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        when (screen) {
            "item", "settings" -> showMain()
            "list" -> closeList()
            "items", "sentinel" -> showTab("home")
            "new-item" -> showMain()
            "setup", "customize" -> showHome()
            "settings-page" -> showSettings()
            "history" -> showItem(lastItemId)
            "devices", "recovery-key" -> showSettingsPage("account")
            "qr-approve" -> showMain()
            "transfer" -> showSettingsPage("transfer")
            "recover" -> leaveRecovery()
            "sentinel-list" -> showSentinel(null)
            "editor" -> editorBack?.invoke() ?: showMain()
            "device" -> {
                deviceRequest?.let { request -> thread { Keyless.cancelDeviceSetup(request) } }
                deviceRequest = null
                showSignIn()
            }
            "qr-signin" -> {
                stopQrSignIn()
                showSignIn()
            }
            else -> @Suppress("DEPRECATION") super.onBackPressed()
        }
    }

    /** A keyless://setup link fills the sign-in form; a keyless://sign-in one (a new device's code) waits for the vault. */
    private fun handleLink(intent: Intent?): Boolean {
        val data = intent?.data?.toString() ?: return false
        if (data.lowercase().startsWith("keyless://sign-in")) {
            if (Keyless.hasAccount) {
                pendingSignInLink = data
            } else {
                Toast.makeText(this, getString(R.string.qr_sign_in_first), Toast.LENGTH_LONG).show()
            }
            return true
        }
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
            else -> showMain()
        }
    }

    /** Where the vault's screens go back to: the list opened, or the tab under it. */
    internal fun showMain() {
        if (listOpen) showList() else showTab(tab)
    }

    private fun closeList() {
        listOpen = false
        searching = false
        query = ""
        showTab(tab)
    }

    /** A list of the items, filtered (`filter` and the others set before), from a tab. */
    internal fun openList(filter: String, vault: String? = null, tag: String? = null, passkeys: Boolean = false) {
        this.filter = filter
        vaultFilter = vault
        tagFilter = tag
        passkeyFilter = passkeys
        query = ""
        searching = false
        showList()
    }

    /** The search: every item, the field first. */
    internal fun showSearch() {
        filter = "all"
        vaultFilter = null
        tagFilter = null
        passkeyFilter = false
        query = ""
        searching = true
        showList()
    }

    /** The list, kept beside the item on wide screens (tablets, unfolded phones). */
    private var listPage: View? = null

    /** A tab is shown: no list beside the items opened from it. */
    internal fun dropListPage() {
        listPage = null
    }

    private val wide: Boolean get() = resources.configuration.screenWidthDp >= 720

    internal fun show(name: String, view: View, scroll: Boolean = true) {
        ticking?.let { handler.removeCallbacks(it) }
        ticking = null
        if (name != "editor") editorBack = null
        screen = name
        root.removeAllViews()
        (listPage?.parent as? ViewGroup)?.removeView(listPage)
        // Locked or signed out: the list (and its titles) goes.
        if (name in AUTH_SCREENS) listPage = null
        // The desktop's panels: white (or dark gray) screens; the lock screens on the page's gray.
        val auth = name in AUTH_SCREENS
        root.setBackgroundColor(getColor(if (auth) R.color.app_bg else R.color.screen))
        val content = if (scroll) ScrollView(this).apply {
            isFillViewport = true
            addView(view)
        } else view
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
        val email = field(getString(R.string.email), TEXT_EMAIL, autofill = View.AUTOFILL_HINT_EMAIL_ADDRESS)
        email.setText(received?.first ?: "")
        val secretKey = field("K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX", TEXT_KEY, secret = true)
        val password = field(getString(R.string.master_password), TEXT_PASSWORD, autofill = View.AUTOFILL_HINT_PASSWORD)
        val errorLine = label(error ?: "", 14f).apply { setTextColor(getColor(R.color.danger)) }
        form.add(brandHeader(getString(R.string.sign_in_title), getString(R.string.sign_in_intro)))
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
                        tab = "home"
                        listOpen = false
                        showMain()
                        offerBiometric()
                    } else {
                        submit.isEnabled = true
                        submit.text = getString(R.string.sign_in)
                        errorLine.text = errorText(failure)
                    }
                }
            }
        }
        form.add(submit, top = 8)
        form.add(secondaryButton(getString(R.string.with_passkey)) {
            passkeySignIn(errorLine) {
                received = null
                notice = null
                tab = "home"
                listOpen = false
                showMain()
            }
        }, top = 8)
        form.add(plainButton(getString(R.string.qr_sign_in)) { showQrSignIn() }, top = 12)
        form.add(plainButton(getString(R.string.use_other_device)) {
            val address = email.text.toString().trim().lowercase()
            if (!address.contains("@")) {
                errorLine.text = getString(R.string.email_first)
            } else {
                showDevice(address)
            }
        }, top = 4)
        form.addCentered(quietButton(Labels.t(this, "recovery.forgot")) { showRecover() }, top = 4)
        show("signin", form)
    }

    private fun showDevice(email: String) {
        val form = column()
        val status = label(getString(R.string.device_waiting), 15f, muted = true).apply { gravity = android.view.Gravity.CENTER }
        form.add(brandHeader(getString(R.string.use_other_device), getString(R.string.device_body, email)))
        form.add(panel().apply { add(status) }, top = 24)
        form.add(secondaryButton(getString(R.string.cancel)) {
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

    private fun stopQrSignIn() {
        qrRequest?.let { request -> thread { Keyless.cancelQrSignIn(request) } }
        qrRequest = null
    }

    /** A QR code for a signed-in phone to read; back to the form with the Secret Key it sends. */
    private fun showQrSignIn() {
        stopQrSignIn()
        val form = column()
        form.add(brandHeader(getString(R.string.qr_sign_in), null))
        // The code on its own, as wide as the screen lets it be: inside a
        // panel a small phone would leave it too few pixels per module.
        val holder = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val status = label(getString(R.string.syncing), 14f, muted = true).apply { gravity = android.view.Gravity.CENTER }
        val again = secondaryButton(getString(R.string.qr_sign_in_new)) { showQrSignIn() }.apply { visibility = View.GONE }
        form.addCentered(holder, top = 16)
        form.add(status, top = 12)
        form.add(again, top = 12)
        // What to do on the other phone, as the desktop shows it beside its code.
        val box = panel()
        box.add(label(getString(R.string.qr_steps_title), 15f, bold = true))
        for ((n, step) in listOf(R.string.qr_step_open, R.string.qr_step_account, R.string.qr_step_scan).withIndex()) {
            box.add(numberedStep(n + 1, getString(step)), top = 10)
        }
        form.add(box, top = 16)
        form.add(label(getString(R.string.device_password_still), 12f, muted = true).apply { gravity = android.view.Gravity.CENTER }, top = 12)
        form.add(secondaryButton(getString(R.string.cancel)) {
            stopQrSignIn()
            showSignIn()
        }, top = 16)
        show("qr-signin", form)
        val ended = { text: String ->
            runOnUiThread {
                if (screen == "qr-signin") {
                    holder.removeAllViews()
                    status.text = text
                    again.visibility = View.VISIBLE
                }
            }
        }
        thread {
            val request = try {
                Keyless.startQrSignIn()
            } catch (e: Exception) {
                ended(errorText(e))
                return@thread
            }
            qrRequest = request
            val art = Keyless.qrArt(request.link)
            runOnUiThread {
                if (qrRequest !== request) return@runOnUiThread
                // As large as the panel lets it be, up to 280 dp (a narrow phone has less).
                holder.addView(BrandedQrView(this, art, dp(280)), LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
                holder.contentDescription = getString(R.string.qr_sign_in)
                status.text = getString(R.string.qr_sign_in_waiting)
            }
            while (qrRequest === request) {
                Thread.sleep(2000)
                if (qrRequest !== request) return@thread
                val state = try {
                    Keyless.pollQrSignIn(request)
                } catch (e: Exception) {
                    qrRequest = null
                    ended(errorText(e))
                    return@thread
                }
                when (state.getString("status")) {
                    "approved" -> {
                        qrRequest = null
                        runOnUiThread {
                            received = state.getString("email") to state.getString("secretKey")
                            notice = getString(R.string.device_done)
                            showSignIn()
                        }
                        return@thread
                    }
                    "denied", "expired" -> {
                        qrRequest = null
                        ended(getString(if (state.getString("status") == "denied") R.string.qr_sign_in_denied else R.string.qr_sign_in_expired))
                        return@thread
                    }
                }
            }
        }
    }

    // ----- unlocking --------------------------------------------------------------

    private fun showUnlock() {
        show(
            "unlock",
            unlockForm(
                onUnlocked = {
                    showMain()
                    // Not after a biometric unlock: it is on then.
                    offerBiometric()
                },
                onSignOut = { signOut() },
            ),
        )
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

    /** The name of what the list shows (All items, a category, a vault, a tag...). */
    private fun listTitle(): String = when {
        vaultFilter != null -> (0 until Keyless.vaults.length()).map { Keyless.vaults.getJSONObject(it) }.firstOrNull { it.optString("id") == vaultFilter }?.optString("name") ?: getString(R.string.all_items)
        !tagFilter.isNullOrEmpty() -> tagFilter!!
        passkeyFilter -> Labels.t(this, "filters.passkey")
        filter == "favorites" -> getString(R.string.favorites)
        filter == "archive" -> getString(R.string.archived_items)
        filter == "trash" -> getString(R.string.trash)
        filter.startsWith("category:") -> Labels.categoryPlural(this, filter.removePrefix("category:"))
        else -> getString(R.string.all_items)
    }

    internal fun showList() {
        if (!Keyless.isUnlocked) return route()
        listOpen = true
        val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val status = label("", 12f, muted = true).apply { visibility = View.GONE }
        val search = searchField(getString(if (searching) R.string.search_keyless else R.string.search)).apply {
            setText(query)
            background = shape(getColor(R.color.search_pill), 24f)
            minHeight = dp(48)
            setPadding(dp(16), dp(8), dp(16), dp(8))
        }
        val filterButton = iconButton(R.drawable.ic_filter, Labels.t(this, "filters.title")) {}
        val sortButton = iconButton(R.drawable.ic_sort, Labels.t(this, "list.sort.title")) {}
        if (searching) {
            // The search: Back and the field, as one bar.
            val bar = row().apply { setPadding(dp(4), dp(8), dp(12), dp(8)) }
            bar.add(iconButton(R.drawable.ic_back, getString(R.string.back), getColor(R.color.fg)) { closeList() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            bar.add(search, width = 0, weight = 1f)
            page.add(bar)
        } else {
            page.add(topBar(listTitle(), { closeList() }, filterButton, sortButton))
            val line = LinearLayout(this).apply { setPadding(dp(16), 0, dp(16), dp(8)) }
            line.add(search)
            page.add(line)
        }
        val recent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), 0, dp(16), 0)
        }
        page.add(recent)
        val openedHead = row().apply {
            setPadding(dp(16), dp(4), dp(4), 0)
            visibility = View.GONE
        }
        page.add(openedHead)
        page.add(LinearLayout(this).apply { setPadding(dp(16), 0, dp(16), 0); addView(status) })
        val empty = label(getString(R.string.no_results), 14f, muted = true).apply {
            gravity = android.view.Gravity.CENTER
            setPadding(dp(16), dp(32), dp(16), dp(16))
            visibility = View.GONE
        }
        page.add(empty)
        val list = ListView(this).apply {
            divider = null
            selector = pressable(colorDrawable(android.R.color.transparent))
            clipToPadding = false
            setPadding(0, 0, 0, dp(96))
        }
        val adapter = ItemsAdapter()
        list.adapter = adapter
        val area = FrameLayout(this)
        area.addView(list, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        if (!searching && filter != "trash" && Keyless.writableVaults().isNotEmpty()) {
            val fab = Fab(this, getString(R.string.new_item)) { newItem(favorite = filter == "favorites") }
            area.addView(fab, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, android.view.Gravity.BOTTOM or android.view.Gravity.END).apply { setMargins(dp(16), dp(16), dp(16), dp(16)) })
            list.setOnScrollListener(object : android.widget.AbsListView.OnScrollListener {
                private var first = 0
                override fun onScrollStateChanged(view: android.widget.AbsListView?, scrollState: Int) {}
                override fun onScroll(view: android.widget.AbsListView?, firstVisibleItem: Int, visibleItemCount: Int, totalItemCount: Int) {
                    if (firstVisibleItem != first) fab.fold(firstVisibleItem > first)
                    first = firstVisibleItem
                }
            })
        }
        page.addView(area, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        fun showRecent() {
            recent.removeAllViews()
            val searches = recentSearches()
            if (query.isNotEmpty() || !search.hasFocus() || searches.isEmpty()) return
            val head = row()
            head.add(label(Labels.t(this, "list.recentSearches"), 13f, bold = true, muted = true), width = 0, weight = 1f)
            head.add(plainButton(Labels.t(this, "list.clearRecent")) {
                getSharedPreferences("keyless", MODE_PRIVATE).edit().remove("recent_searches").apply()
                recent.removeAllViews()
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            recent.add(head)
            for (text in searches) {
                recent.add(listRow(icon(R.drawable.ic_history, getColor(R.color.subtle), 18), text, null).apply {
                    minimumHeight = dp(48)
                    setPadding(dp(4), 0, dp(4), 0)
                    setOnClickListener { search.setText(text); search.setSelection(text.length) }
                })
            }
        }
        search.setOnFocusChangeListener { _, _ -> showRecent() }
        list.setOnItemClickListener { _, _, position, _ ->
            if (query.trim().length >= 2) rememberSearch(query.trim())
            showItem(adapter.shown[position].id)
        }

        fun refresh() {
            adapter.update()
            // An empty search: the items opened last, under their heading.
            openedHead.removeAllViews()
            openedHead.visibility = if (searching && query.isBlank() && adapter.shown.isNotEmpty()) View.VISIBLE else View.GONE
            if (openedHead.visibility == View.VISIBLE) {
                openedHead.add(label(getString(R.string.recently_used), 13f, bold = true, muted = true), width = 0, weight = 1f)
                openedHead.add(plainButton(getString(R.string.recent_searches_clear)) {
                    forgetOpened()
                    refresh()
                }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            }
            val active = vaultFilter != null || tagFilter != null || passkeyFilter
            filterButton.setImageDrawable(iconDrawable(R.drawable.ic_filter, getColor(if (active) R.color.accent else R.color.muted)))
            filterButton.background = if (active) pressable(shape(getColor(R.color.accent_soft), 10f), 10f) else pressable(null)
            empty.visibility = if (adapter.shown.isEmpty() && query.isNotBlank() || adapter.shown.isEmpty() && !searching) View.VISIBLE else View.GONE
            empty.text = getString(if (query.isEmpty()) R.string.no_items else R.string.no_results)
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                query = s?.toString() ?: ""
                refresh()
                showRecent()
                searchDetailsSoon(query) { refresh() }
            }
        })
        search.setOnEditorActionListener { _, _, _ ->
            if (query.trim().length >= 2) rememberSearch(query.trim())
            false
        }
        filterButton.setOnClickListener { chooseFilters { if (!searching) showList() else refresh() } }
        sortButton.setOnClickListener { chooseSort { adapter.update() } }
        refresh()
        listPage = page
        show("list", page, scroll = false)
        listRefresh = { refresh() }
        if (searching) {
            search.post {
                search.requestFocus()
                getSystemService(android.view.inputmethod.InputMethodManager::class.java)?.showSoftInput(search, 0)
            }
        }
    }

    private var listRefresh: (() -> Unit)? = null

    /** The settings page open (where its screens go back to). */
    internal var settingsPage = ""

    /** The theme changed: the activity is made again, on the same settings page. */
    internal fun reopenSettingsPage(page: String) {
        reopenSettings = page
        recreate()
    }

    internal fun signOutFromSettings() = signOut()

    /** What waited for the vault: a new device's sign-in code opened here, a launcher shortcut. */
    internal fun runPending() {
        pendingSignInLink?.let { link ->
            pendingSignInLink = null
            reviewQrSignIn(link)
        }
        when (pendingAction.also { pendingAction = null }) {
            "SEARCH" -> showSearch()
            "NEW_ITEM" -> if (Keyless.writableVaults().isNotEmpty()) newItem(favorite = false)
            "GENERATOR" -> showGenerator(onUse = null, copy = { copy(getString(R.string.generated_password), it) })
        }
    }

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

    internal fun sync(status: TextView, then: (() -> Unit)? = null) {
        status.text = getString(R.string.syncing)
        status.visibility = View.VISIBLE
        thread {
            val failure = try {
                Keyless.sync()
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                status.text = failure?.let { errorText(it) } ?: ""
                if (status.text.isEmpty()) status.visibility = View.GONE
                if (then != null) then() else if (screen == "list") listRefresh?.invoke()
            }
            // Sentinel's daily downloads and the websites' icons, after the items are fresh.
            if (failure == null) {
                SentinelData.refresh(this, force = false)
                SiteIcons.refresh(this, force = true)
            }
        }
    }

    private inner class ItemsAdapter : BaseAdapter() {
        var shown: List<Summary> = emptyList()

        fun update() {
            // Each word anywhere, case and accents aside (see Search.kt).
            val words = searchWords(query)
            val source = when (filter) {
                "archive" -> Keyless.archived
                "trash" -> Keyless.trashed
                else -> Keyless.items
            }
            val inDetails = if (query.trim().length >= 2) detailMatches else emptySet()
            if (searching && query.isBlank()) {
                val byId = Keyless.items.associateBy { it.id }
                shown = openedIds().mapNotNull { byId[it] }.take(8)
                notifyDataSetChanged()
                return
            }
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
                        val texts = mutableListOf(item.title, item.subtitle)
                        if (urls != null) for (i in 0 until urls.length()) texts.add(urls.getJSONObject(i).optString("href"))
                        if (tags != null) for (i in 0 until tags.length()) texts.add(tags.optString(i))
                        hasWords(words, texts) || item.id in inDetails
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
            val url = item.overview.optJSONArray("urls")?.optJSONObject(0)?.optString("href")
            val star = if (item.favorite) icon(R.drawable.ic_star, getColor(R.color.warning), 16).apply { setPadding(0, 0, dp(4), 0) } else null
            // The list draws the touch feedback (its selector).
            return listRow(itemIcon(item.category, item.title, url), item.title, item.subtitle, star).apply { background = null }
        }
    }

    // ----- an item ---------------------------------------------------------------------

    /** The item shown last (where Back goes from its history). */
    private var lastItemId = ""

    internal fun showItem(id: String) {
        if (!Keyless.isUnlocked) return route()
        lastItemId = id
        noteOpened(id)
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
        val actions = mutableListOf<View>()
        if (writable && !trashed) {
            val favorite = overview.optBoolean("favorite")
            val star = if (favorite) iconButton(R.drawable.ic_star_filled, getString(R.string.unfavorite), getColor(R.color.warning)) {} else iconButton(R.drawable.ic_star, getString(R.string.favorite), getColor(R.color.fg)) {}
            star.setOnClickListener { act({ Keyless.setFavorite(id, !favorite) }) { showItem(id) } }
            actions.add(star)
            actions.add(iconButton(R.drawable.ic_edit, getString(R.string.edit), getColor(R.color.fg)) { editItem(id) })
        }
        if (!trashed) {
            lateinit var more: View
            more = iconButton(R.drawable.ic_more, getString(R.string.more), getColor(R.color.fg)) {
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
                        3 -> act({ Keyless.setTrashed(id, true) }) { showMain() }
                        4 -> showHistory(id, writable)
                        5 -> shareItem(id, title)
                        6 -> showWifiQr(id)
                        7 -> attachFile(id)
                    }
                    true
                }
                menu.show()
            }
            actions.add(more)
        }
        val screen = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        screen.add(topBar(null, { showMain() }, *actions.toTypedArray()))
        val page = column(20).apply { setPadding(dp(16), dp(4), dp(16), dp(28)) }
        screen.add(page)
        // The header, as the desktop's: the item's icon, its title, its category and vault.
        val firstUrl = overview.optJSONArray("urls")?.optJSONObject(0)?.optString("href")
        val header = row().apply { gravity = android.view.Gravity.TOP }
        header.addView(itemIcon(overview.optString("category"), title, firstUrl, 60))
        val names = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(2), 0, 0)
        }
        names.add(label(title, 24f, bold = true).apply { setTextIsSelectable(true) })
        val vaultName = (0 until Keyless.vaults.length()).map { Keyless.vaults.getJSONObject(it) }.firstOrNull { it.optString("id") == item.optString("vaultId") }?.optString("name")
        names.add(label(listOfNotNull(Labels.category(this, overview.optString("category")), vaultName?.ifEmpty { null }).joinToString("  ·  "), 14f, muted = true), top = 2)
        header.addView(names, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        page.add(header)
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
                        .setPositiveButton(R.string.delete_forever) { _, _ -> act({ Keyless.deleteForGood(id) }) { showMain() } }
                        .setNegativeButton(R.string.cancel, null)
                        .show()
                }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                page.add(actions, top = 4)
            }
        } else if (archived) {
            page.add(label(getString(R.string.archived_note), 13f, muted = true), top = 8)
        }
        val updaters = mutableListOf<() -> Unit>()

        fun group(fields: org.json.JSONArray?) {
            if (fields == null) return
            val card = card()
            for (i in 0 until fields.length()) {
                val f = fields.getJSONObject(i)
                if (f.optString("value").isEmpty()) continue
                card.add(fieldView(f, updaters))
            }
            if (card.childCount > 0) page.add(card, top = 16)
        }

        group(details.optJSONArray("fields"))
        val sections = details.optJSONArray("sections")
        if (sections != null) for (i in 0 until sections.length()) {
            val section = sections.getJSONObject(i)
            val title = section.optString("title")
            if (title.isNotEmpty()) page.add(sectionTitle(title), top = 24)
            group(section.optJSONArray("fields"))
        }
        val urls = overview.optJSONArray("urls")
        if (urls != null && urls.length() > 0) {
            page.add(sectionTitle(getString(R.string.websites)), top = 24)
            val card = card()
            for (i in 0 until urls.length()) {
                val href = urls.getJSONObject(i).optString("href")
                if (href.isEmpty()) continue
                val target = if (href.startsWith("http://") || href.startsWith("https://")) href else "https://$href"
                val open = iconButton(R.drawable.ic_external, getString(R.string.open)) {
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(target)))
                    } catch (e: Exception) {
                        // No browser.
                    }
                }
                val copyUrl = iconButton(R.drawable.ic_copy, getString(R.string.copy)) { copy(getString(R.string.websites), href) }
                card.add(fieldRow(urls.getJSONObject(i).optString("label").ifEmpty { Labels.field(this, "website") }, label(href, 16f, muted = false).apply { setTextColor(accent()) }, copyUrl, open))
            }
            page.add(card, top = 8)
        }
        passkeysSection(page, id, details.optJSONArray("passkeys"), writable && !trashed)
        val notes = details.optString("notes")
        if (notes.isNotEmpty()) {
            page.add(sectionTitle(getString(R.string.notes)), top = 24)
            page.add(card().apply { add(label(notes, 15f).apply { setTextIsSelectable(true); setPadding(dp(16), dp(14), dp(16), dp(14)); setLineSpacing(0f, 1.25f) }) }, top = 8)
        }
        attachmentsSection(page, id, writable && !trashed)
        val tags = overview.optJSONArray("tags")
        if (tags != null && tags.length() > 0) {
            page.add(sectionTitle(getString(R.string.tags)), top = 24)
            val chips = row()
            for (i in 0 until tags.length()) {
                chips.addView(label(tags.getString(i), 13f).apply {
                    setTextColor(getColor(R.color.muted))
                    weight(500)
                    background = shape(getColor(R.color.panel), 14f)
                    setPadding(dp(12), dp(6), dp(12), dp(6))
                }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(6) })
            }
            page.add(HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(chips) }, top = 8)
        }
        val updated = overview.optLong("updated_at")
        if (updated > 0) page.add(label(getString(R.string.modified, DateFormat.getDateTimeInstance().format(Date(updated * 1000))), 12f, muted = true).apply { setTextColor(getColor(R.color.subtle)) }, top = 24)
        if (!writable) page.add(label(getString(R.string.vault_read_only_note), 12f, muted = true), top = 4)
        show("item", screen)
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
        val name = fieldName(field.optString("label"))
        val kind = field.optString("kind")
        val secret = field.optString("value")
        val value = label("", 16f)
        var shownValue: View = value
        var toCopy = { secret }
        val actions = mutableListOf<View>()
        when (kind) {
            "totp" -> {
                // The code as the desktop shows it: large, in the accent, red when it is about to change.
                value.typeface = android.graphics.Typeface.create(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD)
                value.textSize = 21f
                value.letterSpacing = 0.08f
                val remaining = label("", 13f, muted = true)
                val line = row()
                line.add(value, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                line.addView(remaining, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dp(12) })
                shownValue = line
                var code = ""
                val update = {
                    try {
                        val answer = Keyless.totp(secret)
                        code = answer.getString("code")
                        val left = answer.getInt("remaining")
                        value.text = code.chunked((code.length + 1) / 2).joinToString(" ")
                        value.setTextColor(getColor(if (left <= 5) R.color.danger else R.color.accent))
                        remaining.text = getString(R.string.seconds_left, left)
                    } catch (e: KeylessException) {
                        value.text = "—"
                    }
                }
                update()
                updaters.add(update)
                toCopy = { code }
            }
            "concealed", "pin", "card_number", "security_question" -> {
                value.typeface = android.graphics.Typeface.MONOSPACE
                value.text = HIDDEN
                var shown = false
                lateinit var toggle: android.widget.ImageButton
                toggle = iconButton(R.drawable.ic_eye, getString(R.string.show)) {
                    shown = !shown
                    value.text = if (!shown) HIDDEN else if (kind == "concealed") passwordText(secret) else secret
                    toggle.setImageDrawable(iconDrawable(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye, getColor(R.color.muted)))
                    toggle.contentDescription = getString(if (shown) R.string.hide else R.string.show)
                    toggle.tooltipText = toggle.contentDescription
                }
                actions.add(toggle)
            }
            else -> {
                value.text = secret
                value.setTextIsSelectable(true)
            }
        }
        actions.add(iconButton(R.drawable.ic_copy, getString(R.string.copy)) { copy(name, toCopy()) })
        val box = fieldRow(name, shownValue, *actions.toTypedArray())
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

    companion object {
        const val CLIP_LABEL = "keyless"
        private const val SCAN_QR = 10

        /** The screens shown signed out or locked. */
        private val AUTH_SCREENS = listOf("signin", "unlock", "device", "qr-signin", "recover")

        /** The settings page to show again after the theme changed (the screen is made again). */
        private var reopenSettings: String? = null
    }
}
