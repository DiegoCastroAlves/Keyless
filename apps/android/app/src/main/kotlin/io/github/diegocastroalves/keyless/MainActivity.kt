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

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
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
    private var deviceRequest: Keyless.DeviceRequest? = null
    private var ticking: Runnable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        route()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (handleLink(intent)) route()
    }

    override fun onResume() {
        super.onResume()
        if (screen != "signin" && screen != "device" && screen != "unlock" && !Keyless.isUnlocked) route()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        if (screen == "list" || screen == "item" || screen == "settings" || screen == "editor" || screen == "devices" || screen.startsWith("sentinel")) Keyless.touch()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        when (screen) {
            "item", "settings" -> showList()
            "devices" -> showSettings()
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

    internal fun show(name: String, view: View, scroll: Boolean = true) {
        ticking?.let { handler.removeCallbacks(it) }
        ticking = null
        if (name != "editor") editorBack = null
        screen = name
        root.removeAllViews()
        root.addView(
            if (scroll) ScrollView(this).apply { addView(view) } else view,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT),
        )
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
        form.add(plainButton(getString(R.string.use_other_device)) {
            val address = email.text.toString().trim().lowercase()
            if (!address.contains("@")) {
                errorLine.text = getString(R.string.email_first)
            } else {
                showDevice(address)
            }
        }, top = 4)
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
        page.add(LinearLayout(this).apply { setPadding(dp(16), 0, dp(16), 0); addView(search, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)) })
        val filters = row().apply { setPadding(dp(12), dp(4), dp(12), dp(4)) }
        page.add(HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(filters) })
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
        list.setOnItemClickListener { _, _, position, _ -> showItem(adapter.shown[position].id) }
        page.addView(list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        fun refresh() {
            adapter.update()
            filters.removeAllViews()
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
            }
        })
        refresh()
        show("list", page, scroll = false)
        if (Keyless.items.isEmpty()) sync(status) { refresh() }
        listRefresh = { refresh() }
    }

    private var listRefresh: (() -> Unit)? = null

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
            shown = source.filter { item ->
                when {
                    filter == "favorites" && !item.favorite -> false
                    filter.startsWith("category:") && item.category != filter.removePrefix("category:") -> false
                    else -> {
                        val urls = item.overview.optJSONArray("urls")
                        val text = buildString {
                            append(item.title).append(' ').append(item.subtitle)
                            if (urls != null) for (i in 0 until urls.length()) append(' ').append(urls.getJSONObject(i).optString("href"))
                        }.lowercase()
                        words.all { text.contains(it) }
                    }
                }
            }
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

    internal fun showItem(id: String) {
        if (!Keyless.isUnlocked) return route()
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
            lateinit var more: Button
            more = plainButton("⋮") {
                val menu = PopupMenu(this, more)
                menu.menu.add(0, 1, 0, R.string.duplicate)
                menu.menu.add(0, 2, 1, if (archived) R.string.unarchive else R.string.archive)
                menu.menu.add(0, 3, 2, R.string.move_to_trash)
                menu.setOnMenuItemClickListener { choice ->
                    when (choice.itemId) {
                        1 -> {
                            var copyId = ""
                            act({ copyId = Keyless.duplicate(id, getString(R.string.copy_title, title)) }) { showItem(copyId) }
                        }
                        2 -> act({ Keyless.setArchived(id, !archived) }) { showItem(id) }
                        3 -> act({ Keyless.setTrashed(id, true) }) { showList() }
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

        page.add(label(getString(R.string.account), 16f, bold = true), top = 24)
        page.add(label(Keyless.email, 14f, muted = true), top = 4)
        page.add(plainButton(getString(R.string.devices)) { showDevices() }, width = ViewGroup.LayoutParams.WRAP_CONTENT, top = 4)
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
    }
}
