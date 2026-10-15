package io.github.diegocastroalves.keyless

import android.Manifest
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.autofill.AutofillManager
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.Toast

/** Whether suggestions go to the keyboard, and what the autofill check screen reads. */
object AutofillCheck {
    private fun prefs(context: Context) = context.getSharedPreferences("keyless", Context.MODE_PRIVATE)

    /**
     * Suggestions as chips in keyboards that show them; on unless the user
     * turns them off. Test builds (pointed at the fake server over http)
     * start with them off: UIAutomator cannot read a keyboard's chips (its
     * dump of every window fails on them), and full_run.py looks for the
     * list. autofill_run.py turns them on.
     */
    fun inlineEnabled(context: Context): Boolean = prefs(context).getBoolean("inline_suggestions", !BuildConfig.SERVER.startsWith("http://"))

    fun setInlineEnabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean("inline_suggestions", enabled).apply()
    }

    fun noteInlineRequest(context: Context, asked: Boolean) {
        val keyboard = Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: ""
        prefs(context).edit().putInt("inline_asked", if (asked) 1 else 0).putString("inline_keyboard", keyboard).apply()
    }

    /** 1 asked, 0 did not, -1 unknown (no fill yet, or another keyboard since). */
    fun inlineAsked(context: Context): Int {
        val keyboard = Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: ""
        val prefs = prefs(context)
        return if (prefs.getString("inline_keyboard", null) == keyboard) prefs.getInt("inline_asked", -1) else -1
    }

    /** The Chrome channels installed. */
    val chromes = listOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary")

    /**
     * Whether Chrome lets another autofill service fill ("Autofill using
     * another service"): true, false, or null when this Chrome does not say
     * (before version 135).
     */
    fun chromeUsesOtherService(context: Context, chrome: String): Boolean? = try {
        val uri = Uri.Builder().scheme("content").authority("$chrome.AutofillThirdPartyModeContentProvider").path("autofill_third_party_mode").build()
        context.contentResolver.query(uri, arrayOf("autofill_third_party_state"), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getInt(cursor.getColumnIndexOrThrow("autofill_third_party_state")) == 1 else null
        }
    } catch (e: Exception) {
        null
    }
}

/**
 * Autofill check: whether Keyless is the autofill service and the
 * Credential Manager provider, whether the keyboard can show its
 * suggestions, whether it may notify, and how to let it fill in Chrome,
 * with a button to each setting. Nothing in it is secret: it needs no
 * unlocking.
 */
class AutofillCheckActivity : Activity() {
    private lateinit var root: FrameLayout

    /** The scroll a drawing has yet to restore (it waits for its layout). */
    private var restoring = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) window.setDecorFitsSystemWindows(false)
        root = FrameLayout(this)
        root.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars())
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            }
            insets
        }
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun open(vararg intents: Intent) {
        for (intent in intents) {
            try {
                startActivity(intent)
                return
            } catch (e: Exception) {
                // Not on this phone: the next one.
            }
        }
        Toast.makeText(this, R.string.check_no_settings, Toast.LENGTH_SHORT).show()
    }

    private fun section(page: LinearLayout, title: Int, ok: Boolean?, status: String, body: String?, buttons: List<Pair<String, () -> Unit>>, extra: View? = null) {
        val box = panel()
        box.add(label(getString(title), 16f, bold = true), top = 6)
        val mark = when (ok) {
            true -> "✓ "
            false -> "✗ "
            null -> ""
        }
        box.add(
            label(mark + status, 14f).apply {
                when (ok) {
                    true -> setTextColor(accent())
                    false -> setTextColor(getColor(R.color.danger))
                    null -> {}
                }
            },
            top = 4,
        )
        if (!body.isNullOrEmpty()) box.add(label(body, 13f, muted = true), top = 4)
        if (extra != null) box.add(extra, top = 8)
        for ((text, action) in buttons) box.add(plainButton(text, action), width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(box, top = 16)
    }

    private fun render() {
        val page = column(20)
        page.add(plainButton("← " + getString(R.string.back)) { finish() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(label(getString(R.string.check_title), 24f, bold = true), top = 8)
        page.add(label(getString(R.string.check_intro), 14f, muted = true), top = 4)
        val packageUri = Uri.parse("package:$packageName")
        val providerSettings = Intent("android.settings.CREDENTIAL_PROVIDER").setData(packageUri)

        // The autofill service.
        val autofill = getSystemService(AutofillManager::class.java)
        val isService = autofill?.hasEnabledAutofillServices() == true
        val serviceButtons = ArrayList<Pair<String, () -> Unit>>()
        if (!isService) {
            serviceButtons.add(getString(R.string.check_service_button) to { open(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(packageUri)) })
        } else if (Build.VERSION.SDK_INT >= 34) {
            serviceButtons.add(getString(R.string.check_service_change) to { open(providerSettings) })
        }
        section(
            page, R.string.check_service_title, isService,
            getString(if (isService) R.string.check_service_on else if (autofill?.isAutofillSupported == false) R.string.check_service_unsupported else R.string.check_service_off),
            getString(R.string.check_service_body), serviceButtons,
        )

        // Credential Manager.
        if (Build.VERSION.SDK_INT >= 34) {
            val manager = getSystemService(android.credentials.CredentialManager::class.java)
            val enabled = try {
                manager?.isEnabledCredentialProviderService(ComponentName(this, KeylessCredentialService::class.java)) == true
            } catch (e: Exception) {
                false
            }
            section(
                page, R.string.check_provider_title, enabled, getString(if (enabled) R.string.check_provider_on else R.string.check_provider_off),
                getString(R.string.check_provider_body), listOf(getString(R.string.check_provider_button) to { open(providerSettings) }),
            )
        } else {
            section(page, R.string.check_provider_title, null, getString(R.string.check_provider_old), null, emptyList())
        }

        // Suggestions in the keyboard.
        val keyboardButton = listOf(getString(R.string.check_keyboard_button) to { open(Intent(Settings.ACTION_INPUT_METHOD_SETTINGS)) })
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val keyboard = keyboardName()
            val enabled = AutofillCheck.inlineEnabled(this)
            val asked = AutofillCheck.inlineAsked(this)
            val status = when {
                !enabled -> getString(R.string.check_inline_off)
                asked == 1 -> getString(R.string.check_inline_yes, keyboard)
                asked == 0 -> getString(R.string.check_inline_no, keyboard)
                else -> getString(R.string.check_inline_unknown, keyboard)
            }
            val toggle = Switch(this).apply {
                text = getString(R.string.check_inline_switch)
                isChecked = enabled
                setOnCheckedChangeListener { _, checked ->
                    AutofillCheck.setInlineEnabled(this@AutofillCheckActivity, checked)
                    render()
                }
            }
            section(page, R.string.check_inline_title, if (!enabled || asked == -1) null else asked == 1, status, getString(R.string.check_inline_body), keyboardButton, toggle)
        } else {
            section(page, R.string.check_inline_title, null, getString(R.string.check_inline_old), null, keyboardButton)
        }

        // Notifications.
        val allowed = OneTimeCodes.notificationsAllowed(this)
        val notificationSettings = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
        val notifyButtons = ArrayList<Pair<String, () -> Unit>>()
        if (!allowed) {
            val canAsk = Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED &&
                (!askedForNotifications() || shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS))
            if (canAsk) {
                notifyButtons.add(getString(R.string.check_notifications_button) to { askForNotifications() })
            } else {
                notifyButtons.add(getString(R.string.check_notifications_settings) to { open(notificationSettings) })
            }
        }
        section(page, R.string.check_notifications_title, allowed, getString(if (allowed) R.string.check_notifications_on else R.string.check_notifications_off), getString(R.string.check_notifications_body), notifyButtons)

        // Chrome.
        val installed = AutofillCheck.chromes.filter { installed(it) }
        val states = installed.map { AutofillCheck.chromeUsesOtherService(this, it) }
        val known = states.filterNotNull()
        val (chromeOk, chromeStatus) = when {
            installed.isEmpty() -> null to getString(R.string.check_chrome_absent)
            known.isEmpty() -> null to getString(R.string.check_chrome_unknown)
            known.all { it } -> true to getString(R.string.check_chrome_on)
            else -> false to getString(R.string.check_chrome_off)
        }
        val chromeButtons = if (installed.isEmpty()) emptyList() else listOf(getString(R.string.check_chrome_button) to { openChrome(installed.first()) })
        section(page, R.string.check_chrome_title, chromeOk, chromeStatus, getString(R.string.check_chrome_body), chromeButtons)

        // Drawn again after each change: where the reader was stays in view
        // (also when drawn twice before the first one's layout, as after the
        // notification permission: its answer, then onResume).
        val scrolled = restoring.takeIf { it > 0 } ?: (root.getChildAt(0) as? ScrollView)?.scrollY ?: 0
        val scroll = ScrollView(this).apply { addView(page) }
        root.removeAllViews()
        root.addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        root.requestApplyInsets()
        if (scrolled > 0) {
            restoring = scrolled
            scroll.addOnLayoutChangeListener(object : View.OnLayoutChangeListener {
                override fun onLayoutChange(v: View, left: Int, top: Int, right: Int, bottom: Int, oldLeft: Int, oldTop: Int, oldRight: Int, oldBottom: Int) {
                    scroll.removeOnLayoutChangeListener(this)
                    scroll.scrollTo(0, scrolled)
                    restoring = 0
                }
            })
        }
    }

    private fun installed(packageName: String): Boolean = try {
        packageManager.getPackageInfo(packageName, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    private fun keyboardName(): String {
        val id = Settings.Secure.getString(contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD) ?: return "?"
        val pkg = ComponentName.unflattenFromString(id)?.packageName ?: return id
        return try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) {
            pkg
        }
    }

    /** Chrome's "Autofill services" settings (Chrome 135+), or Chrome itself. */
    private fun openChrome(chrome: String) {
        val settings = Intent(Intent.ACTION_APPLICATION_PREFERENCES)
            .addCategory(Intent.CATEGORY_DEFAULT)
            .addCategory(Intent.CATEGORY_APP_BROWSER)
            .addCategory(Intent.CATEGORY_PREFERENCE)
            .setPackage(chrome)
        val launch = packageManager.getLaunchIntentForPackage(chrome)
        if (launch != null) open(settings, launch) else open(settings)
    }

    private fun askedForNotifications(): Boolean = getSharedPreferences("keyless", Context.MODE_PRIVATE).getBoolean("notifications_asked", false)

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT < 33) return
        getSharedPreferences("keyless", Context.MODE_PRIVATE).edit().putBoolean("notifications_asked", true).apply()
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        render()
    }

    companion object {
        /** Opens the screen (for MainActivity's settings). */
        fun open(context: Context) {
            context.startActivity(Intent(context, AutofillCheckActivity::class.java))
        }
    }
}
