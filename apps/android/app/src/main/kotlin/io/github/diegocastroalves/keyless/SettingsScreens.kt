package io.github.diegocastroalves.keyless

import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.view.View
import android.view.ViewGroup
import android.view.autofill.AutofillManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/*
 * Settings: a list of groups (account, general, security, autofill, import
 * and export, about), each with its own page.
 */

/** A settings page: a top bar with Back, and `body` under it. */
private fun MainActivity.settingsScreen(name: String, title: String, back: () -> Unit, body: LinearLayout) {
    val page = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(topBar(title, back))
    body.setPadding(dp(16), dp(4), dp(16), dp(24))
    page.addView(ScrollView(this).apply {
        isFillViewport = true
        addView(body)
    }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    show(name, page, scroll = false)
}

private fun MainActivity.vertical(): LinearLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

/** A group's padding for what is not a row (switches, choices, texts). */
private fun LinearLayout.padded(): LinearLayout = apply { setPadding(context.dp(16), context.dp(10), context.dp(16), context.dp(12)) }

internal fun MainActivity.showSettings() {
    if (!Keyless.isUnlocked) return route()
    settingsPage = ""
    val body = vertical()
    val me = group()
    val avatar = accountButton(Keyless.email, getString(R.string.account), null)
    me.add(groupRow(avatar, Keyless.email, getString(R.string.account)) { showSettingsPage("account") })
    body.add(me, top = 8)

    val main = group()
    main.add(groupRow(roundIcon(R.drawable.ic_settings, Hues.blue, 36), getString(R.string.settings_general)) { showSettingsPage("general") })
    main.add(groupRow(roundIcon(R.drawable.ic_lock, Hues.amber, 36), getString(R.string.settings_security)) { showSettingsPage("security") })
    main.add(groupRow(roundIcon(R.drawable.ic_autofill, Hues.slate, 36), getString(R.string.autofill)) { showSettingsPage("autofill") })
    body.add(main, top = 12)

    val data = group()
    data.add(groupRow(roundIcon(R.drawable.ic_file_down, Hues.violet, 36), getString(R.string.settings_transfer)) { showSettingsPage("transfer") })
    body.add(data, top = 12)

    val about = group()
    about.add(groupRow(roundIcon(R.drawable.ic_info, Hues.cyan, 36), getString(R.string.settings_about)) { showSettingsPage("about") })
    body.add(about, top = 12)
    settingsScreen("settings", getString(R.string.settings), { showMain() }, body)
}

/** One group of the settings: "account", "general", "security", "autofill", "transfer" or "about". */
internal fun MainActivity.showSettingsPage(id: String) {
    if (!Keyless.isUnlocked) return route()
    settingsPage = id
    val body = vertical()
    val title = when (id) {
        "account" -> {
            accountPage(body)
            getString(R.string.account)
        }
        "general" -> {
            generalPage(body)
            getString(R.string.settings_general)
        }
        "security" -> {
            securityPage(body)
            getString(R.string.settings_security)
        }
        "autofill" -> {
            autofillPage(body)
            getString(R.string.autofill)
        }
        "transfer" -> {
            val card = group()
            card.add(groupRow(roundIcon(R.drawable.ic_file_down, Hues.violet, 36), Labels.t(this, "importer.title")) { showImport() })
            card.add(groupRow(roundIcon(R.drawable.ic_file_up, Hues.indigo, 36), Labels.t(this, "importer.exportDialogTitle")) { showExport() })
            body.add(card, top = 8)
            getString(R.string.settings_transfer)
        }
        else -> {
            aboutPage(body)
            getString(R.string.settings_about)
        }
    }
    settingsScreen("settings-page", title, { showSettings() }, body)
}

private fun MainActivity.accountPage(body: LinearLayout) {
    val card = group()
    card.add(groupRow(roundIcon(R.drawable.ic_user, Hues.slate, 36), Keyless.email, null))
    card.add(groupRow(roundIcon(R.drawable.ic_smartphone, Hues.indigo, 36), getString(R.string.devices)) { showDevices() })
    card.add(groupRow(roundIcon(R.drawable.ic_scan, Hues.teal, 36), getString(R.string.sign_in_other)) { signInOnOtherDevice() })
    card.add(groupRow(roundIcon(R.drawable.ic_shield, Hues.green, 36), Labels.t(this, "recovery.title")) { showRecoveryKey() })
    body.add(card, top = 8)

    signInPasskeysSection(body)

    val out = group()
    out.add(groupRow(roundIcon(R.drawable.ic_log_out, Hues.red, 36), getString(R.string.sign_out)) {
        AlertDialog.Builder(this)
            .setTitle(R.string.sign_out)
            .setMessage(R.string.sign_out_body)
            .setPositiveButton(R.string.sign_out) { _, _ -> signOutFromSettings() }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }.apply { ((getChildAt(1) as LinearLayout).getChildAt(0) as TextView).setTextColor(getColor(R.color.danger)) })
    body.add(out, top = 16)
}

private fun MainActivity.generalPage(body: LinearLayout) {
    body.add(heading(getString(R.string.theme)), top = 4)
    val themes = RadioGroup(this)
    val prefs = getSharedPreferences("keyless", android.content.Context.MODE_PRIVATE)
    for ((value, name) in listOf("system" to R.string.theme_system, "light" to R.string.theme_light, "dark" to R.string.theme_dark)) {
        themes.addView(RadioButton(this).apply {
            text = getString(name)
            id = View.generateViewId()
            minHeight = dp(44)
            isChecked = prefs.getString("theme", "system") == value
            setOnClickListener {
                if (prefs.getString("theme", "system") != value) {
                    prefs.edit().putString("theme", value).apply()
                    reopenSettingsPage("general")
                }
            }
        })
    }
    body.add(group().padded().apply { add(themes) })

    val icons = group().padded()
    icons.add(Switch(this).apply {
        text = getString(R.string.site_icons)
        minHeight = dp(44)
        isChecked = SiteIcons.enabled(this@generalPage)
        setOnCheckedChangeListener { _, on -> SiteIcons.setEnabled(this@generalPage, on) }
    })
    icons.add(label(getString(R.string.site_icons_hint), 13f, muted = true), top = 2)
    body.add(icons, top = 16)
}

private fun MainActivity.securityPage(body: LinearLayout) {
    val unlocking = group().padded()
    if (biometricAvailable()) {
        val toggle = Switch(this).apply {
            text = getString(R.string.biometric_unlock)
            minHeight = dp(44)
            isChecked = SecureStore.biometricEnabled(this@securityPage)
        }
        toggle.setOnCheckedChangeListener { _, checked ->
            if (!checked) {
                SecureStore.disableBiometric(this)
                return@setOnCheckedChangeListener
            }
            enableBiometric { on -> if (!on) toggle.isChecked = false }
        }
        unlocking.add(toggle)
        unlocking.add(label(getString(R.string.biometric_unlock_hint), 13f, muted = true), top = 2)
    }
    unlocking.add(Switch(this).apply {
        text = getString(R.string.lock_on_screen_off)
        minHeight = dp(44)
        isChecked = Keyless.lockOnScreenOff
        setOnCheckedChangeListener { _, checked -> Keyless.lockOnScreenOff = checked }
    }, top = if (unlocking.childCount > 0) 8 else 0)
    body.add(heading(getString(R.string.settings_unlocking)), top = 4)
    body.add(unlocking)

    body.add(heading(getString(R.string.auto_lock)), top = 16)
    val minutes = RadioGroup(this)
    for (m in listOf(1, 5, 10, 30)) {
        minutes.addView(RadioButton(this).apply {
            text = resources.getQuantityString(R.plurals.minutes, m, m)
            id = View.generateViewId()
            minHeight = dp(44)
            isChecked = Keyless.autoLockMinutes == m
            setOnClickListener { Keyless.autoLockMinutes = m }
        })
    }
    body.add(group().padded().apply { add(minutes) })

    if (biometricAvailable()) {
        body.add(heading(getString(R.string.master_password_every)), top = 16)
        val days = RadioGroup(this)
        for (d in listOf(1, 7, 14, 30)) {
            days.addView(RadioButton(this).apply {
                text = if (d == 1) getString(R.string.every_day) else getString(R.string.every_days, d)
                id = View.generateViewId()
                minHeight = dp(44)
                isChecked = Keyless.masterPasswordDays == d
                setOnClickListener { Keyless.masterPasswordDays = d }
            })
        }
        body.add(group().padded().apply {
            add(days)
            add(label(getString(R.string.master_password_every_hint), 13f, muted = true), top = 4)
        })
    }
}

/** Whether a step is on: a check and "On", or the button that turns it on. */
private fun MainActivity.stepState(on: Boolean, start: () -> Unit): View = if (on) {
    row().apply {
        addView(icon(R.drawable.ic_check, getColor(R.color.success), 18))
        addView(label(getString(R.string.step_on), 14f).apply {
            setTextColor(getColor(R.color.success))
            setPadding(dp(6), 0, dp(8), 0)
        })
    }
} else {
    plainButton(getString(R.string.turn_on)) { start() }
}

private fun MainActivity.autofillPage(body: LinearLayout) {
    val autofill = getSystemService(AutofillManager::class.java)
    val card = group()
    val fillOn = autofill?.hasEnabledAutofillServices() == true
    card.add(groupRow(roundIcon(R.drawable.ic_autofill, Hues.blue, 36), getString(R.string.autofill), getString(if (fillOn) R.string.autofill_on else R.string.autofill_hint), stepState(fillOn) {
        try {
            startActivity(Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:$packageName")))
        } catch (e: Exception) {
            // No autofill settings on this phone.
        }
    }).wrapSubtitle(4))
    if (Build.VERSION.SDK_INT >= 34) {
        card.add(groupRow(roundIcon(R.drawable.ic_cat_login, Hues.amber, 36), getString(R.string.passkeys), getString(R.string.passkeys_hint), stepState(passkeysOn()) {
            try {
                startActivity(Intent("android.settings.CREDENTIAL_PROVIDER").setData(Uri.parse("package:$packageName")))
            } catch (e: Exception) {
                // No such settings screen on this phone.
            }
        }).wrapSubtitle(5))
    }
    body.add(card, top = 8)
}

private fun MainActivity.aboutPage(body: LinearLayout) {
    val version = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: ""
    } catch (e: Exception) {
        ""
    }
    val card = group()
    val logo = ImageView(this).apply {
        setImageDrawable(getDrawable(R.mipmap.ic_launcher))
        layoutParams = LinearLayout.LayoutParams(dp(40), dp(40))
    }
    card.add(groupRow(logo, getString(R.string.app_name), getString(R.string.version, version)))
    card.add(groupRow(roundIcon(R.drawable.ic_shield, Hues.green, 36), getString(R.string.privacy_policy), null, icon(R.drawable.ic_external, getColor(R.color.subtle), 18)) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.privacy_url))))
        } catch (e: Exception) {
            // No browser.
        }
    })
    card.add(groupRow(roundIcon(R.drawable.ic_info, Hues.slate, 36), getString(R.string.about_licenses)) { showLicenses() })
    body.add(card, top = 8)
}

/** The licenses of what the app ships (the Inter font, the Lucide icons). */
private fun MainActivity.showLicenses() {
    val text = try {
        assets.list("licenses").orEmpty().sorted().joinToString("\n\n") { name -> assets.open("licenses/$name").bufferedReader().use { it.readText() }.trim() }
    } catch (e: Exception) {
        ""
    }
    val view = label(text, 12f, muted = true).apply {
        setPadding(dp(20), dp(12), dp(20), dp(12))
        setTextIsSelectable(true)
    }
    AlertDialog.Builder(this)
        .setTitle(R.string.about_licenses)
        .setView(ScrollView(this).apply { addView(view) })
        .setPositiveButton(Labels.t(this, "common.close"), null)
        .show()
}
