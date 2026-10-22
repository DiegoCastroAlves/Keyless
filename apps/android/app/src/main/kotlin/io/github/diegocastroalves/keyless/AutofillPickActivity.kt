package io.github.diegocastroalves.keyless

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.ScrollView
import android.widget.Toast
import kotlin.concurrent.thread

/**
 * "Search Keyless" in the autofill list: any login for the fields, chosen
 * by the user, those fitting the app or site first (AppLinks). With the
 * switch on, the app (or site) is added to the login, so that the login
 * shows by itself next time. Unlocks first when Keyless locked meanwhile.
 */
class AutofillPickActivity : KeylessActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Keyless.isUnlocked) {
            pick()
            return
        }
        setContentView(ScrollView(this).apply { addView(unlockForm(onUnlocked = { pick() }, onSignOut = null)) })
    }

    private fun pick() {
        val packageName = intent.getStringExtra(EXTRA_PACKAGE)
        val domain = intent.getStringExtra(EXTRA_DOMAIN)
        setContentView(
            loginPicker(packageName, domain, onPick = { login, link -> fill(login, link, packageName, domain) }, onCancel = {
                setResult(RESULT_CANCELED)
                finish()
            }),
        )
    }

    private fun ids(name: String): List<AutofillId> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(name, AutofillId::class.java) ?: emptyList()
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayListExtra<AutofillId>(name) ?: emptyList()
        }

    @Suppress("DEPRECATION")
    private fun fill(login: Summary, link: Boolean, packageName: String?, domain: String?) {
        val item = try {
            Keyless.item(login.id)
        } catch (e: Exception) {
            Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
            return
        }
        val values = AutofillResponses.loginValues(item)
        val dataset = Dataset.Builder()
        if (!AutofillResponses.fillLogin(dataset, values, ids(EXTRA_USERNAMES), ids(EXTRA_PASSWORDS))) {
            Toast.makeText(this, R.string.pick_no_values, Toast.LENGTH_LONG).show()
            return
        }
        Keyless.touch()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
        values.totp?.let { OneTimeCodes.copy(this, login.title, it) }
        if (link) linkInBackground(login.id, packageName, domain)
        finish()
    }

    companion object {
        const val EXTRA_USERNAMES = "usernames"
        const val EXTRA_PASSWORDS = "passwords"
        /** The app asking (null for a web page). */
        const val EXTRA_PACKAGE = "package"
        /** The web page's domain (null in an app). */
        const val EXTRA_DOMAIN = "domain"
    }
}

/** Links the app (or site) to the login, uploading it; says how it went. */
internal fun android.app.Activity.linkInBackground(itemId: String, packageName: String?, domain: String?) {
    val app = applicationContext
    val label = packageName?.let { AppLinks.label(this, it) }
    val name = label ?: packageName ?: domain ?: return
    thread {
        val text = try {
            AppLinks.link(itemId, packageName, domain, label)
            app.getString(R.string.linked_to, name)
        } catch (e: Exception) {
            app.errorText(e)
        }
        Handler(app.mainLooper).post { Toast.makeText(app, text, Toast.LENGTH_SHORT).show() }
    }
}
