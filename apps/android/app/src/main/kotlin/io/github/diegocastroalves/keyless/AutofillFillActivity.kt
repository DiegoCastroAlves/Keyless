package io.github.diegocastroalves.keyless

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.ScrollView

/**
 * A login with a one-time password, chosen in the autofill list: answers
 * with the login to fill and copies the current code, so it is ready to
 * paste on the next screen. It has no screen of its own unless Keyless
 * locked meanwhile and must be unlocked first.
 */
class AutofillFillActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Keyless.isUnlocked) {
            fill()
            return
        }
        val page = ScrollView(this).apply {
            setBackgroundColor(themeColor(android.R.attr.colorBackground))
            addView(unlockForm(onUnlocked = { fill() }, onSignOut = null))
        }
        setContentView(page)
    }

    private fun themeColor(attr: Int): Int {
        val values = obtainStyledAttributes(intArrayOf(attr))
        return try {
            values.getColor(0, 0)
        } finally {
            values.recycle()
        }
    }

    private fun ids(name: String): List<AutofillId> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(name, AutofillId::class.java) ?: emptyList()
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayListExtra<AutofillId>(name) ?: emptyList()
        }

    @Suppress("DEPRECATION")
    private fun fill() {
        val id = intent.getStringExtra(EXTRA_ITEM)
        val item = try {
            if (id == null) null else Keyless.item(id)
        } catch (e: Exception) {
            null
        }
        if (item == null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        Keyless.touch()
        val values = AutofillResponses.loginValues(item)
        val dataset = Dataset.Builder()
        if (!AutofillResponses.fillLogin(dataset, values, ids(EXTRA_USERNAMES), ids(EXTRA_PASSWORDS))) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
        values.totp?.let { OneTimeCodes.copy(this, item.getJSONObject("overview").optString("title"), it) }
        finish()
    }

    companion object {
        const val EXTRA_ITEM = "item"
        const val EXTRA_USERNAMES = "usernames"
        const val EXTRA_PASSWORDS = "passwords"
    }
}
