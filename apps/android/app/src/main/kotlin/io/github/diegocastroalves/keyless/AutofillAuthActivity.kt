package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.ScrollView
import android.widget.Toast
import kotlin.concurrent.thread

/**
 * Unlocks Keyless for autofill, then answers with the logins for the
 * fields, or saves the login that was typed.
 */
class AutofillAuthActivity : KeylessActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val done = { if (intent.getBooleanExtra(EXTRA_SAVE, false)) save() else answer() }
        if (Keyless.isUnlocked) {
            done()
            return
        }
        setContentView(ScrollView(this).apply { addView(unlockForm(onUnlocked = done, onSignOut = null)) })
    }

    private fun save() {
        val pending = Keyless.pendingSave
        Keyless.pendingSave = null
        if (pending == null) {
            finish()
            return
        }
        thread {
            val result = try {
                Keyless.saveLogin(pending.domain, pending.packageName, pending.title, pending.username, pending.password)
                getString(R.string.saved)
            } catch (e: Exception) {
                errorText(e)
            }
            runOnUiThread {
                Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun answer() {
        val structure = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
        // The keyboard's request for chips, when it made one.
        val inline = when {
            !AutofillCheck.inlineEnabled(this) -> null
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU ->
                intent.getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST, android.view.inputmethod.InlineSuggestionsRequest::class.java)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                @Suppress("DEPRECATION")
                intent.getParcelableExtra<android.view.inputmethod.InlineSuggestionsRequest>(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST)
            else -> null
        }
        thread {
            val response = structure?.let {
                try {
                    AutofillResponses.datasets(this, AutofillParser.parse(it), inline)
                } catch (e: Exception) {
                    null
                }
            }
            runOnUiThread {
                if (response != null) {
                    setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
                } else {
                    setResult(RESULT_CANCELED)
                }
                finish()
            }
        }
    }

    companion object {
        const val EXTRA_SAVE = "save"
    }
}
