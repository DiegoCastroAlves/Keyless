package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.ScrollView

/** Unlocks Keyless for autofill, then answers with the logins for the fields. */
class AutofillAuthActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Keyless.isUnlocked) {
            answer()
            return
        }
        setContentView(ScrollView(this).apply { addView(unlockForm(onUnlocked = { answer() }, onSignOut = null)) })
    }

    private fun answer() {
        val structure = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
        val response = structure?.let {
            try {
                AutofillResponses.datasets(this, AutofillParser.parse(it))
            } catch (e: Exception) {
                null
            }
        }
        if (response != null) {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        } else {
            setResult(RESULT_CANCELED)
        }
        finish()
    }
}
