package io.github.diegocastroalves.keyless.formtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * A sign-up form, as an app would have one: the email, a new password
 * (Android's "newPassword" hint) and its confirmation, known only by its
 * hint text. "Create account" says whether both fields hold the same
 * password, and how long it is.
 */
class SignUpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            padded()
        }
        val email = EditText(this).apply {
            hint = "Email"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            setAutofillHints(View.AUTOFILL_HINT_EMAIL_ADDRESS)
        }
        val password = EditText(this).apply {
            hint = "New password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints("newPassword")
        }
        val confirm = EditText(this).apply {
            hint = "Confirm password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val status = TextView(this)
        column.addView(TextView(this).apply { text = "Create an account"; textSize = 22f })
        column.addView(email)
        column.addView(password)
        column.addView(confirm)
        column.addView(Button(this).apply {
            text = "Create account"
            setOnClickListener {
                val made = password.text.toString()
                val same = made.isNotEmpty() && made == confirm.text.toString()
                status.text = "Account created: ${email.text}, " + (if (same) "passwords match (${made.length} characters)" else "passwords differ")
                getSystemService(AutofillManager::class.java)?.commit()
            }
        })
        column.addView(status)
        setContentView(ScrollView(this).apply { addView(column) })
    }
}
