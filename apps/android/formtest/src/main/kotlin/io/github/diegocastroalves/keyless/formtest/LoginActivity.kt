package io.github.diegocastroalves.keyless.formtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** A sign-in form, as an app would have one. "Log in" ends the form (autofill then offers to save). */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 160, 48, 48)
        }
        val username = EditText(this).apply {
            hint = "Username"
            inputType = InputType.TYPE_CLASS_TEXT
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
        }
        val password = EditText(this).apply {
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
        }
        val status = TextView(this)
        val login = Button(this).apply {
            text = "Log in"
            setOnClickListener {
                status.text = "Logged in as ${username.text}"
                getSystemService(AutofillManager::class.java)?.commit()
            }
        }
        column.addView(TextView(this).apply { text = "Example sign-in"; textSize = 22f })
        column.addView(username)
        column.addView(password)
        column.addView(login)
        column.addView(status)
        setContentView(column)
    }
}
