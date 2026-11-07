package io.github.diegocastroalves.keyless

import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * "Suggest a strong password" in the autofill list, for a new account or a
 * new password: one made by the generator (its kind as last chosen, here
 * or in the generator) that the field and the web page's site take
 * (Keyless.suggestPassword). Using it saves the login first, so the
 * password is never lost when the form is not sent or Android does not
 * offer to save; then it fills the password, its confirmation and the
 * username when one is typed here. Unlocks first when Keyless locked
 * meanwhile.
 */
class AutofillSuggestActivity : KeylessActivity() {
    private var options = JSONObject()
    private var password = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Keyless.isUnlocked) {
            show()
            return
        }
        setContentView(ScrollView(this).apply { addView(unlockForm(onUnlocked = { show() }, onSignOut = null)) })
    }

    private fun ids(name: String): List<AutofillId> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(name, AutofillId::class.java) ?: emptyList()
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableArrayListExtra<AutofillId>(name) ?: emptyList()
        }

    private fun show() {
        val packageName = intent.getStringExtra(EXTRA_PACKAGE)
        val domain = intent.getStringExtra(EXTRA_DOMAIN)
        val maxLength = intent.getIntExtra(EXTRA_MAX_LENGTH, 0)
        val digits = intent.getBooleanExtra(EXTRA_DIGITS, false)
        val appName = packageName?.let { AppLinks.label(this, it) ?: it }
        val target = appName ?: domain ?: ""
        val prefs = getSharedPreferences("keyless", Context.MODE_PRIVATE)
        val saved = try {
            JSONObject(prefs.getString("generator", null) ?: "{}")
        } catch (e: Exception) {
            JSONObject()
        }
        // The generator's options for a kind, when it was the last one used.
        fun optionsFor(kind: String): JSONObject = when {
            saved.optString("kind") == kind -> JSONObject(saved.toString())
            kind == "memorable" -> JSONObject().put("kind", kind).put("words", 4)
            kind == "pin" -> JSONObject().put("kind", kind).put("length", 6)
            else -> JSONObject().put("kind", "random").put("length", 24)
        }
        // A field for digits only takes a PIN.
        options = optionsFor(if (digits) "pin" else saved.optString("kind", "random"))

        val page = column(20)
        page.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        page.add(brandHeader(getString(R.string.suggest_title), if (target.isEmpty()) null else getString(R.string.suggest_for, target)))

        val shown = label("", 20f).apply {
            typeface = Typeface.MONOSPACE
            contentDescription = getString(R.string.generated_password)
        }
        val note = label("", 13f, muted = true)
        val again = iconButton(R.drawable.ic_refresh, getString(R.string.regenerate)) {}
        val line = row().apply {
            addView(shown, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(again, LinearLayout.LayoutParams(dp(44), dp(44)).apply { marginStart = dp(4) })
        }
        page.add(panel().apply {
            add(line)
            add(note, top = 4)
        }, top = 12)

        fun suggest() {
            val made = try {
                Keyless.suggestPassword(JSONObject(options.toString()), maxLength, domain)
            } catch (e: Exception) {
                null
            }
            password = made?.optString("password") ?: ""
            shown.text = passwordText(password)
            val adjusted = if (made == null || made.isNull("adjusted")) null else made.optString("adjusted")
            note.text = when (adjusted) {
                "length" -> getString(R.string.suggest_length, maxLength)
                "rules" -> getString(R.string.suggest_rules)
                else -> ""
            }
            note.visibility = if (note.text.isEmpty()) View.GONE else View.VISIBLE
        }
        again.setOnClickListener { suggest() }

        if (!digits) {
            val kinds = row()
            fun renderKinds() {
                kinds.removeAllViews()
                for ((kind, text) in listOf("random" to R.string.gen_random, "memorable" to R.string.gen_memorable, "pin" to R.string.gen_pin)) {
                    val chip = chip(getString(text), options.optString("kind") == kind) {
                        options = optionsFor(kind)
                        // As the generator keeps them: the kind used next time.
                        prefs.edit().putString("generator", options.toString()).apply()
                        renderKinds()
                        suggest()
                    }
                    kinds.addView(chip, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginEnd = dp(8) })
                }
            }
            renderKinds()
            page.add(kinds, top = 12)
        }

        // What the app's username field holds is not sent with a fill request
        // (only with a save request): typed here, or added when Android
        // offers to save once the form is sent (Keyless.saveLogin).
        val username = field(getString(R.string.suggest_username), TEXT_EMAIL)
        if (intent.getBooleanExtra(EXTRA_CHANGE, false)) {
            // A new password for the one login there: saved to it.
            thread {
                val logins = try {
                    if (domain != null) Keyless.matches(domain, null) else AppSites.logins(this, packageName ?: "")
                } catch (e: Exception) {
                    emptyList()
                }
                val only = logins.singleOrNull()?.subtitle?.ifEmpty { null } ?: return@thread
                runOnUiThread { if (username.text.isEmpty()) username.setText(only) }
            }
        }
        page.add(username, top = 16)
        page.add(label(getString(R.string.suggest_note), 13f, muted = true), top = 12)
        val error = label("", 14f).apply {
            setTextColor(getColor(R.color.danger))
            visibility = View.GONE
        }
        page.add(error, top = 8)
        lateinit var use: TextView
        use = primaryButton(getString(R.string.suggest_use)) {
            if (password.isEmpty()) return@primaryButton
            use.isEnabled = false
            error.visibility = View.GONE
            val name = username.text.toString().trim()
            val chosen = password
            thread {
                val failure = try {
                    val id = Keyless.saveLogin(domain, if (domain == null) packageName else null, domain ?: appName ?: "", name, chosen)
                    if (id != null) Keyless.suggested = Keyless.Suggested(id, chosen, System.currentTimeMillis())
                    null
                } catch (e: Exception) {
                    e
                }
                runOnUiThread {
                    if (failure != null) {
                        error.text = errorText(failure)
                        error.visibility = View.VISIBLE
                        use.isEnabled = true
                    } else {
                        fill(name, chosen)
                    }
                }
            }
        }
        page.add(use, top = 12)
        page.add(plainButton(getString(R.string.cancel)) {
            setResult(RESULT_CANCELED)
            finish()
        }, top = 4)
        suggest()
        setContentView(ScrollView(this).apply { addView(page) })
    }

    @Suppress("DEPRECATION")
    private fun fill(username: String, password: String) {
        val dataset = Dataset.Builder()
        if (username.isNotEmpty()) ids(EXTRA_USERNAMES).forEach { dataset.setValue(it, AutofillValue.forText(username)) }
        ids(EXTRA_PASSWORDS).forEach { dataset.setValue(it, AutofillValue.forText(password)) }
        Keyless.touch()
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
        Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show()
        finish()
    }

    companion object {
        const val EXTRA_USERNAMES = "usernames"
        /** The fields the password goes in: the new one and its confirmation. */
        const val EXTRA_PASSWORDS = "passwords"
        /** The app asking (null for a web page). */
        const val EXTRA_PACKAGE = "package"
        /** The web page's domain (null in an app). */
        const val EXTRA_DOMAIN = "domain"
        /** The most characters the fields take (0: any). */
        const val EXTRA_MAX_LENGTH = "maxLength"
        /** Whether they take digits only. */
        const val EXTRA_DIGITS = "digits"
        /** A change-password form (it has the current password too). */
        const val EXTRA_CHANGE = "change"
    }
}
