package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.provider.Settings
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.concurrent.thread

fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

fun Context.accent(): Int = getColor(R.color.accent)

fun Context.label(text: CharSequence, size: Float = 15f, bold: Boolean = false, muted: Boolean = false): TextView =
    TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        if (bold) typeface = Typeface.DEFAULT_BOLD
        if (muted) setTextColor(getColor(R.color.muted))
    }

fun Context.field(hint: String, type: Int, secret: Boolean = false): EditText =
    EditText(this).apply {
        this.hint = hint
        inputType = type
        setSingleLine(true)
        // Keyless's own secrets are never offered to an autofill service.
        if (secret) importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

const val TEXT_EMAIL = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
const val TEXT_PASSWORD = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
const val TEXT_KEY = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD

fun Context.primaryButton(text: String, onClick: () -> Unit): Button =
    Button(this).apply {
        this.text = text
        isAllCaps = false
        backgroundTintList = ColorStateList.valueOf(accent())
        setTextColor(Color.WHITE)
        setOnClickListener { onClick() }
    }

fun Context.plainButton(text: String, onClick: () -> Unit): Button =
    Button(this, null, android.R.attr.borderlessButtonStyle).apply {
        this.text = text
        isAllCaps = false
        setTextColor(accent())
        setOnClickListener { onClick() }
    }

fun Context.column(padding: Int = 24): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(padding), dp(padding), dp(padding), dp(padding))
    }

fun Context.row(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
}

fun LinearLayout.add(view: View, top: Int = 0, width: Int = ViewGroup.LayoutParams.MATCH_PARENT, weight: Float = 0f): LinearLayout {
    val params = LinearLayout.LayoutParams(width, ViewGroup.LayoutParams.WRAP_CONTENT, weight)
    params.topMargin = context.dp(top)
    addView(view, params)
    return this
}

/** A rounded panel behind a group of fields. */
fun Context.panel(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(dp(14), dp(6), dp(14), dp(6))
    background = GradientDrawable().apply {
        cornerRadius = dp(12).toFloat()
        setColor(getColor(R.color.panel))
    }
}

/** A round letter for an item without an icon. */
fun Context.avatar(title: String): TextView = TextView(this).apply {
    text = title.trim().take(1).uppercase().ifEmpty { "?" }
    gravity = Gravity.CENTER
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
    typeface = Typeface.DEFAULT_BOLD
    setTextColor(accent())
    background = GradientDrawable().apply {
        cornerRadius = dp(10).toFloat()
        setColor(getColor(R.color.panel))
    }
}

/** An error, in the user's language. */
fun Context.errorText(error: Throwable): String {
    val key = (error as? KeylessException)?.key
    val res = when (key) {
        "invalid_credentials" -> R.string.err_invalid_credentials
        "wrong_password" -> R.string.err_wrong_password
        "secret_key_invalid" -> R.string.err_secret_key_invalid
        "setup_code_invalid" -> R.string.err_setup_code_invalid
        "email_not_confirmed" -> R.string.err_email_not_confirmed
        "too_many_attempts" -> R.string.err_too_many_attempts
        "account_not_set_up" -> R.string.err_account_not_set_up
        "account_keys_undecryptable" -> R.string.err_account_keys_undecryptable
        "offline" -> R.string.err_offline
        "device_setup_throttled" -> R.string.err_device_setup_throttled
        "device_setup_unavailable" -> R.string.err_device_setup_unavailable
        "session_expired" -> R.string.err_session_expired
        "biometric_key_invalid" -> R.string.err_biometric_key_invalid
        "save_conflict" -> R.string.err_save_conflict
        "vault_read_only" -> R.string.err_vault_read_only
        "passkey_origin" -> R.string.err_passkey_origin
        "passkey_excluded" -> R.string.err_passkey_excluded
        "device_revoked" -> R.string.err_device_revoked
        "devices_unavailable" -> R.string.err_devices_unavailable
        "device_setup_code_wrong" -> R.string.err_device_setup_code_wrong
        "device_setup_code_denied" -> R.string.err_device_setup_code_denied
        "device_setup_expired" -> R.string.err_device_setup_expired
        "device_setup_failed" -> R.string.err_device_setup_failed
        "title_too_long" -> R.string.err_title_too_long
        "too_many_fields" -> R.string.err_too_many_fields
        "notes_too_long" -> R.string.err_notes_too_long
        "item_too_large" -> R.string.err_item_too_large
        "not_found" -> R.string.err_not_found
        else -> null
    }
    if (key == "field_too_long") return getString(R.string.err_field_too_long, error.message ?: "")
    if (res != null) return getString(res)
    // The desktop's texts for the rest; the client puts a text's one value
    // (a detail, a minimum, an email) in the message.
    if (key != null) {
        val detail = error.message ?: ""
        val text = Labels.t(this, "errors.$key", mapOf("detail" to detail, "min" to detail, "email" to detail, "max" to detail, "quota" to detail, "label" to detail, "seconds" to detail))
        if (text != "errors.$key") return text
    }
    return getString(R.string.err_unknown, error.message ?: error.toString())
}

// ----- unlocking (the app and autofill) --------------------------------------

private fun Context.bootCount(): Int = Settings.Global.getInt(contentResolver, Settings.Global.BOOT_COUNT, 0)

fun Context.biometricAvailable(): Boolean {
    val manager = getSystemService(BiometricManager::class.java) ?: return false
    val result = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    } else {
        @Suppress("DEPRECATION")
        manager.canAuthenticate()
    }
    return result == BiometricManager.BIOMETRIC_SUCCESS
}

/**
 * Biometric unlock is on, and the master password was typed since the phone
 * started and within the days the settings allow.
 */
fun Context.biometricUsable(): Boolean {
    val prefs = getSharedPreferences("keyless", Context.MODE_PRIVATE)
    val typedAt = prefs.getLong("password_at", 0L)
    val fresh = System.currentTimeMillis() - typedAt < Keyless.masterPasswordDays * 86_400_000L
    return SecureStore.biometricEnabled(this) && prefs.getInt("password_boot", -1) == bootCount() && fresh
}

/** The master password was just typed (signing in or unlocking). */
fun Context.notePasswordTyped() {
    getSharedPreferences("keyless", Context.MODE_PRIVATE).edit().putInt("password_boot", bootCount()).putLong("password_at", System.currentTimeMillis()).apply()
}

/** Asks for biometrics with `cipher`, then calls `done` with the authenticated cipher (on the main thread). */
fun Activity.biometric(title: String, cipher: javax.crypto.Cipher, done: (javax.crypto.Cipher?) -> Unit) {
    val prompt = BiometricPrompt.Builder(this)
        .setTitle(title)
        .setNegativeButton(getString(R.string.cancel), mainExecutor) { _, _ -> done(null) }
        .build()
    prompt.authenticate(
        BiometricPrompt.CryptoObject(cipher),
        CancellationSignal(),
        mainExecutor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                done(result.cryptoObject?.cipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                done(null)
            }
        },
    )
}

/** The unlock form: master password, or biometrics when on. */
fun Activity.unlockForm(onUnlocked: () -> Unit, onSignOut: (() -> Unit)?): View {
    val form = column()
    val password = field(getString(R.string.master_password), TEXT_PASSWORD, secret = true)
    val error = label("", 14f).apply { setTextColor(getColor(R.color.danger)) }
    lateinit var unlock: Button
    unlock = primaryButton(getString(R.string.unlock)) {
        val typed = password.text.toString()
        if (typed.isEmpty()) return@primaryButton
        unlock.isEnabled = false
        error.text = ""
        thread {
            val failure = try {
                Keyless.unlock(typed)
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                unlock.isEnabled = true
                if (failure == null) {
                    password.setText("")
                    notePasswordTyped()
                    onUnlocked()
                } else {
                    error.text = errorText(failure)
                }
            }
        }
    }
    form.add(label(getString(R.string.unlock_title), 22f, bold = true))
    form.add(label(Keyless.email, 14f, muted = true), top = 4)
    form.add(password, top = 20)
    form.add(error, top = 6)
    form.add(unlock, top = 8)
    if (biometricUsable()) {
        val tryBiometric = {
            val cipher = SecureStore.biometricDecryptCipher(this)
            if (cipher == null) {
                error.text = getString(R.string.err_biometric_key_invalid)
            } else {
                biometric(getString(R.string.biometric_title), cipher) { authenticated ->
                    val userKey = authenticated?.let { SecureStore.openBiometric(this, it) }
                    if (userKey != null) {
                        try {
                            Keyless.unlockWithUserKey(userKey)
                            onUnlocked()
                        } catch (e: Exception) {
                            SecureStore.disableBiometric(this)
                            error.text = errorText(e)
                        }
                    }
                }
            }
        }
        form.add(plainButton(getString(R.string.unlock_biometric)) { tryBiometric() }, top = 4)
        form.post { tryBiometric() }
    }
    if (onSignOut != null) {
        form.add(plainButton(getString(R.string.sign_out)) {
            AlertDialog.Builder(this)
                .setTitle(R.string.sign_out)
                .setMessage(R.string.sign_out_body)
                .setPositiveButton(R.string.sign_out) { _, _ -> onSignOut() }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }, top = 24)
    }
    return form
}
