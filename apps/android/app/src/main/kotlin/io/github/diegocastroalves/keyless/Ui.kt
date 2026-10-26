package io.github.diegocastroalves.keyless

import android.annotation.SuppressLint
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
import android.os.Bundle
import android.os.CancellationSignal
import android.provider.Settings
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.accessibility.AccessibilityNodeInfo
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import kotlin.concurrent.thread

fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

fun Context.accent(): Int = getColor(R.color.accent)

/** "Syncing…" in the middle of a screen (an unlock for autofill or a passkey, while it syncs). */
fun Context.syncingView(): View = label(getString(R.string.syncing), 14f, muted = true).apply { gravity = Gravity.CENTER }

fun Context.label(text: CharSequence, size: Float = 15f, bold: Boolean = false, muted: Boolean = false): TextView =
    TextView(this).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        // Titles semibold, as the desktop's.
        if (bold) weight(600)
        setTextColor(getColor(if (muted) R.color.muted else R.color.fg))
        if (size >= 20f) letterSpacing = -0.01f
    }

/**
 * A one-line field. `secret`: never offered to an autofill service (the
 * Secret Key, recovery keys, passwords of files). `autofill`: what the field
 * is for one (the account's email and master password, which the user's
 * password manager may fill; Keyless's own service skips Keyless). Passwords
 * start hidden, with an eye to show them.
 */
fun Context.field(hint: String, type: Int, secret: Boolean = false, autofill: String? = null): EditText =
    EditText(this).apply {
        this.hint = hint
        // Before the type: it would replace a password's mask.
        setSingleLine(true)
        inputType = type
        fieldLook()
        when {
            autofill != null -> {
                setAutofillHints(autofill)
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
            }
            secret -> importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        val password = type and InputType.TYPE_MASK_VARIATION == InputType.TYPE_TEXT_VARIATION_PASSWORD
        // The keyboard learns nothing typed here.
        if (secret || password) imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        if (password) withEye()
    }

/** An eye at the end of a password field: shows or hides what it holds (hidden first). */
@SuppressLint("ClickableViewAccessibility")
private fun EditText.withEye() {
    val show = context.getDrawable(R.drawable.ic_eye)!!.mutate().apply { setTint(context.getColor(R.color.muted)) }
    val hide = context.getDrawable(R.drawable.ic_eye_off)!!.mutate().apply { setTint(context.getColor(R.color.muted)) }
    val shown = { transformationMethod !is PasswordTransformationMethod }
    fun draw() = setCompoundDrawablesRelativeWithIntrinsicBounds(null, null, if (shown()) hide else show, null)
    fun toggle() {
        val start = selectionStart
        val end = selectionEnd
        transformationMethod = if (shown()) PasswordTransformationMethod.getInstance() else null
        if (start >= 0) setSelection(start, end)
        draw()
    }
    draw()
    compoundDrawablePadding = (8 * resources.displayMetrics.density).toInt()
    setOnTouchListener { _, event ->
        // The eye, its padding and the field's own, at the end.
        val reach = totalPaddingEnd
        val onEye = if (layoutDirection == View.LAYOUT_DIRECTION_RTL) event.x <= reach else event.x >= width - reach
        if (!onEye) return@setOnTouchListener false
        if (event.action == MotionEvent.ACTION_UP) toggle()
        true
    }
    // Screen readers: the eye as an action of the field.
    accessibilityDelegate = object : View.AccessibilityDelegate() {
        override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) {
            super.onInitializeAccessibilityNodeInfo(host, info)
            val label = context.getString(if (shown()) R.string.hide_password else R.string.show_password)
            info.addAction(AccessibilityNodeInfo.AccessibilityAction(R.id.toggle_password, label))
        }

        override fun performAccessibilityAction(host: View, action: Int, args: Bundle?): Boolean {
            if (action != R.id.toggle_password) return super.performAccessibilityAction(host, action, args)
            toggle()
            return true
        }
    }
}

/** Android's hint for a new password (androidx's HintConstants, not in the platform). */
const val NEW_PASSWORD = "newPassword"

const val TEXT_EMAIL = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
const val TEXT_PASSWORD = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
// Not a password type: password managers would take it for the master password's field.
const val TEXT_KEY = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS

/** The desktop's text field: a hairline that turns the accent while typing. */
fun EditText.fieldLook() {
    val idle = context.shape(context.getColor(R.color.panel), 10f, context.getColor(R.color.line_strong))
    val typing = context.shape(context.getColor(R.color.panel), 10f, context.getColor(R.color.accent), 2f)
    background = android.graphics.drawable.StateListDrawable().apply {
        addState(intArrayOf(android.R.attr.state_focused), typing)
        addState(intArrayOf(), idle)
    }
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
    // Also for passwords, which Android writes in a monospace font otherwise.
    typeface = context.inter(400)
    setTextColor(context.getColor(R.color.fg))
    setHintTextColor(context.getColor(R.color.subtle))
    minHeight = context.dp(48)
    setPadding(context.dp(14), context.dp(10), context.dp(14), context.dp(10))
}

private fun Button.buttonLook(fill: Int?, stroke: Int?, text: Int, weight: Int) {
    isAllCaps = false
    stateListAnimator = null
    elevation = 0f
    setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
    weight(weight)
    setTextColor(text)
    minHeight = context.dp(48)
    minimumHeight = context.dp(48)
    minWidth = 0
    minimumWidth = 0
    setPadding(context.dp(18), 0, context.dp(18), 0)
    background = context.pressable(if (fill == null && stroke == null) null else context.shape(fill ?: Color.TRANSPARENT, 10f, stroke), 10f)
}

/** The main action: filled with the accent. */
fun Context.primaryButton(text: String, onClick: () -> Unit): Button =
    Button(this).apply {
        this.text = text
        buttonLook(accent(), null, getColor(R.color.accent_fg), 600)
        setOnClickListener { onClick() }
    }

/** Another action beside it: outlined. */
fun Context.secondaryButton(text: String, onClick: () -> Unit): Button =
    Button(this).apply {
        this.text = text
        buttonLook(getColor(R.color.panel), getColor(R.color.line_strong), getColor(R.color.fg), 500)
        setOnClickListener { onClick() }
    }

/** A link-like action, in the accent color. */
fun Context.plainButton(text: String, onClick: () -> Unit): Button =
    Button(this, null, android.R.attr.borderlessButtonStyle).apply {
        this.text = text
        buttonLook(null, null, accent(), 500)
        minHeight = dp(44)
        minimumHeight = dp(44)
        setPadding(dp(12), 0, dp(12), 0)
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

/** A group of fields and texts: a rounded surface (see card() for rows). */
fun Context.panel(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
    setPadding(dp(16), dp(12), dp(16), dp(12))
    background = shape(getColor(R.color.panel), 16f)
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
        "passkey_failed" -> R.string.err_passkey_failed
        "passkey_throttled" -> R.string.err_passkey_throttled
        "passkey_sign_in_off" -> R.string.err_passkey_sign_in_off
        "passkey_needs_password" -> R.string.err_passkey_needs_password
        "passkey_cancelled" -> R.string.passkey_cancelled
        "passkey_no_prf" -> R.string.passkey_no_prf
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

/** Turns biometric unlock on: biometrics checked, then the user key kept for it; `done(true)` once on. */
fun Activity.enableBiometric(done: (Boolean) -> Unit) {
    val cipher = try {
        SecureStore.biometricEncryptCipher()
    } catch (e: Exception) {
        Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
        return done(false)
    }
    biometric(getString(R.string.biometric_enable_title), cipher) { authenticated ->
        if (authenticated != null) SecureStore.saveBiometric(this, authenticated, Keyless.exportUserKey())
        done(authenticated != null)
    }
}

/**
 * Right after the master password opened the app: offers biometric unlock,
 * once (asked again after the next sign-in), when the phone has biometrics
 * and it is off. Settings still turn it on or off.
 */
fun Activity.offerBiometric() {
    val prefs = getSharedPreferences("keyless", Context.MODE_PRIVATE)
    if (!biometricAvailable() || SecureStore.biometricEnabled(this) || prefs.getBoolean("biometric_offered", false)) return
    prefs.edit().putBoolean("biometric_offered", true).apply()
    AlertDialog.Builder(this)
        .setTitle(R.string.biometric_offer_title)
        .setMessage(getString(R.string.biometric_offer_body))
        .setPositiveButton(R.string.biometric_offer_yes) { _, _ -> enableBiometric {} }
        .setNegativeButton(R.string.not_now, null)
        .show()
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
    val password = field(getString(R.string.master_password), TEXT_PASSWORD, autofill = View.AUTOFILL_HINT_PASSWORD)
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
    form.add(brandHeader(getString(R.string.unlock_title), Keyless.email))
    form.add(password, top = 24)
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
        form.add(secondaryButton(getString(R.string.unlock_biometric)) { tryBiometric() }.apply {
            setCompoundDrawablesRelative(iconDrawable(R.drawable.ic_fingerprint, getColor(R.color.fg)).apply { setBounds(0, 0, dp(18), dp(18)) }, null, null, null)
        }, top = 8)
        form.post { tryBiometric() }
    }
    if (onSignOut != null) {
        form.addCentered(quietButton(getString(R.string.sign_out), R.drawable.ic_log_out) {
            AlertDialog.Builder(this)
                .setTitle(R.string.sign_out)
                .setMessage(R.string.sign_out_body)
                .setPositiveButton(R.string.sign_out) { _, _ -> onSignOut() }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }, top = 20)
    }
    return form
}
