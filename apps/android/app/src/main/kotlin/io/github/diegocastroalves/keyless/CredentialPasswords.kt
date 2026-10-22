package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import android.widget.ScrollView
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.Action
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PendingIntentHandler
import kotlin.concurrent.thread

/**
 * Passwords through Android's Credential Manager: the logins of the app
 * asking (by its package name), or of the page a browser in Google's list
 * shows, "Search Keyless" for any other login (linked to the app if wanted,
 * see AppLinks), and saving a new one. The choice opens
 * PasswordCredentialActivity, which unlocks if needed.
 */
@RequiresApi(34)
object CredentialPasswords {
    /** Where the caller signs in: a website's host (a trusted browser's page), or its package name. Network: off the main thread. */
    class Caller(val domain: String?, val packageName: String?)

    fun caller(context: Context, info: CallingAppInfo): Caller {
        val origin = Origins.browserOrigin(context, info)
        val host = origin?.let { Uri.parse(it).host?.lowercase() }
        return if (host != null) Caller(host, null) else Caller(null, info.packageName)
    }

    fun matches(caller: Caller): List<Summary> = Keyless.matches(caller.domain, caller.packageName)

    /** A password entry for each login of the caller, for each password option asked. */
    fun addEntries(context: Context, request: BeginGetCredentialRequest, builder: BeginGetCredentialResponse.Builder) {
        val options = request.beginGetCredentialOptions.filterIsInstance<BeginGetPasswordOption>()
        val info = request.callingAppInfo ?: return
        if (options.isEmpty() || info.packageName == context.packageName) return
        val logins = try {
            matches(caller(context, info))
        } catch (e: Exception) {
            return
        }
        var code = 5000
        for (option in options) {
            for (login in logins.take(10)) {
                if (login.subtitle.isEmpty()) continue
                val intent = Intent(context, PasswordCredentialActivity::class.java)
                    .setAction(PasswordCredentialActivity.ACTION_GET)
                    .putExtra(PasswordCredentialActivity.EXTRA_ITEM, login.id)
                val pending = PendingIntent.getActivity(context, code++, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                builder.addCredentialEntry(PasswordCredentialEntry.Builder(context, login.subtitle, pending, option).setDisplayName(login.title).build())
            }
        }
    }

    /** "Search Keyless": any login for the caller, chosen in PasswordCredentialActivity. */
    fun addPickAction(context: Context, request: BeginGetCredentialRequest, builder: BeginGetCredentialResponse.Builder) {
        val info = request.callingAppInfo ?: return
        if (request.beginGetCredentialOptions.none { it is BeginGetPasswordOption } || info.packageName == context.packageName) return
        val intent = Intent(context, PasswordCredentialActivity::class.java).setAction(PasswordCredentialActivity.ACTION_PICK)
        val pending = PendingIntent.getActivity(context, 2004, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        builder.addAction(Action(context.getString(R.string.autofill_pick), pending))
    }

    /** The entry offering to save a new password in Keyless. */
    fun createEntry(context: Context): CreateEntry {
        val intent = Intent(context, PasswordCredentialActivity::class.java).setAction(PasswordCredentialActivity.ACTION_CREATE)
        val pending = PendingIntent.getActivity(context, 2003, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return CreateEntry.Builder(Keyless.email.ifEmpty { context.getString(R.string.app_name) }, pending).build()
    }
}

/** Answers Credential Manager with a password, or saves a new one, once Keyless is unlocked. */
@RequiresApi(34)
class PasswordCredentialActivity : KeylessActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Keyless.isUnlocked) {
            proceed()
        } else {
            setContentView(ScrollView(this).apply { addView(unlockForm(onUnlocked = { proceed() }, onSignOut = null)) })
        }
    }

    private fun proceed() {
        when (intent.action) {
            ACTION_GET -> get()
            ACTION_PICK -> pick()
            ACTION_CREATE -> create()
            else -> finish()
        }
    }

    /** "Search Keyless": the user chooses the login for the caller, and may link the caller to it. */
    private fun pick() {
        // An action gets the request as it began (who asks, and for what),
        // not the full one an entry gets.
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
        val info = request?.callingAppInfo
        if (info == null || request.beginGetCredentialOptions.none { it is BeginGetPasswordOption }) return failGet("no request")
        thread {
            // Telling a browser's page apart may need the network.
            val caller = try {
                CredentialPasswords.caller(this, info)
            } catch (e: Exception) {
                CredentialPasswords.Caller(null, info.packageName)
            }
            runOnUiThread {
                setContentView(loginPicker(caller.packageName, caller.domain, onPick = { login, link -> answer(login, link, caller) }, onCancel = {
                    val result = Intent()
                    PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
                    setResult(RESULT_OK, result)
                    finish()
                }))
            }
        }
    }

    private fun answer(login: Summary, link: Boolean, caller: CredentialPasswords.Caller) {
        thread {
            val values = try {
                AutofillResponses.loginValues(Keyless.item(login.id)).also { if (it.password == null) throw KeylessException("not_found") }
            } catch (e: Exception) {
                runOnUiThread { android.widget.Toast.makeText(this, if (e is KeylessException && e.key == "not_found") getString(R.string.pick_no_values) else errorText(e), android.widget.Toast.LENGTH_LONG).show() }
                return@thread
            }
            runOnUiThread {
                Keyless.touch()
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PasswordCredential(values.username ?: "", values.password!!)))
                setResult(RESULT_OK, result)
                values.totp?.let { OneTimeCodes.copy(this, login.title, it) }
                if (link) linkInBackground(login.id, caller.packageName, caller.domain)
                finish()
            }
        }
    }

    private fun get() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null || request.credentialOptions.none { it is GetPasswordOption }) return failGet("no request")
        val id = intent.getStringExtra(EXTRA_ITEM) ?: return failGet("no item")
        thread {
            val answer = try {
                // Still a login of whoever asks now.
                val caller = CredentialPasswords.caller(this, request.callingAppInfo)
                if (CredentialPasswords.matches(caller).none { it.id == id }) throw KeylessException("passkey_origin", "not a login of ${request.callingAppInfo.packageName}")
                val item = Keyless.item(id)
                val values = AutofillResponses.loginValues(item)
                Triple(values, item.getJSONObject("overview").optString("title"), values.password ?: throw KeylessException("not_found"))
            } catch (e: Exception) {
                runOnUiThread { failGet(errorText(e)) }
                return@thread
            }
            runOnUiThread {
                Keyless.touch()
                val (values, title, password) = answer
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PasswordCredential(values.username ?: "", password)))
                setResult(RESULT_OK, result)
                values.totp?.let { OneTimeCodes.copy(this, title, it) }
                finish()
            }
        }
    }

    private fun create() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val call = request?.callingRequest as? CreatePasswordRequest
        if (request == null || call == null) return failCreate("no request")
        thread {
            val failure = try {
                val caller = CredentialPasswords.caller(this, request.callingAppInfo)
                val title = caller.domain ?: appName(request.callingAppInfo.packageName)
                Keyless.saveLogin(caller.domain, caller.packageName, title, call.id.trim(), call.password)
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                if (failure != null) return@runOnUiThread failCreate(errorText(failure))
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
                setResult(RESULT_OK, result)
                android.widget.Toast.makeText(this, R.string.saved, android.widget.Toast.LENGTH_SHORT).show()
                finish()
            }
        }
    }

    private fun appName(packageName: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageName, 0)).toString()
    } catch (e: Exception) {
        packageName
    }

    private fun failGet(message: String) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException(message))
        setResult(RESULT_OK, result)
        finish()
    }

    private fun failCreate(message: String) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(result, CreateCredentialUnknownException(message))
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        const val ACTION_GET = "io.github.diegocastroalves.keyless.password.GET"
        const val ACTION_PICK = "io.github.diegocastroalves.keyless.password.PICK"
        const val ACTION_CREATE = "io.github.diegocastroalves.keyless.password.CREATE"
        const val EXTRA_ITEM = "item"
    }
}
