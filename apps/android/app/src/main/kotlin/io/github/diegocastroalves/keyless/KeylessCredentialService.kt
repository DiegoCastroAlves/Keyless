package io.github.diegocastroalves.keyless

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Keyless as a provider in Android's Credential Manager: the passkeys kept
 * for the site an app or browser signs in to, and new ones; the passwords
 * of the app asking, and new ones (CredentialPasswords). The choice opens
 * PasskeyActivity or PasswordCredentialActivity, which unlock if needed,
 * check who is asking and answer.
 */
@RequiresApi(34)
class KeylessCredentialService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request is BeginCreatePasswordCredentialRequest && Keyless.hasAccount && request.callingAppInfo?.packageName != packageName) {
            callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(CredentialPasswords.createEntry(this)).build())
            return
        }
        if (request !is BeginCreatePublicKeyCredentialRequest || !Keyless.hasAccount) {
            callback.onError(CreateCredentialUnknownException())
            return
        }
        val intent = Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_CREATE)
        val pending = PendingIntent.getActivity(this, 2001, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val entry = CreateEntry.Builder(Keyless.email.ifEmpty { getString(R.string.app_name) }, pending).build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        if (!Keyless.hasAccount || request.beginGetCredentialOptions.none { it is BeginGetPublicKeyCredentialOption || it is BeginGetPasswordOption }) {
            callback.onResult(BeginGetCredentialResponse.Builder().build())
            return
        }
        if (!Keyless.isUnlocked) {
            val intent = Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_UNLOCK)
            val pending = PendingIntent.getActivity(this, 2002, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            callback.onResult(BeginGetCredentialResponse.Builder().addAuthenticationAction(AuthenticationAction(getString(R.string.autofill_unlock), pending)).build())
            return
        }
        // Telling a browser's page apart may need the network; a sync first.
        thread {
            Keyless.syncBriefly(1_500)
            callback.onResult(entries(this, request))
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        /** One entry per passkey kept for the requests' sites, and per password of the caller. */
        fun entries(context: Context, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
            val builder = BeginGetCredentialResponse.Builder()
            var code = 3000
            for (option in request.beginGetCredentialOptions) {
                if (option !is BeginGetPublicKeyCredentialOption) continue
                val json = try {
                    JSONObject(option.requestJson)
                } catch (e: Exception) {
                    continue
                }
                val allow = json.optJSONArray("allowCredentials")
                val ids = if (allow == null) emptyList() else (0 until allow.length()).mapNotNull { allow.optJSONObject(it)?.optString("id") }
                for (passkey in Keyless.passkeysFor(json.optString("rpId"), ids)) {
                    val intent = Intent(context, PasskeyActivity::class.java)
                        .setAction(PasskeyActivity.ACTION_GET)
                        .putExtra(PasskeyActivity.EXTRA_ITEM, passkey.getString("itemId"))
                        .putExtra(PasskeyActivity.EXTRA_CREDENTIAL, passkey.getString("credentialId"))
                    val pending = PendingIntent.getActivity(context, code++, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                    val name = passkey.optString("userName").ifEmpty { passkey.optString("title") }
                    builder.addCredentialEntry(
                        PublicKeyCredentialEntry.Builder(context, name, pending, option).setDisplayName(passkey.optString("title")).build(),
                    )
                }
            }
            CredentialPasswords.addEntries(context, request, builder)
            CredentialPasswords.addPickAction(context, request, builder)
            return builder.build()
        }
    }
}
