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
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.json.JSONObject

/**
 * Keyless as a passkey provider in Android's Credential Manager: the
 * passkeys kept for the site an app or browser signs in to, and new ones.
 * The choice opens PasskeyActivity, which unlocks if needed, checks who is
 * asking (Origins) and answers.
 */
@RequiresApi(34)
class KeylessCredentialService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
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
        if (!Keyless.hasAccount || request.beginGetCredentialOptions.none { it is BeginGetPublicKeyCredentialOption }) {
            callback.onResult(BeginGetCredentialResponse.Builder().build())
            return
        }
        if (!Keyless.isUnlocked) {
            val intent = Intent(this, PasskeyActivity::class.java).setAction(PasskeyActivity.ACTION_UNLOCK)
            val pending = PendingIntent.getActivity(this, 2002, intent, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            callback.onResult(BeginGetCredentialResponse.Builder().addAuthenticationAction(AuthenticationAction(getString(R.string.autofill_unlock), pending)).build())
            return
        }
        callback.onResult(entries(this, request))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        /** One entry per passkey kept for the requests' sites. */
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
            return builder.build()
        }
    }
}
