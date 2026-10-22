package io.github.diegocastroalves.keyless

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.view.WindowManager
import android.widget.ScrollView
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Answers Android's Credential Manager once Keyless is unlocked: the
 * passkeys after an unlock, a sign-in with the chosen passkey, or a new
 * passkey kept in the site's login.
 */
@RequiresApi(34)
class PasskeyActivity : KeylessActivity() {
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
            ACTION_UNLOCK -> unlocked()
            ACTION_GET -> get()
            ACTION_CREATE -> create()
            else -> finish()
        }
    }

    /** The error for the calling app, with what went wrong (nothing secret). */
    private fun failure(e: Exception): String =
        if (e is KeylessException && e.message != null && e.message != e.key) "${errorText(e)} (${e.message})" else errorText(e)

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    /** clientDataJSON for an app (browsers make their own). */
    private fun clientData(type: String, challenge: String, origin: String, packageName: String): String =
        "{\"type\":" + JSONObject.quote(type) + ",\"challenge\":" + JSONObject.quote(challenge) + ",\"origin\":" + JSONObject.quote(origin) +
            ",\"androidPackageName\":" + JSONObject.quote(packageName) + "}"

    private fun unlocked() {
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
        // Off the main thread: telling a browser's page apart may need the
        // network, and the passwords would be left out without a word.
        thread {
            val entries = try {
                request?.let { KeylessCredentialService.entries(this, it) }
            } catch (e: Exception) {
                null
            }
            runOnUiThread {
                val result = Intent()
                if (entries != null) PendingIntentHandler.setBeginGetCredentialResponse(result, entries)
                setResult(RESULT_OK, result)
                finish()
            }
        }
    }

    private fun get() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.firstOrNull { it is GetPublicKeyCredentialOption } as? GetPublicKeyCredentialOption
        if (request == null || option == null) return failGet("no request")
        thread {
            val answer = try {
                val json = JSONObject(option.requestJson)
                val rpId = json.getString("rpId")
                val origin = Origins.origin(this, request.callingAppInfo, rpId)
                val hash = option.clientDataHash
                val args = JSONObject()
                    .put("itemId", intent.getStringExtra(EXTRA_ITEM))
                    .put("credentialId", intent.getStringExtra(EXTRA_CREDENTIAL))
                    .put("userVerified", true)
                var clientData: String? = null
                if (hash != null) {
                    args.put("clientDataHash", b64(hash))
                } else {
                    clientData = clientData("webauthn.get", json.getString("challenge"), origin, request.callingAppInfo.packageName)
                    args.put("clientDataJson", clientData)
                }
                val signed = Native.obj("passkeyGet", args)
                JSONObject()
                    .put("id", signed.getString("credentialId"))
                    .put("rawId", signed.getString("credentialId"))
                    .put("type", "public-key")
                    .put("authenticatorAttachment", "platform")
                    .put(
                        "response",
                        JSONObject()
                            // With a hash, the browser puts in its own clientDataJSON.
                            .put("clientDataJSON", b64((clientData ?: "{}").toByteArray()))
                            .put("authenticatorData", signed.getString("authenticatorData"))
                            .put("signature", signed.getString("signature"))
                            .put("userHandle", signed.getString("userHandle")),
                    )
                    .put("clientExtensionResults", JSONObject())
            } catch (e: Exception) {
                runOnUiThread { failGet(failure(e)) }
                return@thread
            }
            runOnUiThread {
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(answer.toString())))
                setResult(RESULT_OK, result)
                finish()
            }
        }
    }

    private fun create() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val call = request?.callingRequest as? CreatePublicKeyCredentialRequest
        if (request == null || call == null) return failCreate("no request")
        thread {
            val answer = try {
                val json = JSONObject(call.requestJson)
                val rp = json.getJSONObject("rp")
                val user = json.getJSONObject("user")
                val rpId = rp.optString("id").ifEmpty { throw KeylessException("passkey_origin", "no rp id") }
                val origin = Origins.origin(this, request.callingAppInfo, rpId)
                val exclude = json.optJSONArray("excludeCredentials")
                val excluded = JSONArray()
                if (exclude != null) for (i in 0 until exclude.length()) exclude.optJSONObject(i)?.optString("id")?.let { excluded.put(it) }
                val made = Keyless.createPasskey(
                    JSONObject()
                        .put("rpId", rpId)
                        .put("rpName", rp.optString("name"))
                        .put("userHandle", user.getString("id"))
                        .put("userName", user.optString("name"))
                        .put("userDisplayName", user.optString("displayName"))
                        .put("excludeCredentials", excluded)
                        .put("userVerified", true),
                )
                val hash = call.clientDataHash
                val clientData = if (hash == null) clientData("webauthn.create", json.getString("challenge"), origin, request.callingAppInfo.packageName) else "{}"
                JSONObject()
                    .put("id", made.getString("credentialId"))
                    .put("rawId", made.getString("credentialId"))
                    .put("type", "public-key")
                    .put("authenticatorAttachment", "platform")
                    .put(
                        "response",
                        JSONObject()
                            .put("clientDataJSON", b64(clientData.toByteArray()))
                            .put("attestationObject", made.getString("attestationObject"))
                            .put("authenticatorData", made.getString("authenticatorData"))
                            .put("publicKey", made.getString("publicKey"))
                            .put("publicKeyAlgorithm", -7)
                            .put("transports", JSONArray().put("internal").put("hybrid")),
                    )
                    .put("clientExtensionResults", JSONObject().put("credProps", JSONObject().put("rk", true)))
            } catch (e: Exception) {
                runOnUiThread { failCreate(failure(e)) }
                return@thread
            }
            runOnUiThread {
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(answer.toString()))
                setResult(RESULT_OK, result)
                finish()
            }
        }
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
        const val ACTION_UNLOCK = "io.github.diegocastroalves.keyless.passkey.UNLOCK"
        const val ACTION_GET = "io.github.diegocastroalves.keyless.passkey.GET"
        const val ACTION_CREATE = "io.github.diegocastroalves.keyless.passkey.CREATE"
        const val EXTRA_ITEM = "item"
        const val EXTRA_CREDENTIAL = "credential"
    }
}
