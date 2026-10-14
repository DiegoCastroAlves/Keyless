package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.os.CancellationSignal
import android.util.Base64
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID
import kotlin.concurrent.thread

/*
 * Signing in to Keyless with a passkey instead of the master password and
 * Secret Key, as the web vault (see keyless-client's passkey_login): the
 * passkey's PRF output opens what the server keeps for it. Passkeys are made
 * for the site's domain; its Digital Asset Links let this app use them.
 */

/** The site the passkeys belong to (apps/site, .well-known/assetlinks.json). */
private const val RP_ID = "keyless.diegoalves.dev"

private fun b64url(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

private fun challenge(): String = b64url(ByteArray(32).also { SecureRandom().nextBytes(it) })

/** The PRF output and credential id a passkey answered with, or why not. */
private class PrfAnswer(val output: String?, val credentialId: String)

private fun prfOf(responseJson: String): PrfAnswer {
    val json = JSONObject(responseJson)
    val first = json.optJSONObject("clientExtensionResults")?.optJSONObject("prf")?.optJSONObject("results")?.optString("first")?.ifEmpty { null }
    return PrfAnswer(first, json.optString("rawId").ifEmpty { json.optString("id") })
}

/** Asks Credential Manager for one of Keyless's passkeys (`allow`: only that one), with its PRF output. */
private fun Activity.getPasskey(salt: String, allow: String?, done: (Result<PrfAnswer>) -> Unit) {
    val request = JSONObject()
        .put("challenge", challenge())
        .put("rpId", RP_ID)
        .put("userVerification", "required")
        .put("extensions", JSONObject().put("prf", JSONObject().put("eval", JSONObject().put("first", salt))))
    if (allow != null) request.put("allowCredentials", JSONArray().put(JSONObject().put("type", "public-key").put("id", allow)))
    CredentialManager.create(this).getCredentialAsync(
        this,
        GetCredentialRequest(listOf(GetPublicKeyCredentialOption(request.toString()))),
        CancellationSignal(),
        mainExecutor,
        object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
            override fun onResult(result: GetCredentialResponse) {
                val credential = result.credential as? PublicKeyCredential
                done(if (credential == null) Result.failure(KeylessException("passkey_cancelled")) else Result.success(prfOf(credential.authenticationResponseJson)))
            }

            override fun onError(e: GetCredentialException) {
                done(Result.failure(KeylessException("passkey_cancelled", e.message ?: e.type)))
            }
        },
    )
}

// ----- signing in ---------------------------------------------------------------

/** Signs in with the passkey's PRF output: the server's bundle for its proof opens the account. */
fun Keyless.signInWithPasskey(prfOutput: String, credentialId: String) {
    val proof = Native.obj("passkeyProof", JSONObject().put("prfOutput", prfOutput).put("credentialId", credentialId)).getString("proof")
    val answer = JSONObject(Server.rpc("passkey_sign_in", JSONObject().put("p_credential_id", credentialId).put("p_proof", proof)))
    val error = answer.optString("error")
    if (error.isNotEmpty() || !answer.has("user_id") || !answer.has("enc_bundle")) {
        throw KeylessException(if (error == "passkey_throttled" || error == "passkey_sign_in_off") error else "passkey_failed")
    }
    val bundle = Native.obj(
        "passkeyOpen",
        JSONObject().put("prfOutput", prfOutput).put("credentialId", credentialId).put("userId", answer.getString("user_id")).put("encBundle", answer.getString("enc_bundle")),
    )
    finishSignIn(bundle.getString("email"), bundle.getString("authSecret"), bundle.getString("secretKey"))
}

internal fun MainActivity.passkeySignIn(error: android.widget.TextView, onSignedIn: () -> Unit) {
    error.text = ""
    val salt = Native.run("passkeySalt") as String
    getPasskey(salt, null) { result ->
        val answer = result.getOrElse {
            error.text = getString(R.string.passkey_cancelled)
            return@getPasskey
        }
        val output = answer.output
        if (output == null) {
            error.text = getString(R.string.passkey_no_prf)
            return@getPasskey
        }
        thread {
            val failure = try {
                Keyless.signInWithPasskey(output, answer.credentialId)
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread { if (failure == null) onSignedIn() else error.text = errorText(failure) }
        }
    }
}

// ----- the account's passkeys (settings) ---------------------------------------------

fun Keyless.signInPasskeys(): JSONArray {
    val rows = Server.passkeys(token())
    return Native.arr("passkeyNames", rows)
}

fun Keyless.removeSignInPasskey(id: String) {
    Server.rpc("remove_passkey", JSONObject().put("p_id", id), token())
}

private fun Keyless.addSignInPasskey(prfOutput: String, credentialId: String, name: String) {
    val sealed = Native.obj("passkeyRegister", JSONObject().put("prfOutput", prfOutput).put("credentialId", credentialId).put("name", name))
    Server.rpc(
        "add_passkey",
        JSONObject().put("p_id", UUID.randomUUID().toString()).put("p_credential_id", credentialId).put("p_enc_name", sealed.getString("encName"))
            .put("p_proof", sealed.getString("proof")).put("p_enc_bundle", sealed.getString("encBundle")),
        token(),
    )
}

/** Makes a passkey for Keyless with Credential Manager, then keeps it on the server. */
private fun MainActivity.createSignInPasskey(name: String, done: () -> Unit) {
    val salt = Native.run("passkeySalt") as String
    val status = Keyless.status()
    val request = JSONObject()
        .put("rp", JSONObject().put("id", RP_ID).put("name", "Keyless"))
        .put("user", JSONObject().put("id", b64url(status.optString("userId").toByteArray())).put("name", status.optString("email")).put("displayName", status.optString("email")))
        .put("challenge", challenge())
        .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)).put(JSONObject().put("type", "public-key").put("alg", -257)))
        .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
        .put("extensions", JSONObject().put("prf", JSONObject().put("eval", JSONObject().put("first", salt))))
    val failed = { key: String -> Toast.makeText(this, errorText(KeylessException(key)), Toast.LENGTH_LONG).show() }
    CredentialManager.create(this).createCredentialAsync(
        this,
        CreatePublicKeyCredentialRequest(request.toString()),
        CancellationSignal(),
        mainExecutor,
        object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
            override fun onResult(result: CreateCredentialResponse) {
                val made = (result as? CreatePublicKeyCredentialResponse)?.let { prfOf(it.registrationResponseJson) } ?: return failed("passkey_cancelled")
                val keep = { output: String ->
                    act({ Keyless.addSignInPasskey(output, made.credentialId, name) }) {
                        Toast.makeText(this@createSignInPasskey, R.string.passkey_added, Toast.LENGTH_SHORT).show()
                        done()
                    }
                }
                val output = made.output
                if (output != null) return keep(output)
                // Most passkeys give the PRF output only when used.
                getPasskey(salt, made.credentialId) { again ->
                    val prf = again.getOrNull()?.output
                    if (prf == null) failed(if (again.isSuccess) "passkey_no_prf" else "passkey_cancelled") else keep(prf)
                }
            }

            override fun onError(e: CreateCredentialException) {
                failed("passkey_cancelled")
            }
        },
    )
}

/** Settings: the passkeys that sign in to Keyless, to add or remove. */
internal fun MainActivity.signInPasskeysSection(page: LinearLayout) {
    page.add(label(getString(R.string.signin_passkeys), 16f, bold = true), top = 24)
    page.add(label(getString(R.string.signin_passkeys_body), 13f, muted = true), top = 4)
    val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(list, top = 4)
    fun load() {
        thread {
            val rows = try {
                Result.success(Keyless.signInPasskeys())
            } catch (e: Exception) {
                Result.failure(e)
            }
            runOnUiThread {
                list.removeAllViews()
                val found = rows.getOrElse {
                    val text = if ((it as? KeylessException)?.key == "missing_function") t("errors.passkeys_unavailable") else errorText(it)
                    list.add(label(text, 13f, muted = true))
                    return@runOnUiThread
                }
                if (found.length() == 0) list.add(label(getString(R.string.no_passkeys), 13f, muted = true))
                for (i in 0 until found.length()) {
                    val row = found.getJSONObject(i)
                    val line = row()
                    line.add(label(row.optString("name").ifEmpty { "—" }, 14f), width = 0, weight = 1f)
                    line.add(plainButton(getString(R.string.remove)) {
                        act({ Keyless.removeSignInPasskey(row.getString("id")) }) { load() }
                    }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                    list.add(line)
                }
            }
        }
    }
    load()
    page.add(plainButton(getString(R.string.add_passkey)) {
        val name = EditText(this).apply {
            hint = getString(R.string.passkey_name)
            setSingleLine(true)
            setText(android.os.Build.MODEL)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.add_passkey)
            .setView(column(20).apply { add(name) })
            .setPositiveButton(R.string.add_passkey) { _, _ -> createSignInPasskey(name.text.toString().trim()) { load() } }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    page.add(label(getString(R.string.passkeys_changed), 12f, muted = true), top = 2)
}
