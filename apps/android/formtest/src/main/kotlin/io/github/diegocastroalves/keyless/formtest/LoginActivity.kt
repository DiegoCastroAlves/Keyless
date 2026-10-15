package io.github.diegocastroalves.keyless.formtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.content.ClipboardManager
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import org.json.JSONArray
import org.json.JSONObject

/** A sign-in form, as an app would have one. "Log in" ends the form (autofill then offers to save). */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            padded()
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
        column.addView(Button(this).apply { text = "Create passkey"; setOnClickListener { createPasskey(status) } })
        column.addView(Button(this).apply { text = "Sign in with passkey"; setOnClickListener { usePasskey(status) } })
        column.addView(status)
        // Passwords through Credential Manager, and what is on the clipboard (a code copied after filling).
        val more = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        more.addView(Button(this).apply { text = "Save password"; setOnClickListener { savePassword(username.text.toString(), password.text.toString(), status) } })
        more.addView(Button(this).apply { text = "Get password"; setOnClickListener { getPassword(username, password, status) } })
        column.addView(more)
        val clipboard = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        clipboard.addView(Button(this).apply { text = "Paste"; setOnClickListener { paste(status) } })
        // A clipboard keyboards show nothing from (their chips go first).
        clipboard.addView(Button(this).apply {
            text = "Clear clipboard"
            setOnClickListener {
                getSystemService(ClipboardManager::class.java)?.clearPrimaryClip()
                status.text = "Clipboard cleared"
            }
        })
        column.addView(clipboard)
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun savePassword(id: String, secret: String, status: TextView) {
        CredentialManager.create(this).createCredentialAsync(
            this,
            CreatePasswordRequest(id, secret),
            null,
            mainExecutor,
            object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(result: CreateCredentialResponse) {
                    status.text = "Password saved"
                }

                override fun onError(e: CreateCredentialException) {
                    status.text = "Save failed: ${e.type} ${e.message}"
                }
            },
        )
    }

    private fun getPassword(username: EditText, password: EditText, status: TextView) {
        CredentialManager.create(this).getCredentialAsync(
            this,
            GetCredentialRequest(listOf(GetPasswordOption())),
            null,
            mainExecutor,
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    val credential = result.credential as? PasswordCredential
                    if (credential == null) {
                        status.text = "No password"
                        return
                    }
                    username.setText(credential.id)
                    password.setText(credential.password)
                    status.text = "Got password for ${credential.id}"
                }

                override fun onError(e: GetCredentialException) {
                    status.text = "Get failed: ${e.type} ${e.message}"
                }
            },
        )
    }

    private fun paste(status: TextView) {
        val clip = getSystemService(ClipboardManager::class.java)?.primaryClip
        val text = if (clip != null && clip.itemCount > 0) clip.getItemAt(0).coerceToText(this).toString() else ""
        status.text = "Clipboard: [$text]"
    }

    private fun challenge(): String =
        android.util.Base64.encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)

    private fun createPasskey(status: TextView) {
        val request = JSONObject()
            .put("challenge", challenge())
            .put("rp", JSONObject().put("id", SITE).put("name", "Passkey test"))
            .put("user", JSONObject().put("id", "dGVzdGVy").put("name", "tester").put("displayName", "Tester"))
            .put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .put("timeout", 60000)
        CredentialManager.create(this).createCredentialAsync(
            this,
            CreatePublicKeyCredentialRequest(request.toString()),
            null,
            mainExecutor,
            object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(result: CreateCredentialResponse) {
                    status.text = "Passkey created"
                }

                override fun onError(e: CreateCredentialException) {
                    status.text = "Create failed: ${e.type} ${e.message}"
                }
            },
        )
    }

    private fun usePasskey(status: TextView) {
        val request = JSONObject().put("challenge", challenge()).put("rpId", SITE).put("userVerification", "required")
        CredentialManager.create(this).getCredentialAsync(
            this,
            GetCredentialRequest(listOf(GetPublicKeyCredentialOption(request.toString()))),
            null,
            mainExecutor,
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    val json = (result.credential as? PublicKeyCredential)?.authenticationResponseJson ?: ""
                    status.text = if (JSONObject(json).getJSONObject("response").has("signature")) "Signed in with passkey" else "No signature"
                }

                override fun onError(e: GetCredentialException) {
                    status.text = "Sign-in failed: ${e.type} ${e.message}"
                }
            },
        )
    }

    companion object {
        const val SITE = "passkey.example.test"
    }
}
