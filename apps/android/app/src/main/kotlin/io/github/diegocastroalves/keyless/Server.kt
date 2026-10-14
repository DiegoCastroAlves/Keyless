package io.github.diegocastroalves.keyless

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * The Keyless server (Supabase Auth and the Data API), as the desktop app
 * uses it. What is sent is ciphertext, a proof or the derived sign-in secret.
 */
object Server {
    const val BASE = "https://ednfhgbjtgkrmtnudcjr.supabase.co"
    private const val KEY = "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD"

    class Session(val accessToken: String, val refreshToken: String, val expiresAt: Long, val userId: String)

    private fun enc(value: String): String = URLEncoder.encode(value, "UTF-8")

    private fun request(path: String, method: String = "GET", body: String? = null, token: String? = null): String {
        val connection = try {
            (URL("$BASE/$path").openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = 15_000
                readTimeout = 30_000
                useCaches = false
                setRequestProperty("apikey", KEY)
                if (token != null) setRequestProperty("Authorization", "Bearer $token")
                if (body != null) {
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                }
            }
        } catch (e: IOException) {
            throw KeylessException("offline", e.message ?: "offline")
        }
        try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (status !in 200..299) throw mapError(status, text)
            return text
        } catch (e: IOException) {
            throw KeylessException("offline", e.message ?: "offline")
        } finally {
            connection.disconnect()
        }
    }

    private fun mapError(status: Int, text: String): KeylessException {
        val body = try { JSONObject(text) } catch (e: Exception) { JSONObject() }
        val code = body.optString("error_code").ifEmpty { body.optString("code") }.ifEmpty { body.optString("error") }
        val message = body.optString("msg").ifEmpty { body.optString("message") }.ifEmpty { body.optString("error_description") }.ifEmpty { "HTTP $status" }
        return when {
            code == "invalid_credentials" || code == "invalid_grant" -> KeylessException("invalid_credentials", message)
            code == "email_not_confirmed" -> KeylessException("email_not_confirmed", message)
            status == 429 || code.startsWith("over_") -> KeylessException("too_many_attempts", message)
            code == "PGRST202" || code == "PGRST205" -> KeylessException("missing_function", message)
            status == 401 || status == 403 || code == "refresh_token_not_found" || code == "session_not_found" -> KeylessException("session_expired", message)
            else -> KeylessException("unknown", "$message ($code)")
        }
    }

    private fun session(text: String): Session {
        val raw = JSONObject(text)
        val now = System.currentTimeMillis() / 1000
        val expiresAt = if (raw.has("expires_at")) raw.getLong("expires_at") else now + raw.optLong("expires_in", 3600)
        return Session(raw.getString("access_token"), raw.getString("refresh_token"), expiresAt, raw.getJSONObject("user").getString("id"))
    }

    fun signIn(email: String, authSecret: String): Session =
        session(request("auth/v1/token?grant_type=password", "POST", JSONObject().put("email", email).put("password", authSecret).toString()))

    fun refresh(refreshToken: String): Session =
        session(request("auth/v1/token?grant_type=refresh_token", "POST", JSONObject().put("refresh_token", refreshToken).toString()))

    fun signOut(token: String) {
        try {
            request("auth/v1/logout?scope=local", "POST", "{}", token)
        } catch (e: KeylessException) {
            // Already ended.
        }
    }

    fun profile(token: String, userId: String): JSONObject? {
        val rows = JSONArray(request("rest/v1/profiles?user_id=eq.${enc(userId)}&select=format,kdf,enc_user_key,public_key,enc_private_key,pending_kdf,pending_enc_user_key", token = token))
        return if (rows.length() > 0) rows.getJSONObject(0) else null
    }

    fun memberships(token: String, userId: String): String =
        request("rest/v1/vault_members?user_id=eq.${enc(userId)}&select=vault_id,role,enc_vault_key,vaults(owner_id,enc_meta,seq,deleted_at,enc_tombstone)", token = token)

    fun itemsSince(token: String, vaultId: String, cursor: Long, limit: Int): JSONArray =
        JSONArray(request("rest/v1/items?select=*&vault_id=eq.${enc(vaultId)}&seq=gt.$cursor&order=seq.asc&limit=$limit", token = token))

    /** A database function; `token` is null for those open to anyone. */
    fun rpc(name: String, args: JSONObject, token: String? = null): String = request("rest/v1/rpc/$name", "POST", args.toString(), token)
}
