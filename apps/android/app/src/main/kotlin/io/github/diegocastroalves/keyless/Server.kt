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
    val BASE: String = BuildConfig.SERVER
    private const val KEY = "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD"

    class Session(val accessToken: String, val refreshToken: String, val expiresAt: Long, val userId: String)

    private fun enc(value: String): String = URLEncoder.encode(value, "UTF-8")

    private fun request(path: String, method: String = "GET", body: String? = null, token: String? = null, headers: Map<String, String> = emptyMap()): String =
        String(send(path, method, body?.toByteArray(Charsets.UTF_8), "application/json", token, headers, 30_000, ::mapError), Charsets.UTF_8)

    private fun send(
        path: String,
        method: String,
        body: ByteArray?,
        contentType: String,
        token: String?,
        headers: Map<String, String>,
        timeout: Int,
        error: (Int, String) -> KeylessException,
    ): ByteArray {
        val connection = try {
            (URL("$BASE/$path").openConnection() as HttpURLConnection).apply {
                requestMethod = method
                connectTimeout = 15_000
                readTimeout = timeout
                useCaches = false
                setRequestProperty("apikey", KEY)
                if (token != null) setRequestProperty("Authorization", "Bearer $token")
                for ((name, value) in headers) setRequestProperty(name, value)
                if (body != null) {
                    doOutput = true
                    setRequestProperty("Content-Type", contentType)
                    setFixedLengthStreamingMode(body.size)
                    outputStream.use { it.write(body) }
                }
            }
        } catch (e: IOException) {
            throw KeylessException("offline", e.message ?: "offline")
        }
        try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            if (status !in 200..299) throw error(status, String(bytes, Charsets.UTF_8))
            return bytes
        } catch (e: IOException) {
            throw KeylessException("offline", e.message ?: "offline")
        } finally {
            connection.disconnect()
        }
    }

    /** Storage's errors, as the desktop reads them. */
    private fun storageError(status: Int, text: String): KeylessException {
        val body = try { JSONObject(text) } catch (e: Exception) { JSONObject() }
        val inner = body.opt("statusCode")?.toString() ?: status.toString()
        val message = body.optString("message")
        val error = body.optString("error")
        return when {
            message.contains("row-level security") -> KeylessException("attachment_refused", message)
            inner == "409" -> KeylessException("attachment_exists", message)
            inner == "404" -> KeylessException("attachment_missing", message)
            inner == "413" -> KeylessException("attachment_refused", message)
            (inner == "401" || inner == "403") && (error.equals("unauthorized", ignoreCase = true) || message.contains("jwt", ignoreCase = true)) -> KeylessException("session_expired", message)
            else -> KeylessException("unknown", "$message ($inner $error)")
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
            // add_passkey while the server's passkey sign-in switch is off.
            code == "55000" -> KeylessException("passkey_sign_in_off", message)
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

    /** Adds an item; the server's row back (empty when the id is taken). */
    fun insertItem(token: String, id: String, vaultId: String, encOverview: String, encDetails: String): JSONArray =
        JSONArray(
            request(
                "rest/v1/items",
                "POST",
                JSONObject().put("id", id).put("vault_id", vaultId).put("enc_overview", encOverview).put("enc_details", encDetails).toString(),
                token,
                mapOf("Prefer" to "return=representation"),
            ),
        )

    /** Replaces an item's content where the server still has `baseRevision`; empty on a conflict. */
    fun updateItem(token: String, id: String, baseRevision: Long, encOverview: String, encDetails: String): JSONArray =
        JSONArray(
            request(
                "rest/v1/items?id=eq.${enc(id)}&revision=eq.$baseRevision",
                "PATCH",
                JSONObject().put("enc_overview", encOverview).put("enc_details", encDetails).toString(),
                token,
                mapOf("Prefer" to "return=representation"),
            ),
        )

    /** Writes `body` (content or a tombstone) where the server still has `baseRevision`; empty on a conflict. */
    fun patchItem(token: String, id: String, baseRevision: Long, body: JSONObject): JSONArray =
        JSONArray(request("rest/v1/items?id=eq.${enc(id)}&revision=eq.$baseRevision", "PATCH", body.toString(), token, mapOf("Prefer" to "return=representation")))

    /** One item as the server has it now, or null when it has none. */
    fun item(token: String, id: String): JSONObject? {
        val rows = JSONArray(request("rest/v1/items?select=*&id=eq.${enc(id)}", token = token))
        return if (rows.length() > 0) rows.getJSONObject(0) else null
    }

    /** The account's signed-in devices (what each says about itself is encrypted). */
    fun devices(token: String): String =
        request("rest/v1/devices?select=id,enc_info,ip,country,created_at,last_seen_at&revoked_at=is.null&order=last_seen_at.desc", token = token)

    /** Adds items (an import); the server's rows back. */
    fun insertItems(token: String, rows: JSONArray): JSONArray =
        JSONArray(request("rest/v1/items", "POST", rows.toString(), token, mapOf("Prefer" to "return=representation")))

    /** An item's earlier versions, newest first; none on a server without them. */
    fun itemVersions(token: String, id: String): JSONArray =
        try {
            JSONArray(request("rest/v1/item_versions?select=revision,enc_overview,enc_details&item_id=eq.${enc(id)}&order=revision.desc&limit=50", token = token))
        } catch (e: KeylessException) {
            if (e.key == "missing_function") JSONArray() else throw e
        }

    fun insertShare(token: String, row: JSONObject) {
        request("rest/v1/shares", "POST", row.toString(), token, mapOf("Prefer" to "return=minimal"))
    }

    /** The account's links, newest first (never their contents). */
    fun shares(token: String): JSONArray =
        JSONArray(request("rest/v1/shares?select=id,enc_label,expires_at,max_views,views,created_at,revoked_at&order=created_at.desc&limit=200", token = token))

    fun revokeShare(token: String, id: String, at: String) {
        request("rest/v1/shares?id=eq.${enc(id)}", "PATCH", JSONObject().put("revoked_at", at).toString(), token, mapOf("Prefer" to "return=minimal"))
    }

    // Attachments: Storage objects hold only ciphertext, in chunks of up to
    // 4 MiB, so these requests get more time.
    private const val STORAGE_TIMEOUT = 300_000

    /** Uploads a chunk; never replaces one (a retry after a lost answer leaves it as it was). */
    fun uploadObject(token: String, name: String, bytes: ByteArray) {
        try {
            send("storage/v1/object/attachments/$name", "POST", bytes, "application/octet-stream", token, mapOf("x-upsert" to "false"), STORAGE_TIMEOUT, ::storageError)
        } catch (e: KeylessException) {
            if (e.key != "attachment_exists") throw e
        }
    }

    fun downloadObject(token: String, name: String): ByteArray =
        send("storage/v1/object/authenticated/attachments/$name", "GET", null, "", token, emptyMap(), STORAGE_TIMEOUT, ::storageError)

    /** Deletes chunks; names that do not exist are skipped. */
    fun deleteObjects(token: String, names: List<String>) {
        for (batch in names.chunked(1000)) {
            send("storage/v1/object/attachments", "DELETE", JSONObject().put("prefixes", JSONArray(batch)).toString().toByteArray(), "application/json", token, emptyMap(), STORAGE_TIMEOUT, ::storageError)
        }
    }

    /** Bytes of attachments the account uploaded (`used`) and may keep (`quota`), if the server counts them. */
    fun attachmentSpace(token: String): JSONObject? =
        try {
            JSONObject(rpc("attachment_space", JSONObject(), token))
        } catch (e: Exception) {
            null
        }

    /** The account's passkeys for signing in (their names encrypted). */
    fun passkeys(token: String): String =
        request("rest/v1/passkeys?select=id,credential_id,enc_name,created_at,last_used_at&order=created_at.asc", token = token)

    /** A database function; `token` is null for those open to anyone. */
    fun rpc(name: String, args: JSONObject, token: String? = null): String = request("rest/v1/rpc/$name", "POST", args.toString(), token)
}
