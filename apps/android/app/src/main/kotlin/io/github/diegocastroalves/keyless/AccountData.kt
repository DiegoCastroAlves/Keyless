package io.github.diegocastroalves.keyless

import org.json.JSONArray
import org.json.JSONObject

/*
 * The account's recovery key, importing and exporting, and new vaults, as
 * the desktop (see keyless-client's recovery and transfer).
 */

private fun Keyless.secretKey(): String = SecureStore.get(context, "secret_key") ?: throw KeylessException("secret_key_invalid")

/** When the account's recovery key was made (ISO 8601), or null without one. */
fun Keyless.recoveryKeyCreated(): String? {
    val answer = Server.rpc("recovery_key_created", JSONObject(), token()).trim()
    return if (answer == "null" || answer.isEmpty()) null else answer.trim('"')
}

/** Makes a recovery key, replacing any other; returns it, to show. */
fun Keyless.createRecoveryKey(masterPassword: String): String {
    val made = Native.obj("recoveryCreate", JSONObject().put("masterPassword", masterPassword).put("secretKey", secretKey()))
    Server.rpc("set_recovery_key", JSONObject().put("p_proof", made.getString("proof")).put("p_enc_user_key", made.getString("encUserKey")), token())
    return made.getString("recoveryKey")
}

fun Keyless.removeRecoveryKey(masterPassword: String) {
    Native.run("checkPassword", JSONObject().put("masterPassword", masterPassword).put("secretKey", secretKey()))
    Server.rpc("remove_recovery_key", JSONObject(), token())
}

/** The server's answer to a recovery step, or its refusal. */
private fun recoveryAnswer(text: String): JSONObject {
    val answer = try {
        JSONObject(text)
    } catch (e: Exception) {
        JSONObject()
    }
    val error = answer.optString("error")
    if (error.isNotEmpty()) {
        throw KeylessException(if (error in listOf("recovery_failed", "recovery_throttled", "recovery_invalid")) error else "unknown", error)
    }
    return answer
}

/** Recovery, step 1 (signed out): opens the account of `email` with `recoveryKey`. */
fun Keyless.recoveryBegin(email: String, recoveryKey: String) {
    val begun = Native.obj("recoveryBegin", JSONObject().put("email", email).put("recoveryKey", recoveryKey))
    val start = recoveryAnswer(Server.rpc("begin_recovery", JSONObject().put("p_email", begun.getString("email")).put("p_proof", begun.getString("proof"))))
    Native.run("recoveryOpen", start)
}

/** Step 2: the new credentials for `masterPassword`, to show: email, Secret Key and the next recovery key. */
fun Keyless.recoveryPrepare(masterPassword: String): JSONObject {
    val prepared = Native.obj("recoveryPrepare", JSONObject().put("masterPassword", masterPassword))
    pendingRecovery = prepared
    return prepared.getJSONObject("show")
}

/** Step 3: sends them, then signs in with them. */
fun Keyless.recoveryFinish() {
    val prepared = pendingRecovery ?: throw KeylessException("recovery_expired")
    recoveryAnswer(Server.rpc("complete_recovery", prepared.getJSONObject("send")))
    pendingRecovery = null
    Native.run("recoveryForget")
    val show = prepared.getJSONObject("show")
    finishSignIn(show.getString("email"), prepared.getString("authSecret"), show.getString("secretKey"))
}

fun Keyless.recoveryCancel() {
    pendingRecovery = null
    Native.run("recoveryForget")
}

// ----- new vaults ---------------------------------------------------------------

/** Makes a vault named `name`; returns its id. */
fun Keyless.createVault(name: String): String {
    val made = Native.obj("vaultNew", JSONObject().put("name", name))
    Server.rpc("create_vault", made, token())
    sync()
    return made.getString("p_id")
}

// ----- importing ----------------------------------------------------------------

/**
 * Reads an import file of `format` (the desktop's: one_pux, csv,
 * keyless_backup, keyless_export, json, kdbx, one_pif, keeper_csv,
 * dashlane_zip); the counts to confirm: total_items, vaults [[name, count]],
 * files, file_bytes, warnings.
 */
fun Keyless.importParse(format: String, file: ByteArray, password: String?, keyFile: ByteArray?, name: String): JSONObject {
    val args = JSONObject().put("format", format).put("name", name)
    if (!password.isNullOrEmpty()) args.put("password", password)
    return Native.answer(Native.importParse(args.toString(), file, keyFile)) as JSONObject
}

/**
 * Imports what `importParse` read into `targets` (a vault for each of the
 * file's vaults): uploads the attached files, then the items. Answers how
 * many items and files were added, and how many files were not.
 */
fun Keyless.importRun(targets: List<String>, progress: Progress): JSONObject {
    val targetsJson = JSONArray(targets)
    val files = Native.arr("importFiles", JSONObject().put("targets", targetsJson).put("now", now()))
    val total = (0 until files.length()).sumOf { files.getJSONObject(it).optLong("size") }
    val space = if (files.length() > 0) Server.attachmentSpace(token()) else null
    var used = space?.optLong("used") ?: 0L
    var done = 0L
    val uploaded = JSONArray()
    progress(0, total)
    for (i in 0 until files.length()) {
        val file = files.getJSONObject(i)
        val stored = file.getLong("stored")
        if (space != null && used + stored + 4L * 1024 * 1024 + 40 > space.optLong("quota")) {
            done += file.optLong("size")
            continue
        }
        val objects = file.getJSONArray("objects")
        val sent = mutableListOf<String>()
        val chunk = file.optLong("chunkSize", 4L * 1024 * 1024)
        val start = done
        val answer = Native.importFile(file.getString("id")) { index, sealed ->
            try {
                Server.uploadObject(token(), objects.getString(index), sealed)
                sent.add(objects.getString(index))
                touch()
                progress(minOf(start + (index + 1) * chunk, start + file.optLong("size")), total)
                true
            } catch (e: Exception) {
                false
            }
        }
        val read = try {
            Native.answer(answer)
            true
        } catch (e: KeylessException) {
            false
        }
        if (read && sent.size == objects.length()) {
            uploaded.put(file.getString("id"))
            used += stored
        } else if (sent.isNotEmpty()) {
            try {
                Server.deleteObjects(token(), sent)
            } catch (ignored: Exception) {
                // Left for the desktop's cleanup.
            }
        }
        done = start + file.optLong("size")
        progress(done, total)
    }
    val committed = Native.obj("importCommit", JSONObject().put("targets", targetsJson).put("uploaded", uploaded).put("now", now()))
    val items = committed.getJSONArray("items")
    // In batches, each vault's rows applied as the server answers them.
    val byVault = (0 until items.length()).map { items.getJSONObject(it) }.groupBy { it.getString("vaultId") }
    var added = 0
    for ((vaultId, list) in byVault) {
        for (batch in list.chunked(100)) {
            val rows = JSONArray()
            for (item in batch) {
                rows.put(JSONObject().put("id", item.getString("id")).put("vault_id", vaultId).put("enc_overview", item.getString("encOverview")).put("enc_details", item.getString("encDetails")))
            }
            val answered = Server.insertItems(token(), rows)
            Native.run("applyItems", JSONObject().put("vaultId", vaultId).put("items", answered))
            added += answered.length()
        }
    }
    save()
    refreshCache()
    return JSONObject().put("items", added).put("files", committed.optInt("files")).put("filesFailed", committed.optInt("filesFailed"))
}

fun Keyless.importCancel() {
    Native.run("importCancel")
}

// ----- exporting ----------------------------------------------------------------

/**
 * Makes an export of every item the user can read: `format` is csv, json,
 * cxf, zip, 1pux or backup (encrypted with `password`). Returns the file's
 * bytes, how many items it holds, and how many attached files were left out.
 */
fun Keyless.export(format: String, masterPassword: String, password: String?, includePasskeys: Boolean, progress: Progress): Triple<ByteArray, Int, Int> {
    val args = JSONObject().put("format", format).put("masterPassword", masterPassword).put("secretKey", secretKey()).put("includePasskeys", includePasskeys).put("now", now())
    if (password != null) args.put("password", password)
    val started = Native.obj("exportStart", args)
    val files = started.getJSONArray("files")
    val total = (0 until files.length()).sumOf { files.getJSONObject(it).optLong("size") }
    var done = 0L
    var missing = 0
    try {
        progress(0, total)
        for (i in 0 until files.length()) {
            val file = files.getJSONObject(i)
            val id = file.getString("id")
            val objects = file.getJSONArray("objects")
            try {
                for (n in 0 until objects.length()) {
                    Native.answer(Native.exportChunk(id, n, Server.downloadObject(token(), objects.getString(n))))
                    touch()
                }
            } catch (e: KeylessException) {
                if (e.key == "session_expired" || e.key == "device_revoked") throw e
                Native.run("exportFileFailed", JSONObject().put("id", id))
                missing++
            }
            done += file.optLong("size")
            progress(done, total)
        }
        val bytes = Native.exportFinish() ?: throw KeylessException("file_unwritable")
        return Triple(bytes, started.optInt("items"), missing)
    } catch (e: Exception) {
        Native.run("exportCancel")
        throw e
    }
}
