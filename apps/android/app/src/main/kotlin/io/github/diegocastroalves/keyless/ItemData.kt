package io.github.diegocastroalves.keyless

import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream

/*
 * What an item offers beyond its fields, as the desktop: earlier versions,
 * share links, attached files, its Wi-Fi QR code, and searching inside
 * items. Keys stay in the client (Rust): files cross it a chunk at a time.
 */

/** Where share links open (the site's share page). */
const val SHARE_BASE = "https://keyless.diegoalves.dev/share/"

/** The item's earlier versions, newest first, each with what the next one changed. */
fun Keyless.itemVersions(id: String): JSONArray =
    Native.arr("itemVersions", JSONObject().put("id", id).put("rows", Server.itemVersions(token(), id)))

/** Saves version `revision` as the item's newest. */
fun Keyless.restoreVersion(id: String, revision: Long) {
    val rows = Server.itemVersions(token(), id)
    upload(Native.obj("restoreVersion", JSONObject().put("id", id).put("rows", rows).put("revision", revision).put("now", now())))
}

/** A new link for an item; its answer holds the link, shown once. */
fun Keyless.createShare(itemId: String, hours: Int, viewOnce: Boolean, recipients: List<String>): JSONObject {
    val made = Native.obj(
        "shareCreate",
        JSONObject().put("itemId", itemId).put("hours", hours).put("viewOnce", viewOnce).put("recipients", JSONArray(recipients)).put("base", SHARE_BASE).put("now", now()),
    )
    Server.insertShare(token(), made.getJSONObject("row"))
    return made
}

/** The account's links (only `itemId`'s when given), newest first; `all` adds those that ended. */
fun Keyless.shareList(itemId: String?, all: Boolean): JSONArray {
    val args = JSONObject().put("rows", Server.shares(token())).put("all", all).put("now", now())
    if (itemId != null) args.put("itemId", itemId)
    return Native.arr("shareList", args)
}

fun Keyless.revokeShare(id: String) {
    Server.revokeShare(token(), id, Native.run("shareRevokedAt", JSONObject().put("now", now())) as String)
}

/** Ids of the items whose notes and other fields that are not secret hold `query`. */
fun Keyless.searchDetails(query: String): Set<String> {
    val ids = Native.arr("searchDetails", JSONObject().put("query", query))
    return (0 until ids.length()).map { ids.getString(it) }.toSet()
}

fun Keyless.itemsWithPasskeys(): Set<String> {
    val ids = Native.arr("itemsWithPasskeys")
    return (0 until ids.length()).map { ids.getString(it) }.toSet()
}

/** A Wi-Fi item's QR code, or any text's: its modules, row by row. */
fun Keyless.wifiQr(id: String): List<String> = Native.arr("wifiQr", JSONObject().put("id", id)).let { rows -> (0 until rows.length()).map { rows.getString(it) } }

fun Keyless.qrModules(text: String): List<String> = Native.arr("qrModules", JSONObject().put("text", text)).let { rows -> (0 until rows.length()).map { rows.getString(it) } }

/** A QR code in Keyless's look (`keyless_core::qr::art`), for the codes one Keyless app shows another. */
fun Keyless.qrArt(text: String): JSONObject = Native.obj("qrArt", JSONObject().put("text", text))

/** How strong a password is (`score` 0 to 4, `level`...) and whether another item uses it. */
fun Keyless.strength(password: String, itemId: String?): JSONObject {
    val args = JSONObject().put("password", password)
    if (itemId != null) args.put("itemId", itemId)
    return Native.obj("strength", args)
}

fun Keyless.sshGenerate(comment: String): JSONObject = Native.obj("sshGenerate", JSONObject().put("comment", comment))

fun Keyless.sshImport(privateKey: String, passphrase: String?, comment: String): JSONObject {
    val args = JSONObject().put("privateKey", privateKey).put("comment", comment)
    if (!passphrase.isNullOrEmpty()) args.put("passphrase", passphrase)
    return Native.obj("sshImport", args)
}

// ----- attached files --------------------------------------------------------

/** An item's attached files: id, name, size, createdAt. */
fun Keyless.attachments(itemId: String): JSONArray = Native.arr("attachments", JSONObject().put("itemId", itemId))

/** Bytes done of a file being moved, out of its size. */
typealias Progress = (done: Long, total: Long) -> Unit

/** The server's room for `stored` more bytes (it checks a whole chunk ahead). */
private fun Keyless.checkSpace(stored: Long) {
    val space = Server.attachmentSpace(token()) ?: return
    val chunk = 4L * 1024 * 1024 + 40
    if (space.optLong("used") + stored + chunk > space.optLong("quota")) {
        throw KeylessException("attachment_space_full", (space.optLong("quota") / (1024 * 1024)).toString())
    }
}

/**
 * Encrypts and uploads a file of `size` bytes from `input` for vault
 * `vaultId`; returns its id, ready to join an item. Whatever reached the
 * server goes if it fails.
 */
private fun Keyless.uploadFile(name: String, size: Long, vaultId: String, input: InputStream, progress: Progress): String {
    val file = Native.obj("attachmentNew", JSONObject().put("name", name).put("size", size).put("vaultId", vaultId).put("now", now()))
    val id = file.getString("id")
    val objects = file.getJSONArray("objects")
    val lens = file.getJSONArray("chunkLens")
    val sent = mutableListOf<String>()
    try {
        checkSpace(file.getLong("stored"))
        var done = 0L
        progress(0, size)
        for (i in 0 until objects.length()) {
            val plain = ByteArray(lens.getInt(i))
            var read = 0
            while (read < plain.size) {
                val n = input.read(plain, read, plain.size - read)
                if (n < 0) throw KeylessException("file_changed")
                read += n
            }
            val sealed = Native.attachmentSeal(id, i, plain) ?: throw KeylessException("file_changed")
            plain.fill(0)
            Server.uploadObject(token(), objects.getString(i), sealed)
            sent.add(objects.getString(i))
            touch()
            done += lens.getLong(i)
            progress(done, size)
        }
        // The file must not have grown while it was read.
        if (input.read() >= 0) throw KeylessException("file_changed")
        return id
    } catch (e: Exception) {
        Native.run("attachmentForget", JSONObject().put("id", id))
        try {
            if (sent.isNotEmpty()) Server.deleteObjects(token(), sent)
        } catch (ignored: Exception) {
            // Left for the desktop's cleanup.
        }
        throw e
    }
}

/** Attaches a file to an item. */
fun Keyless.attach(itemId: String, name: String, size: Long, input: InputStream, progress: Progress) {
    val vaultId = items.firstOrNull { it.id == itemId }?.vaultId ?: archived.firstOrNull { it.id == itemId }?.vaultId ?: throw KeylessException("not_found")
    val id = uploadFile(name, size, vaultId, input, progress)
    try {
        upload(Native.obj("attachmentsAdd", JSONObject().put("itemId", itemId).put("ids", JSONArray().put(id)).put("now", now())))
    } catch (e: Exception) {
        val file = Native.arr("attachments", JSONObject().put("itemId", itemId))
        if ((0 until file.length()).none { file.getJSONObject(it).optString("id") == id }) Native.run("attachmentForget", JSONObject().put("id", id))
        throw e
    }
}

/** A new Document item holding a file (the share menu's "Save in Keyless"); returns its id. */
fun Keyless.saveDocument(vaultId: String, name: String, size: Long, input: InputStream, label: String, progress: Progress): String {
    val id = uploadFile(name, size, vaultId, input, progress)
    return upload(Native.obj("documentNew", JSONObject().put("id", id).put("label", label).put("now", now())))
}

/** Downloads and decrypts an attached file into `out`, checking every chunk. */
fun Keyless.saveAttachment(itemId: String, attachmentId: String, out: OutputStream, progress: Progress) {
    val list = attachments(itemId)
    val file = (0 until list.length()).map { list.getJSONObject(it) }.firstOrNull { it.optString("id") == attachmentId } ?: throw KeylessException("not_found")
    val objects = file.getJSONArray("objects")
    val size = file.optLong("size")
    var done = 0L
    progress(0, size)
    for (i in 0 until objects.length()) {
        val raw = Server.downloadObject(token(), objects.getString(i))
        val plain = Native.attachmentOpen(itemId, attachmentId, i, raw) ?: throw KeylessException("attachment_damaged")
        out.write(plain)
        done += plain.size
        plain.fill(0)
        touch()
        progress(done, size)
    }
    out.flush()
}

/** Removes an attached file from its item, then from the server. */
fun Keyless.removeAttachment(itemId: String, attachmentId: String) {
    val sealed = Native.obj("attachmentRemove", JSONObject().put("itemId", itemId).put("attachmentId", attachmentId).put("now", now()))
    val objects = sealed.getJSONArray("objects")
    upload(sealed)
    try {
        Server.deleteObjects(token(), (0 until objects.length()).map { objects.getString(it) })
    } catch (e: Exception) {
        // Left for the desktop's cleanup.
    }
}
