package io.github.diegocastroalves.keyless

import org.json.JSONArray
import org.json.JSONObject

/** An error from the client or the server, with a key the app translates. */
class KeylessException(val key: String, message: String = key) : Exception(message)

/**
 * The Keyless client in Rust (crates/keyless-android): keys, checks and
 * decryption. One method, JSON in and out.
 */
object Native {
    init {
        System.loadLibrary("keyless_android")
    }

    @JvmStatic
    external fun call(method: String, args: String): String

    /** The contents of the QR codes in a greyscale picture (rows `stride` bytes apart), as a JSON array. */
    @JvmStatic
    external fun decodeQr(pixels: ByteArray, width: Int, height: Int, stride: Int): String

    /** Chunk `index` of a new file (`attachmentNew`), encrypted; null if there is no such file. */
    @JvmStatic
    external fun attachmentSeal(attachmentId: String, index: Int, plain: ByteArray): ByteArray?

    /** Chunk `index` of an item's attachment, decrypted; null if it does not check out. */
    @JvmStatic
    external fun attachmentOpen(itemId: String, attachmentId: String, index: Int, raw: ByteArray): ByteArray?

    /** Reads an import file (and a KeePass key file); answers like `call`, with the counts. */
    @JvmStatic
    external fun importParse(args: String, file: ByteArray, keyFile: ByteArray?): String

    /** Reads, encrypts and hands the import's file `attachmentId` to `sink`, a chunk at a time. */
    @JvmStatic
    external fun importFile(attachmentId: String, sink: ChunkSink): String

    /** A downloaded chunk of an attached file being exported. */
    @JvmStatic
    external fun exportChunk(attachmentId: String, index: Int, raw: ByteArray): String

    /** The export's file; null if it failed. */
    @JvmStatic
    external fun exportFinish(): ByteArray?

    /** Where `importFile` puts each encrypted chunk; answers whether it went well. */
    fun interface ChunkSink {
        fun put(index: Int, sealed: ByteArray): Boolean
    }

    /** The answer's value: a JSONObject, JSONArray, String, Number, Boolean or null. */
    fun run(method: String, args: Any? = null): Any? {
        val text = when (args) {
            null -> ""
            is String -> args
            else -> args.toString()
        }
        return answer(call(method, text))
    }

    /** The value of an answer in `call`'s form, or its error thrown. */
    fun answer(text: String): Any? {
        val answer = JSONObject(text)
        val error = answer.optJSONObject("error")
        if (error != null) throw KeylessException(error.optString("key"), error.optString("message"))
        return if (answer.isNull("ok")) null else answer.get("ok")
    }

    fun obj(method: String, args: Any? = null): JSONObject = run(method, args) as JSONObject

    fun arr(method: String, args: Any? = null): JSONArray = run(method, args) as JSONArray
}
