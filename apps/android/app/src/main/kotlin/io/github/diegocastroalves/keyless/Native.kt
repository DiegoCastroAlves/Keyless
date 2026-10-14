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

    /** The answer's value: a JSONObject, JSONArray, String, Number, Boolean or null. */
    fun run(method: String, args: Any? = null): Any? {
        val text = when (args) {
            null -> ""
            is String -> args
            else -> args.toString()
        }
        val answer = JSONObject(call(method, text))
        val error = answer.optJSONObject("error")
        if (error != null) throw KeylessException(error.optString("key"), error.optString("message"))
        return if (answer.isNull("ok")) null else answer.get("ok")
    }

    fun obj(method: String, args: Any? = null): JSONObject = run(method, args) as JSONObject

    fun arr(method: String, args: Any? = null): JSONArray = run(method, args) as JSONArray
}
