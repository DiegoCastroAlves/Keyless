package io.github.diegocastroalves.keyless

import android.content.Context
import android.content.pm.Signature
import android.net.Uri
import android.util.Base64
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Who asks for a passkey, and whether it may have one for a site:
 *
 * - a browser reports the page's origin, believed only for the browsers in
 *   Google's list of privileged ones (checked by their signing certificate);
 *   the origin must be the site or a subdomain of it, over https;
 * - any other app must be named by the site itself, in its Digital Asset
 *   Links (`https://<site>/.well-known/assetlinks.json`, relation
 *   `delegate_permission/common.get_login_creds`), with its signing
 *   certificate. Its origin is then `android:apk-key-hash:<hash>`.
 *
 * Network calls: call off the main thread.
 */
object Origins {
    private const val ALLOWLIST_URL = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"
    private const val DAY_MS = 24 * 60 * 60 * 1000L

    private fun fetch(url: String): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.instanceFollowRedirects = false
        try {
            if (connection.responseCode != 200) throw KeylessException("passkey_origin", "HTTP ${connection.responseCode} from $url")
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }

    /** Google's list of browsers that may report origins (kept a day). */
    private fun allowlist(context: Context): String {
        val prefs = context.getSharedPreferences("keyless", Context.MODE_PRIVATE)
        val cached = prefs.getString("browser_allowlist", null)
        if (cached != null && System.currentTimeMillis() - prefs.getLong("browser_allowlist_at", 0) < DAY_MS) return cached
        return try {
            val fresh = fetch(ALLOWLIST_URL)
            prefs.edit().putString("browser_allowlist", fresh).putLong("browser_allowlist_at", System.currentTimeMillis()).apply()
            fresh
        } catch (e: Exception) {
            cached ?: throw KeylessException("passkey_origin", "no browser list: ${e.message}")
        }
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun fingerprint(signature: Signature): String = sha256(signature.toByteArray()).joinToString(":") { "%02X".format(it) }

    private fun certificates(info: CallingAppInfo): List<Signature> {
        val signing = info.signingInfo
        return if (signing.hasMultipleSigners()) signing.apkContentsSigners.toList() else signing.signingCertificateHistory.toList()
    }

    /** The origin to put in the WebAuthn answer, once `info` may use passkeys for `rpId`; throws otherwise. */
    fun origin(context: Context, info: CallingAppInfo, rpId: String): String {
        val site = rpId.trim().lowercase()
        if (site.isEmpty()) throw KeylessException("passkey_origin", "no site")
        if (info.isOriginPopulated()) {
            val origin = try {
                info.getOrigin(allowlist(context))
            } catch (e: Exception) {
                null
            } ?: throw KeylessException("passkey_origin", "${info.packageName} is not a privileged browser")
            val uri = Uri.parse(origin)
            val host = uri.host?.lowercase() ?: throw KeylessException("passkey_origin", "no host in $origin")
            if (uri.scheme != "https" || !(host == site || host.endsWith(".$site"))) {
                throw KeylessException("passkey_origin", "$origin cannot use passkeys of $site")
            }
            return origin.trimEnd('/')
        }
        val certificates = certificates(info)
        if (certificates.isEmpty()) throw KeylessException("passkey_origin", "no certificate")
        val wanted = certificates.map { fingerprint(it) }.toSet()
        val links = try {
            val url = if (BuildConfig.ASSET_LINKS.isEmpty()) "https://$site/.well-known/assetlinks.json" else "${BuildConfig.ASSET_LINKS}$site.json"
            JSONArray(fetch(url))
        } catch (e: Exception) {
            throw KeylessException("passkey_origin", "no Digital Asset Links for $site")
        }
        var allowed = false
        for (i in 0 until links.length()) {
            val statement = links.optJSONObject(i) ?: continue
            val relations = statement.optJSONArray("relation") ?: continue
            val target = statement.optJSONObject("target") ?: continue
            val relation = (0 until relations.length()).any { relations.optString(it) == "delegate_permission/common.get_login_creds" }
            if (!relation || target.optString("namespace") != "android_app" || target.optString("package_name") != info.packageName) continue
            val prints = target.optJSONArray("sha256_cert_fingerprints") ?: continue
            if ((0 until prints.length()).any { prints.optString(it).uppercase() in wanted }) allowed = true
        }
        if (!allowed) throw KeylessException("passkey_origin", "$site does not name ${info.packageName} with ${wanted.joinToString()}")
        val hash = Base64.encodeToString(sha256(certificates.last().toByteArray()), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        return "android:apk-key-hash:$hash"
    }
}
