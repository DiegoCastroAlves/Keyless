package io.github.diegocastroalves.keyless

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import kotlin.concurrent.thread

/**
 * Website icons for logins, as the desktop has them (keyless_core::site_icons):
 * each one downloaded from the site itself (never through a service that would
 * learn which sites are saved), only from public `https` addresses, decoded and
 * drawn again here as a small PNG, and kept in the app's files sealed with a
 * key derived from the account's key, under a keyed hash of the host.
 *
 * The names are checked before each connection (the connection itself
 * resolves them again); a name that later points at the local network would
 * still have to pass the certificate check for that name.
 */
object SiteIcons {
    private const val SETTING = "site_icons"
    private const val SIZE = 64
    /** A page is read up to the end of its head, where icons are declared. */
    private const val MAX_PAGE = 2 * 1024 * 1024
    private const val MAX_ICON = 1024 * 1024
    private const val REFRESH_AFTER = 30L * 24 * 3600 * 1000
    /** Sites without an icon are asked again after a week. */
    private const val RETRY_AFTER = 7L * 24 * 3600 * 1000
    /** Sites expect a browser; this is not one, but it asks like one. */
    private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36"

    /** An icon to show; `padded` ones are transparent and go on a light tile. */
    class Icon(val bitmap: Bitmap, val padded: Boolean)

    private val shown = ConcurrentHashMap<String, Icon>()
    private val running = AtomicBoolean(false)

    /** Whether the icons kept were read since unlocking (and fetched since the last sync). */
    @Volatile private var fresh = false

    /** Told (on a worker thread) when there are new icons to show. */
    @Volatile var changed: (() -> Unit)? = null

    private fun prefs(context: Context) = context.getSharedPreferences("keyless", Context.MODE_PRIVATE)

    fun enabled(context: Context): Boolean = prefs(context).getBoolean(SETTING, true)

    fun setEnabled(context: Context, on: Boolean) {
        prefs(context).edit().putBoolean(SETTING, on).apply()
        if (on) {
            refresh(context, force = true)
        } else {
            clear(context)
            changed?.invoke()
        }
    }

    /** The icon of a website's host, when there is one. */
    fun of(host: String): Icon? = shown[host.lowercase().removePrefix("www.")]

    /** Locked: the icons leave memory (the sealed files stay). */
    fun forget() {
        shown.clear()
        fresh = false
    }

    /** Signed out, or turned off: the files go too. */
    fun clear(context: Context) {
        forget()
        folder(context).deleteRecursively()
    }

    private fun folder(context: Context) = File(context.noBackupFilesDir, "site-icons")

    /** Shows the kept icons and fetches the missing and old ones, in the background (`force`: after a sync). */
    fun refresh(context: Context, force: Boolean = false) {
        if (!enabled(context) || !Keyless.isUnlocked || (fresh && !force)) return
        if (!running.compareAndSet(false, true)) return
        val app = context.applicationContext
        thread {
            try {
                run(app)
                fresh = true
            } catch (e: Exception) {
                // Locked meanwhile, or offline: next time.
            } finally {
                running.set(false)
            }
        }
    }

    private fun run(context: Context) {
        val hosts = Native.arr("siteIconHosts")
        val folder = folder(context).apply { mkdirs() }
        val due = mutableListOf<Pair<String, String>>()
        var added = false
        val now = System.currentTimeMillis()
        for (i in 0 until hosts.length()) {
            val host = hosts.getJSONObject(i).getString("host")
            val id = hosts.getJSONObject(i).getString("id")
            val file = File(folder, id)
            if (file.exists()) {
                val icon = open(id, file.readText())
                if (icon != null && shown.put(host, icon) == null) added = true
                if (now - file.lastModified() < if (icon != null) REFRESH_AFTER else RETRY_AFTER) continue
            }
            due.add(host to id)
        }
        if (added) changed?.invoke()
        if (due.isEmpty()) return
        val pool = Executors.newFixedThreadPool(4)
        try {
            val tasks = due.map { (host, id) -> Triple(host, id, pool.submit<Pair<ByteArray, Boolean>?> { fetch(host) }) }
            var stored = 0
            for ((host, id, task) in tasks) {
                val icon = try {
                    task.get(60, TimeUnit.SECONDS)
                } catch (e: Exception) {
                    null
                }
                if (!Keyless.isUnlocked || !enabled(context)) return
                val args = JSONObject().put("id", id)
                if (icon != null) args.put("png", Base64.encodeToString(icon.first, Base64.NO_WRAP)).put("opaque", icon.second)
                File(folder, id).writeText(Native.run("siteIconSeal", args) as String)
                if (icon != null) {
                    val bitmap = BitmapFactory.decodeByteArray(icon.first, 0, icon.first.size) ?: continue
                    shown[host] = Icon(bitmap, !icon.second)
                    if (++stored % 10 == 0) changed?.invoke()
                }
            }
            if (stored % 10 != 0) changed?.invoke()
        } finally {
            pool.shutdownNow()
        }
    }

    private fun open(id: String, data: String): Icon? {
        val opened = Native.run("siteIconOpen", JSONObject().put("id", id).put("data", data)) as? JSONObject ?: return null
        val png = Base64.decode(opened.getString("png"), Base64.DEFAULT)
        val bitmap = BitmapFactory.decodeByteArray(png, 0, png.size) ?: return null
        return Icon(bitmap, opened.optBoolean("padded"))
    }

    // ----- fetching ----------------------------------------------------------------

    /** The site's icon as a PNG, and whether it is opaque. */
    private fun fetch(host: String): Pair<ByteArray, Boolean>? {
        val home = URL("https://$host/")
        val candidates = mutableListOf<String>()
        get(home, page = true)?.let { (page, html) ->
            val links = Native.arr("siteIconLinks", JSONObject().put("html", String(html, Charsets.UTF_8)).put("url", page.toString()))
            for (i in 0 until links.length()) candidates.add(links.getString(i))
            candidates.add(URL(page, "/favicon.ico").toString())
        }
        candidates.add(URL(home, "/favicon.ico").toString())
        for (candidate in candidates.distinct().take(5)) {
            val (_, bytes) = get(URL(candidate), page = false) ?: continue
            toPng(bytes)?.let { return it }
        }
        return null
    }

    /** Only `https`, to public names whose addresses are all public. */
    private fun allowed(url: URL): Boolean {
        if (url.protocol != "https" || url.host.isNullOrEmpty()) return false
        if (Native.run("siteIconAllowed", JSONObject().put("host", url.host)) != true) return false
        return try {
            val addresses = InetAddress.getAllByName(url.host)
            addresses.isNotEmpty() && addresses.all { Native.run("publicAddress", JSONObject().put("ip", it.hostAddress)) == true }
        } catch (e: Exception) {
            false
        }
    }

    /** GET with size limits, following up to five redirects itself; the final address and the body. */
    private fun get(start: URL, page: Boolean): Pair<URL, ByteArray>? {
        var url = start
        for (hop in 0..5) {
            if (!allowed(url)) return null
            val connection = url.openConnection() as HttpsURLConnection
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 8_000
            connection.readTimeout = 15_000
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("Accept", if (page) "text/html" else "image/*")
            try {
                val code = connection.responseCode
                if (code in 300..399) {
                    url = URL(url, connection.getHeaderField("Location") ?: return null)
                    continue
                }
                if (code !in 200..299) return null
                val limit = if (page) MAX_PAGE else MAX_ICON
                if (!page && connection.contentLengthLong > limit) return null
                val out = ByteArrayOutputStream()
                val buffer = ByteArray(16 * 1024)
                connection.inputStream.use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        out.write(buffer, 0, read)
                        if (page && String(buffer, 0, read, Charsets.ISO_8859_1).contains("</head>", ignoreCase = true)) break
                        if (out.size() > limit) {
                            if (page) break else return null
                        }
                    }
                }
                return url to out.toByteArray()
            } catch (e: Exception) {
                return null
            } finally {
                connection.disconnect()
            }
        }
        return null
    }

    /** Decodes an icon (PNG, ICO, JPEG, GIF, WebP, BMP; never SVG) with size limits, and draws it again as a PNG of at most SIZE pixels. */
    private fun toPng(bytes: ByteArray): Pair<ByteArray, Boolean>? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth < 16 || bounds.outHeight < 16 || bounds.outWidth > 1024 || bounds.outHeight > 1024) return null
        val image = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null
        val scale = minOf(1f, SIZE.toFloat() / maxOf(image.width, image.height))
        val icon = if (scale < 1f) Bitmap.createScaledBitmap(image, (image.width * scale).toInt().coerceAtLeast(1), (image.height * scale).toInt().coerceAtLeast(1), true) else image
        val pixels = IntArray(icon.width * icon.height)
        icon.getPixels(pixels, 0, icon.width, 0, 0, icon.width, icon.height)
        val opaque = pixels.count { (it ushr 24) > 200 } * 10 >= pixels.size * 9
        val out = ByteArrayOutputStream()
        if (!icon.compress(Bitmap.CompressFormat.PNG, 100, out)) return null
        return out.toByteArray() to opaque
    }
}
