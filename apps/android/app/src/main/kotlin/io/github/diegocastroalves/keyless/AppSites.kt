package io.github.diegocastroalves.keyless

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

/**
 * The websites an app signs in to without the user linking them
 * (AppLinks): those naming the app as their own in their Digital Asset
 * Links (`https://<site>/.well-known/assetlinks.json`), by its package and
 * signing certificate, to share sign-ins with it
 * (`delegate_permission/common.get_login_creds`) or to open their links
 * (`handle_all_urls`: the site vouches for the app all the same).
 * instagram.com names com.instagram.android so, and its logins then show
 * in the app too.
 *
 * Only two kinds of sites are asked, so none learns about the rest of the
 * vault: those the app names itself (its manifest's `asset_statements`),
 * and the sites of logins named like the app (instagram.com for
 * "Instagram"). What a site says is kept a week (a day when it names no
 * app); an answer waits for the network at most `waitMs`, and what comes
 * later serves the next one.
 */
object AppSites {
    /** How long autofill and Credential Manager wait for sites. */
    const val WAIT_MS = 2_000L
    private val RELATIONS = setOf("delegate_permission/common.get_login_creds", "delegate_permission/common.handle_all_urls")
    private const val DAY_MS = 24 * 60 * 60 * 1000L
    private const val WEEK_MS = 7 * DAY_MS
    /** A site that could not be reached is not asked again for this long. */
    private const val RETRY_MS = 10 * 60 * 1000L
    private const val MAX_SITES = 6
    private const val MAX_INCLUDES = 3
    private const val MAX_BYTES = 512 * 1024

    private val pool = Executors.newFixedThreadPool(3)
    /** The sites being asked now, each with what it will say. */
    private val asking = ConcurrentHashMap<String, Future<Map<String, Set<String>>?>>()
    private val failedAt = ConcurrentHashMap<String, Long>()

    /**
     * The logins for an app: those linked to it, then those of the sites
     * naming it. `fingerprints`: the app's certificates (SHA-256, as sites
     * write them), when the caller knows them; the installed app's
     * otherwise. Keyless must be unlocked; off the main thread.
     */
    fun logins(context: Context, packageName: String, fingerprints: Set<String>? = null, waitMs: Long = WAIT_MS): List<Summary> {
        val linked = Keyless.matches(null, packageName)
        val sites = try {
            verified(context, packageName, fingerprints ?: fingerprints(context, packageName), waitMs)
        } catch (e: Exception) {
            emptyList()
        }
        return (linked + sites.flatMap { Keyless.matches(it, null) }).distinctBy { it.id }
    }

    /** The sites, among the app's own and those named like it, that name the app with one of `fingerprints`. */
    private fun verified(context: Context, packageName: String, fingerprints: Set<String>, waitMs: Long): List<String> {
        if (fingerprints.isEmpty()) return emptyList()
        val named = Keyless.sitesNamed(AppLinks.words(AppLinks.label(context, packageName), packageName))
        val sites = (declared(context, packageName) + named).distinct().take(MAX_SITES)
        val deadline = SystemClock.elapsedRealtime() + waitMs
        val answers = sites.map { it to says(context, it) }
        return answers.filter { (_, answer) ->
            val apps = try {
                answer.get(maxOf(0L, deadline - SystemClock.elapsedRealtime()), TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                null
            }
            apps?.get(packageName)?.any { it in fingerprints } == true
        }.map { it.first }
    }

    /** Asks the sites the app names itself ahead (while Keyless is locked, say). */
    fun warm(context: Context, packageName: String) {
        declared(context, packageName).take(MAX_SITES).forEach { says(context, it) }
    }

    /** The certificates the installed app is signed with. */
    fun fingerprints(context: Context, packageName: String): Set<String> = try {
        val signing = context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
        when {
            signing == null -> emptySet()
            signing.hasMultipleSigners() -> signing.apkContentsSigners.map { Origins.fingerprint(it) }.toSet()
            else -> signing.signingCertificateHistory.map { Origins.fingerprint(it) }.toSet()
        }
    } catch (e: Exception) {
        emptySet()
    }

    /** The sites an app names itself, in its manifest (`asset_statements`): theirs to confirm. */
    @Suppress("DEPRECATION")
    private fun declared(context: Context, packageName: String): List<String> = try {
        val pm = context.packageManager
        val info = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
        val text = when (val value = info.metaData?.get("asset_statements")) {
            is Int -> pm.getResourcesForApplication(info).getString(value)
            is String -> value
            else -> "[]"
        }
        val statements = JSONArray(text)
        (0 until statements.length()).mapNotNull { i ->
            val statement = statements.optJSONObject(i) ?: return@mapNotNull null
            val target = statement.optJSONObject("target")
            val address = statement.optString("include").ifEmpty { if (target?.optString("namespace") == "web") target.optString("site") else "" }
            Uri.parse(address).takeIf { it.scheme == "https" }?.host?.lowercase()
        }
    } catch (e: Exception) {
        emptyList()
    }

    /** What a site says, kept or asked now: each app it names, with their certificates (null: unreachable). */
    private fun says(context: Context, site: String): Future<Map<String, Set<String>>?> {
        val prefs = context.getSharedPreferences("app_sites", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        try {
            prefs.getString(site, null)?.let { JSONObject(it) }?.let { kept ->
                val apps = kept.getJSONObject("apps")
                if (now - kept.getLong("at") < if (apps.length() == 0) DAY_MS else WEEK_MS) return CompletableFuture.completedFuture(read(apps))
            }
        } catch (e: JSONException) {
            // Asked again.
        }
        if (now - (failedAt[site] ?: 0L) < RETRY_MS) return CompletableFuture.completedFuture(null)
        val task = FutureTask(
            Callable {
                try {
                    val apps = ask(site)
                    prefs.edit().putString(site, JSONObject().put("at", System.currentTimeMillis()).put("apps", write(apps)).toString()).apply()
                    apps
                } catch (e: Exception) {
                    failedAt[site] = System.currentTimeMillis()
                    null
                }
            },
        )
        asking.putIfAbsent(site, task)?.let { return it }
        pool.execute {
            try {
                task.run()
            } finally {
                asking.remove(site, task)
            }
        }
        return task
    }

    private fun read(apps: JSONObject): Map<String, Set<String>> =
        apps.keys().asSequence().associateWith { name ->
            val prints = apps.getJSONArray(name)
            (0 until prints.length()).map { prints.getString(it) }.toSet()
        }

    private fun write(apps: Map<String, Set<String>>): JSONObject =
        JSONObject().also { json -> apps.forEach { (name, prints) -> json.put(name, JSONArray(prints.toList())) } }

    /** Asks a site (or its www. host, when it has no file) for its statements. Throws when it cannot be reached. */
    private fun ask(site: String): Map<String, Set<String>> {
        val statements = statements(fileOf(site)) ?: (if (site.startsWith("www.")) null else statements(fileOf("www.$site"))) ?: return emptyMap()
        val apps = HashMap<String, MutableSet<String>>()
        var includes = 0
        fun take(list: JSONArray, nested: Boolean) {
            for (i in 0 until list.length()) {
                val statement = list.optJSONObject(i) ?: continue
                val include = statement.optString("include")
                if (include.isNotEmpty()) {
                    // Another file of the site's (only one level down).
                    if (nested || includes >= MAX_INCLUDES || Uri.parse(include).scheme != "https") continue
                    includes++
                    statements(include)?.let { take(it, nested = true) }
                    continue
                }
                val relations = statement.optJSONArray("relation") ?: continue
                val target = statement.optJSONObject("target") ?: continue
                val name = target.optString("package_name")
                val prints = target.optJSONArray("sha256_cert_fingerprints")
                if ((0 until relations.length()).none { relations.optString(it) in RELATIONS } || target.optString("namespace") != "android_app" || name.isEmpty() || prints == null) continue
                apps.getOrPut(name) { HashSet() }.addAll((0 until prints.length()).map { prints.optString(it).uppercase() })
            }
        }
        take(statements, nested = false)
        return apps
    }

    /** A host's file; test builds read it from the fake server. */
    private fun fileOf(host: String) = if (BuildConfig.ASSET_LINKS.isEmpty()) "https://$host/.well-known/assetlinks.json" else "${BuildConfig.ASSET_LINKS}$host.json"

    /** The statements at `url`, or null when there are none there (no file, no list). Throws when it cannot be reached. */
    private fun statements(url: String): JSONArray? {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = false
        try {
            if (connection.responseCode != 200) return null
            val body = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (body.size() + read > MAX_BYTES) return null
                    body.write(buffer, 0, read)
                }
            }
            return try {
                JSONArray(body.toString(Charsets.UTF_8.name()))
            } catch (e: JSONException) {
                null
            }
        } finally {
            connection.disconnect()
        }
    }
}
