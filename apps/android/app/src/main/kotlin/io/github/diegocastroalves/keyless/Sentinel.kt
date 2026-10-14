package io.github.diegocastroalves.keyless

import android.app.AlertDialog
import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.Switch
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date
import kotlin.concurrent.thread

/**
 * Sentinel's data on the phone, computed by the Rust core as on the desktop
 * (`keyless_core::health`). The public lists are downloaded whole, about once
 * a day, and kept in the app's files; passwords are looked up on Have I Been
 * Pwned with k-anonymity (only 5 characters of each SHA-1 hash leave the
 * phone), and the results are kept encrypted with a key from the user key.
 */
object SentinelData {
    private const val DAY = 86_400L

    private fun dir(context: Context) = File(context.filesDir, "sentinel").apply { mkdirs() }

    private fun prefs(context: Context) = context.getSharedPreferences("keyless", Context.MODE_PRIVATE)

    fun listOn(context: Context, kind: String): Boolean = prefs(context).getBoolean("sentinel_list_$kind", true)

    fun setListOn(context: Context, kind: String, on: Boolean) {
        prefs(context).edit().putBoolean("sentinel_list_$kind", on).apply()
        // A list turned off is not kept.
        if (!on) File(dir(context), "$kind.json").delete()
    }

    /** Check the passwords online by itself (daily, and new ones as they come). */
    fun checkPasswords(context: Context): Boolean = prefs(context).getBoolean("sentinel_check_passwords", true)

    fun setCheckPasswords(context: Context, on: Boolean) = prefs(context).edit().putBoolean("sentinel_check_passwords", on).apply()

    private fun checks(context: Context): String? = File(dir(context), "checks").takeIf { it.exists() }?.readText()

    private fun now() = System.currentTimeMillis() / 1000

    private fun download(url: String, maxBytes: Int, headers: Map<String, String> = emptyMap()): String {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            setRequestProperty("User-Agent", "Keyless")
            for ((name, value) in headers) setRequestProperty(name, value)
        }
        try {
            if (connection.responseCode !in 200..299) throw IOException("HTTP ${connection.responseCode}")
            val out = java.io.ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    out.write(buffer, 0, read)
                    if (out.size() > maxBytes) throw IOException("too large")
                }
            }
            return out.toString(Charsets.UTF_8.name())
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Downloads what is due: the lists turned on (older than a day, or all
     * with `force`) and the passwords' breach check (daily, every password;
     * new ones in between). Errors leave the old copies.
     */
    fun refresh(context: Context, force: Boolean) {
        val lists = Native.arr("sentinelLists")
        for (i in 0 until lists.length()) {
            val list = lists.getJSONObject(i)
            val kind = list.getString("kind")
            if (!listOn(context, kind)) continue
            val file = File(dir(context), "$kind.json")
            val fetchedAt = if (file.exists()) JSONObject(file.readText()).optLong("fetchedAt") else 0L
            if (!force && now() - fetchedAt < DAY) continue
            try {
                val url = if (BuildConfig.SENTINEL.isEmpty()) list.getString("url") else "${BuildConfig.SENTINEL}lists/$kind"
                val body = download(url, list.getInt("maxBytes"))
                val read = Native.obj("sentinelParseList", JSONObject().put("kind", kind).put("body", body))
                // Turned off meanwhile: not kept.
                if (!listOn(context, kind)) continue
                val partial = File(dir(context), "$kind.json.part")
                partial.writeText(JSONObject().put("sites", read.getJSONObject("sites")).put("fetchedAt", now()).toString())
                partial.renameTo(file)
            } catch (e: Exception) {
                // Kept as it was; tried again later.
            }
        }
        if (!checkPasswords(context) && !force) return
        try {
            val queries = Native.obj("sentinelBreachQueries", JSONObject().put("checks", checks(context) ?: JSONObject.NULL).put("maxAge", if (force) 0 else DAY).put("now", now()))
            if (queries.optBoolean("upToDate")) return
            val prefixes = queries.getJSONArray("prefixes")
            val responses = JSONObject()
            for (i in 0 until prefixes.length()) {
                val prefix = prefixes.getString(i)
                val base = BuildConfig.SENTINEL.ifEmpty { "https://api.pwnedpasswords.com/" }
                responses.put(prefix, download("${base}range/$prefix", 4 * 1024 * 1024, mapOf("Add-Padding" to "true")))
            }
            val results = Native.obj("sentinelBreachResults", JSONObject().put("checks", checks(context) ?: JSONObject.NULL).put("all", queries.getBoolean("all")).put("responses", responses).put("now", now()))
            val partial = File(dir(context), "checks.part")
            partial.writeText(results.getString("checks"))
            partial.renameTo(File(dir(context), "checks"))
        } catch (e: Exception) {
            // Tried again later.
        }
    }

    /** The report for `vaultId` (every vault when null), from what the phone keeps. */
    fun report(context: Context, vaultId: String?): JSONObject {
        val lists = JSONObject()
        val off = JSONArray()
        val kinds = Native.arr("sentinelLists")
        for (i in 0 until kinds.length()) {
            val kind = kinds.getJSONObject(i).getString("kind")
            if (!listOn(context, kind)) {
                off.put(kind)
                continue
            }
            val file = File(dir(context), "$kind.json")
            lists.put(kind, if (file.exists()) JSONObject(file.readText()) else JSONObject.NULL)
        }
        val args = JSONObject().put("lists", lists).put("off", off).put("checks", checks(context) ?: JSONObject.NULL).put("now", now())
        if (vaultId != null) args.put("vaultId", vaultId)
        return Native.obj("sentinelReport", args)
    }

    /** Signing out: nothing of the account stays. */
    fun forget(context: Context) {
        dir(context).deleteRecursively()
    }
}

/** The alerts in the order Sentinel lists them, with their desktop text keys. */
private val ALERTS = listOf(
    "breached" to "breached", "compromised" to "compromised", "lastpass" to "lastpass", "weak" to "weak", "reused" to "reused",
    "unsecured" to "unsecured", "expiring" to "expiring", "two_factor" to "twoFactor", "passkey" to "passkey", "duplicate" to "duplicate",
)

private const val SERIOUS = "breached,compromised,lastpass,weak,reused,unsecured"

private fun Context.st(path: String, vars: Map<String, Any> = emptyMap()) = Labels.t(this, "sentinel.$path", vars)

private fun dateOf(seconds: Long): String = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(seconds * 1000))

/** A summary card for the item list: the score and the serious alerts; opens Sentinel. */
internal fun MainActivity.sentinelCard(holder: LinearLayout) {
    thread {
        val summary = try {
            SentinelData.report(this, null).getJSONObject("summary")
        } catch (e: Exception) {
            null
        }
        runOnUiThread {
            holder.removeAllViews()
            if (summary == null || summary.optInt("checked") == 0) return@runOnUiThread
            val issues = summary.getJSONObject("issues")
            val serious = SERIOUS.split(",").sumOf { issues.optJSONArray(it)?.length() ?: 0 }
            val card = panel()
            val line = row()
            line.add(label(summary.optInt("score").toString(), 22f, bold = true).apply { setTextColor(accent()) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            val texts = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), 0, 0, 0)
            }
            texts.add(label(st("title"), 14f, bold = true))
            texts.add(label(if (serious == 0) st("noSeriousAlerts") else st("seriousAlerts", mapOf("count" to serious)), 13f, muted = true))
            line.add(texts, width = 0, weight = 1f)
            card.add(line)
            card.setOnClickListener { showSentinel(null) }
            holder.add(card)
        }
    }
}

/** Sentinel: the score, each alert's items, the strength levels and the settings. */
internal fun MainActivity.showSentinel(vaultId: String?) {
    val page = column(20)
    page.add(plainButton("← " + getString(R.string.back)) { showList() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    page.add(label(st("title"), 24f, bold = true), top = 8)
    page.add(label(st("subtitle"), 13f, muted = true), top = 4)
    val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(body, top = 12)
    body.add(label(getString(R.string.syncing), 14f, muted = true))
    show("sentinel", page)
    thread {
        val report = try {
            SentinelData.report(this, vaultId)
        } catch (e: Exception) {
            e
        }
        runOnUiThread {
            if (screen != "sentinel") return@runOnUiThread
            body.removeAllViews()
            if (report is Exception) {
                body.add(label(errorText(report), 14f).apply { setTextColor(getColor(R.color.danger)) })
            } else {
                sentinelOverview(body, report as JSONObject, vaultId)
            }
        }
    }
}

private fun MainActivity.sentinelOverview(body: LinearLayout, report: JSONObject, vaultId: String?) {
    val summary = report.getJSONObject("summary")
    val issues = summary.getJSONObject("issues")

    val vaults = (0 until Keyless.vaults.length()).map { Keyless.vaults.getJSONObject(it) }
    if (vaults.size > 1) {
        val spinner = Spinner(this)
        val names = listOf(st("scopeAll")) + vaults.map { it.optString("name") }
        spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, names)
        spinner.setSelection(if (vaultId == null) 0 else vaults.indexOfFirst { it.optString("id") == vaultId } + 1)
        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val chosen = if (position == 0) null else vaults[position - 1].optString("id")
                if (chosen != vaultId) showSentinel(chosen)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        body.add(spinner)
    }

    val score = panel()
    val line = row()
    line.add(label(summary.optInt("score").toString(), 40f, bold = true).apply { setTextColor(accent()) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    val texts = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(14), 0, 0, 0)
    }
    texts.add(label(st("score"), 16f, bold = true))
    texts.add(label(st("checked", mapOf("count" to summary.optInt("checked"))), 13f, muted = true))
    line.add(texts, width = 0, weight = 1f)
    score.add(line)
    body.add(score, top = 8)

    val checkedAt = report.optLong("passwordsCheckedAt")
    if (checkedAt > 0) body.add(label(st("lastChecked", mapOf("when" to dateOf(checkedAt))), 12f, muted = true), top = 8)
    val listsAt = report.optLong("listsUpdatedAt")
    if (listsAt > 0) body.add(label(st("listsUpdated", mapOf("when" to dateOf(listsAt))), 12f, muted = true), top = 2)
    val unchecked = report.optInt("unchecked")
    if (unchecked > 0) body.add(label(st("unchecked", mapOf("count" to unchecked)), 12f, muted = true), top = 2)
    lateinit var check: android.widget.Button
    check = primaryButton(st("checkBreaches")) {
        check.isEnabled = false
        check.text = st("checkingBreaches")
        thread {
            SentinelData.refresh(this, force = true)
            runOnUiThread { if (screen == "sentinel") showSentinel(vaultId) }
        }
    }
    body.add(check, top = 8)

    var any = false
    for ((alert, key) in ALERTS) {
        val list = issues.optJSONArray(alert) ?: continue
        if (list.length() == 0) continue
        any = true
        val rowView = row().apply { setPadding(dp(4), dp(10), dp(4), dp(10)) }
        rowView.add(label(st(key), 16f), width = 0, weight = 1f)
        rowView.add(label(list.length().toString(), 16f, bold = true).apply { setTextColor(if (alert in SERIOUS.split(",")) getColor(R.color.danger) else accent()) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        rowView.setOnClickListener { showSentinelAlert(alert, key, report, vaultId) }
        body.add(rowView, top = 4)
    }
    if (!any) body.add(label(st("allGood"), 15f).apply { setTextColor(accent()) }, top = 12)

    // How many passwords at each strength level.
    val strengths = summary.optJSONArray("strengths")
    if (strengths != null && summary.optInt("checked") > 0) {
        body.add(label(st("strengthTitle"), 16f, bold = true), top = 20)
        body.add(label(st("strengthHint"), 12f, muted = true), top = 2)
        val total = (0 until strengths.length()).sumOf { strengths.optInt(it) }.coerceAtLeast(1)
        for (level in 0 until strengths.length()) {
            val count = strengths.optInt(level)
            if (count == 0) continue
            val bar = row().apply { setPadding(0, dp(6), 0, dp(6)) }
            bar.add(label(Labels.t(this, "strength.$level"), 14f), width = dp(110))
            val fill = View(this).apply {
                background = GradientDrawable().apply {
                    cornerRadius = dp(4).toFloat()
                    setColor(if (level <= 1) getColor(R.color.danger) else accent())
                }
            }
            bar.addView(fill, LinearLayout.LayoutParams(0, dp(10), count.toFloat() / total))
            bar.addView(View(this), LinearLayout.LayoutParams(0, dp(10), 1f - count.toFloat() / total))
            bar.add(label(" $count", 14f), width = ViewGroup.LayoutParams.WRAP_CONTENT)
            bar.setOnClickListener { showSentinelLevel(level, report, vaultId) }
            body.add(bar)
        }
    }

    // Ignored alerts, those resolved marked.
    val ignored = report.optJSONArray("ignored")
    if (ignored != null && ignored.length() > 0) {
        val stale = report.optJSONArray("stale")?.let { s -> (0 until s.length()).map { s.getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } }.toSet() } ?: emptySet()
        body.add(label(st("ignoredTitle"), 16f, bold = true), top = 20)
        for (i in 0 until ignored.length()) {
            val pair = ignored.getJSONArray(i)
            val (id, alert) = pair.getString(0) to pair.getString(1)
            val title = Keyless.items.firstOrNull { it.id == id }?.title ?: continue
            val entry = row()
            val text = "$title · ${st("alert.$alert")}" + if (id to alert in stale) " · ${st("staleShort")}" else ""
            entry.add(label(text, 14f), width = 0, weight = 1f)
            entry.add(plainButton(if (id to alert in stale) st("removeIgnore") else st("watchAgain")) {
                act({ Keyless.upload(Native.obj("sentinelIgnore", JSONObject().put("id", id).put("alerts", JSONArray().put(alert)).put("ignored", false).put("now", System.currentTimeMillis() / 1000))) }) { showSentinel(vaultId) }
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            body.add(entry, top = 2)
        }
    }

    // What Sentinel downloads.
    body.add(label(st("listsTitle"), 16f, bold = true), top = 20)
    body.add(label(st("breachPrivacy"), 12f, muted = true), top = 2)
    body.add(Switch(this).apply {
        text = st("autoCheck")
        isChecked = SentinelData.checkPasswords(this@sentinelOverview)
        setOnCheckedChangeListener { _, on -> SentinelData.setCheckPasswords(this@sentinelOverview, on) }
    }, top = 8)
    for ((kind, key) in listOf("breaches" to "listBreaches", "twoFactor" to "listTwoFactor", "passkeys" to "listPasskeys")) {
        body.add(Switch(this).apply {
            text = st(key)
            isChecked = SentinelData.listOn(this@sentinelOverview, kind)
            setOnCheckedChangeListener { _, on ->
                SentinelData.setListOn(this@sentinelOverview, kind, on)
                if (on) thread { SentinelData.refresh(this@sentinelOverview, force = false); runOnUiThread { if (screen == "sentinel") showSentinel(vaultId) } }
            }
        }, top = 4)
    }
}

/** One alert's items, with what each one is about, and ignoring it. */
private fun MainActivity.showSentinelAlert(alert: String, key: String, report: JSONObject, vaultId: String?) {
    val list = report.getJSONObject("summary").getJSONObject("issues").optJSONArray(alert) ?: JSONArray()
    val httpsReady = report.optJSONArray("httpsReady")?.let { r -> (0 until r.length()).map { r.getString(it) }.toSet() } ?: emptySet()
    val page = column(20)
    page.add(plainButton("← " + st("overview")) { showSentinel(vaultId) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    page.add(label(st(key), 22f, bold = true), top = 8)
    page.add(label(st(key + "Hint"), 13f, muted = true), top = 4)
    for (i in 0 until list.length()) {
        val issue = list.getJSONObject(i)
        val id = issue.getString("id")
        val item = Keyless.items.firstOrNull { it.id == id } ?: continue
        val panel = panel()
        panel.add(label(item.title, 16f, bold = true))
        val note = when (alert) {
            "breached" -> st("breachedSeen", mapOf("formatted" to NumberFormat.getInstance().format(issue.optLong("seen"))))
            "reused" -> st("sharedWith", mapOf("count" to issue.optInt("others")))
            "duplicate" -> st("duplicateNote", mapOf("count" to issue.optInt("others")))
            "compromised" -> st("compromisedNote", mapOf("site" to issue.optString("site"), "date" to issue.optString("date")))
            "two_factor" -> st("twoFactorNote", mapOf("site" to issue.optString("site")))
            "passkey" -> st("passkeyNote", mapOf("site" to issue.optString("site")))
            "expiring" -> st(if (issue.optBoolean("expired")) "expiredOn" else "expiresOn", mapOf("date" to dateOf(issue.optLong("expiresAt"))))
            else -> item.subtitle
        }
        if (note.isNotBlank()) panel.add(label(note, 13f, muted = true), top = 2)
        issue.optJSONObject("breach")?.let { breach ->
            val leaked = breach.optJSONArray("dataClasses")
            if (leaked != null && leaked.length() > 0) {
                panel.add(label(st("breachLeaked") + " " + (0 until leaked.length()).joinToString(", ") { leaked.getString(it) }, 12f, muted = true), top = 2)
            }
        }
        val actions = row()
        actions.add(plainButton(getString(R.string.open)) { showItem(id) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        if (alert == "unsecured" && id in httpsReady && Keyless.canWrite(item.vaultId)) {
            actions.add(plainButton(st("useHttps")) {
                act({ Keyless.upload(Native.obj("sentinelUseHttps", JSONObject().put("id", id).put("now", System.currentTimeMillis() / 1000))) }) {
                    Toast.makeText(this, st("httpsDone"), Toast.LENGTH_SHORT).show()
                    showSentinel(vaultId)
                }
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        if (Keyless.canWrite(item.vaultId)) {
            actions.add(plainButton(st("ignoreShort")) {
                AlertDialog.Builder(this)
                    .setTitle(st("ignore"))
                    .setMessage(item.title)
                    .setPositiveButton(st("ignoreShort")) { _, _ ->
                        act({ Keyless.upload(Native.obj("sentinelIgnore", JSONObject().put("id", id).put("alerts", JSONArray().put(alert)).put("ignored", true).put("now", System.currentTimeMillis() / 1000))) }) { showSentinel(vaultId) }
                    }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        panel.add(actions)
        page.add(panel, top = 8)
    }
    if (list.length() == 0) page.add(label(st("listEmpty"), 14f, muted = true), top = 12)
    show("sentinel-list", page)
}

/** The items whose password is at a strength level. */
private fun MainActivity.showSentinelLevel(level: Int, report: JSONObject, vaultId: String?) {
    val levels = report.optJSONObject("levels") ?: JSONObject()
    val page = column(20)
    page.add(plainButton("← " + st("overview")) { showSentinel(vaultId) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    page.add(label(Labels.t(this, "strength.$level"), 22f, bold = true), top = 8)
    for (item in Keyless.items) {
        if (levels.optInt(item.id, -1) != level) continue
        if (vaultId != null && item.vaultId != vaultId) continue
        val entry = panel()
        entry.add(label(item.title, 16f))
        if (item.subtitle.isNotBlank()) entry.add(label(item.subtitle, 13f, muted = true))
        entry.setOnClickListener { showItem(item.id) }
        page.add(entry, top = 6)
    }
    show("sentinel-list", page)
}
