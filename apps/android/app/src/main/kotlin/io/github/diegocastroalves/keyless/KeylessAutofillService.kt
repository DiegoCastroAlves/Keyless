package io.github.diegocastroalves.keyless

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import android.widget.Toast
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Fills logins, credit cards and identities in apps and browsers. While
 * Keyless is locked it offers to unlock (AutofillAuthActivity); unlocked,
 * the logins of the app (linked to it, or of the sites naming it: AppSites)
 * or website, best first, then "Search Keyless" to choose any login
 * (AutofillPickActivity), and the cards or identities a payment or address
 * form asks for. Suggestions show in the keyboard when it can show them
 * (Android 11+), in a list otherwise. It never fills Keyless itself.
 */
class KeylessAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val parsed = AutofillParser.parse(structure)
        if (!parsed.anything || parsed.packageName == packageName || !Keyless.hasAccount) {
            callback.onSuccess(null)
            return
        }
        val asked = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) request.inlineSuggestionsRequest else null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) AutofillCheck.noteInlineRequest(this, asked != null)
        val inline = if (AutofillCheck.inlineEnabled(this)) asked else null
        if (!Keyless.isUnlocked) {
            // The sites the app names, asked while the user unlocks.
            if (parsed.logins && parsed.webDomain == null) AppSites.warm(this, parsed.packageName)
            val response = try {
                AutofillResponses.locked(this, parsed, inline)
            } catch (e: Exception) {
                null
            }
            callback.onSuccess(response)
            return
        }
        // An app's logins may wait for its sites (AppSites). Android waits 5
        // seconds for the answer: a sync gets a part of them.
        thread {
            Keyless.syncBriefly(1_500)
            val response = try {
                AutofillResponses.datasets(this, parsed, inline)
            } catch (e: Exception) {
                null
            }
            if (!cancellationSignal.isCanceled) callback.onSuccess(response)
        }
    }

    /** What was typed: saved now when unlocked, or after unlocking. */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess()
            return
        }
        val parsed = AutofillParser.parse(structure)
        // A username may have been typed on an earlier screen.
        val values = HashMap<android.view.autofill.AutofillId, String>()
        request.fillContexts.forEach { values.putAll(AutofillParser.values(it.structure)) }
        val password = parsed.passwords.firstNotNullOfOrNull { values[it]?.takeIf { v -> v.isNotEmpty() } }
        if (password == null || parsed.packageName == packageName) {
            callback.onSuccess()
            return
        }
        val earlier = request.fillContexts.dropLast(1).flatMap { AutofillParser.parse(it.structure).usernames }
        val username = (parsed.usernames + earlier).firstNotNullOfOrNull { values[it]?.takeIf { v -> v.isNotBlank() } } ?: ""
        val title = parsed.webDomain ?: appName(parsed.packageName)
        val pending = Keyless.PendingSave(parsed.webDomain, if (parsed.webDomain == null) parsed.packageName else null, title, username.trim(), password)
        if (Keyless.isUnlocked) {
            thread {
                val result = try {
                    Keyless.saveLogin(pending.domain, pending.packageName, pending.title, pending.username, pending.password)
                    getString(R.string.saved)
                } catch (e: Exception) {
                    errorText(e)
                }
                android.os.Handler(mainLooper).post { Toast.makeText(this, result, Toast.LENGTH_SHORT).show() }
            }
            callback.onSuccess()
        } else {
            Keyless.pendingSave = pending
            val intent = Intent(this, AutofillAuthActivity::class.java).putExtra(AutofillAuthActivity.EXTRA_SAVE, true)
            callback.onSuccess(PendingIntent.getActivity(this, 1002, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE).intentSender)
        }
    }

    private fun appName(packageName: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageName, 0)).toString()
    } catch (e: Exception) {
        packageName
    }
}

object AutofillResponses {
    private fun presentation(context: Context, title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle ?: "")
        }

    /** A suggestion's list entry, and its chip in the keyboard when there is room for one. */
    @Suppress("DEPRECATION")
    private fun dataset(context: Context, chips: InlineSuggestions.Chips?, title: String, subtitle: String?): Dataset.Builder {
        val builder = Dataset.Builder(presentation(context, title, subtitle))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) chips?.next(title, subtitle)?.let { builder.setInlinePresentation(it) }
        return builder
    }

    /** Asks Android to offer saving what is typed in these fields. */
    private fun saveInfo(parsed: ParsedFields): SaveInfo? {
        if (parsed.passwords.isEmpty()) return null
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (parsed.usernames.isEmpty()) 0 else SaveInfo.SAVE_DATA_TYPE_USERNAME)
        val builder = SaveInfo.Builder(type, parsed.passwords.toTypedArray())
        if (parsed.usernames.isNotEmpty()) builder.setOptionalIds(parsed.usernames.toTypedArray())
        return builder.build()
    }

    /** A login's username, password and one-time password (an otpauth:// address). */
    class LoginValues(val username: String?, val password: String?, val totp: String?)

    fun loginValues(item: JSONObject): LoginValues {
        val fields = item.getJSONObject("details").optJSONArray("fields")
        var username: String? = null
        var password: String? = null
        var totp: String? = null
        val all = ArrayList<JSONObject>()
        if (fields != null) for (i in 0 until fields.length()) all.add(fields.getJSONObject(i))
        item.getJSONObject("details").optJSONArray("sections")?.let { sections ->
            for (s in 0 until sections.length()) sections.optJSONObject(s)?.optJSONArray("fields")?.let { f -> for (i in 0 until f.length()) all.add(f.getJSONObject(i)) }
        }
        for ((index, field) in all.withIndex()) {
            val value = field.optString("value").ifEmpty { null } ?: continue
            when {
                field.optString("purpose") == "username" && index < (fields?.length() ?: 0) -> if (username == null) username = value
                field.optString("purpose") == "password" && index < (fields?.length() ?: 0) -> if (password == null) password = value
                field.optString("kind") == "totp" -> if (totp == null) totp = value
            }
        }
        return LoginValues(username, password, totp)
    }

    /** The values to put in the fields, for a login. */
    @Suppress("DEPRECATION")
    fun fillLogin(builder: Dataset.Builder, values: LoginValues, usernames: List<AutofillId>, passwords: List<AutofillId>): Boolean {
        var filled = false
        values.username?.let { u -> usernames.forEach { builder.setValue(it, AutofillValue.forText(u)); filled = true } }
        values.password?.let { p -> passwords.forEach { builder.setValue(it, AutofillValue.forText(p)); filled = true } }
        return filled
    }

    /**
     * The logins for the fields' app or website, the cards or identities
     * for a payment or address form, and the offer to save (null when none
     * applies). A login with a one-time password goes through
     * AutofillFillActivity, which copies the code once it is chosen. May
     * wait for the network (AppSites): off the main thread.
     */
    @Suppress("DEPRECATION")
    fun datasets(context: Context, parsed: ParsedFields, inline: InlineSuggestionsRequest?): FillResponse? {
        // A chip kept for "Search Keyless", at the end.
        val chips = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inline != null) InlineSuggestions.Chips(context, inline, reserved = if (parsed.logins) 1 else 0) else null
        val builder = FillResponse.Builder()
        var count = 0
        if (parsed.logins) {
            val matches = (if (parsed.webDomain != null) Keyless.matches(parsed.webDomain, null) else AppSites.logins(context, parsed.packageName)).take(8)
            for ((index, match) in matches.withIndex()) {
                val values = loginValues(Keyless.item(match.id))
                if (values.username == null && values.password == null) continue
                val dataset = dataset(context, chips, match.title, values.username)
                if (!fillLogin(dataset, values, parsed.usernames, parsed.passwords)) continue
                if (values.totp != null) {
                    val intent = Intent(context, AutofillFillActivity::class.java)
                        .putExtra(AutofillFillActivity.EXTRA_ITEM, match.id)
                        .putParcelableArrayListExtra(AutofillFillActivity.EXTRA_USERNAMES, ArrayList(parsed.usernames))
                        .putParcelableArrayListExtra(AutofillFillActivity.EXTRA_PASSWORDS, ArrayList(parsed.passwords))
                    val sender = PendingIntent.getActivity(context, 4000 + index, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE).intentSender
                    dataset.setAuthentication(sender)
                }
                builder.addDataset(dataset.build())
                count++
            }
        }
        if (parsed.cards || parsed.identities) count += forms(context, parsed, builder, chips)
        if (parsed.logins) {
            builder.addDataset(pickDataset(context, parsed, chips))
            count++
        }
        val save = saveInfo(parsed)
        if (save != null) builder.setSaveInfo(save)
        return if (count > 0 || save != null) builder.build() else null
    }

    /**
     * "Search Keyless": any login for these fields, chosen in
     * AutofillPickActivity, which can link it to the app or site. The only
     * suggestion for an app with no login linked yet (Instagram, for a login
     * saved for instagram.com).
     */
    @Suppress("DEPRECATION")
    private fun pickDataset(context: Context, parsed: ParsedFields, chips: InlineSuggestions.Chips?): Dataset {
        val title = context.getString(R.string.autofill_pick)
        val builder = Dataset.Builder(presentation(context, title, null))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) chips?.next(title, null, last = true)?.let { builder.setInlinePresentation(it) }
        // The values come once a login is chosen.
        for (id in (parsed.usernames + parsed.passwords).distinct()) builder.setValue(id, null)
        val intent = Intent(context, AutofillPickActivity::class.java)
            .putParcelableArrayListExtra(AutofillPickActivity.EXTRA_USERNAMES, ArrayList(parsed.usernames))
            .putParcelableArrayListExtra(AutofillPickActivity.EXTRA_PASSWORDS, ArrayList(parsed.passwords))
            .putExtra(AutofillPickActivity.EXTRA_PACKAGE, if (parsed.webDomain == null) parsed.packageName else null)
            .putExtra(AutofillPickActivity.EXTRA_DOMAIN, parsed.webDomain)
        val sender = PendingIntent.getActivity(context, 4900, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE).intentSender
        builder.setAuthentication(sender)
        return builder.build()
    }

    /** The cards and identities that fit the form, each filling every field it has a value for. */
    @Suppress("DEPRECATION")
    private fun forms(context: Context, parsed: ParsedFields, builder: FillResponse.Builder, chips: InlineSuggestions.Chips?): Int {
        // Cards only on secure pages.
        val secure = parsed.webDomain == null || parsed.webScheme == null || parsed.webScheme.equals("https", ignoreCase = true)
        val items = Native.obj("autofillItems", parsed.formJson()).optJSONArray("items") ?: return 0
        var count = 0
        for (i in 0 until minOf(items.length(), 10)) {
            val item = items.getJSONObject(i)
            if (item.optString("category") == "credit_card" && !secure) continue
            val values = item.optJSONArray("values") ?: continue
            val dataset = dataset(context, chips, item.optString("title"), item.optString("subtitle").ifEmpty { null })
            var filled = false
            for ((index, field) in parsed.formFields.withIndex()) {
                if (index >= values.length() || values.isNull(index)) continue
                val value = when (val v = values.get(index)) {
                    is String -> AutofillValue.forText(v)
                    is JSONObject -> when {
                        v.has("index") -> AutofillValue.forList(v.getInt("index"))
                        v.has("date") -> AutofillValue.forDate(v.getLong("date"))
                        else -> null
                    }
                    else -> null
                } ?: continue
                dataset.setValue(field.id, value)
                filled = true
            }
            if (!filled) continue
            builder.addDataset(dataset.build())
            count++
        }
        return count
    }

    /** Locked: a suggestion that opens the unlock screen, which answers with the suggestions. */
    @Suppress("DEPRECATION")
    fun locked(context: Context, parsed: ParsedFields, inline: InlineSuggestionsRequest?): FillResponse {
        val intent = Intent(context, AutofillAuthActivity::class.java)
        val sender = PendingIntent.getActivity(context, 1001, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        val title = context.getString(R.string.autofill_unlock)
        val chip = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inline != null) InlineSuggestions.Chips(context, inline).next(title, null) else null
        val builder = FillResponse.Builder()
        if (chip != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAuthentication(parsed.all.toTypedArray(), sender, presentation(context, title, null), chip)
        } else {
            builder.setAuthentication(parsed.all.toTypedArray(), sender, presentation(context, title, null))
        }
        saveInfo(parsed)?.let { builder.setSaveInfo(it) }
        return builder.build()
    }
}
