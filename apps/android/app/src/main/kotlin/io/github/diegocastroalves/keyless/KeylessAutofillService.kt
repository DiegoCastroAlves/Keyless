package io.github.diegocastroalves.keyless

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.Toast
import kotlin.concurrent.thread

/**
 * Fills logins in apps and browsers. While Keyless is locked it offers to
 * unlock (AutofillAuthActivity); unlocked, the logins of the app or website,
 * best first. It never fills Keyless itself.
 */
class KeylessAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val parsed = AutofillParser.parse(structure)
        if ((parsed.passwords.isEmpty() && parsed.usernames.isEmpty()) || parsed.packageName == packageName || !Keyless.hasAccount) {
            callback.onSuccess(null)
            return
        }
        val response = try {
            if (Keyless.isUnlocked) AutofillResponses.datasets(this, parsed) else AutofillResponses.locked(this, parsed)
        } catch (e: Exception) {
            null
        }
        callback.onSuccess(response)
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

    /** Asks Android to offer saving what is typed in these fields. */
    private fun saveInfo(parsed: ParsedFields): SaveInfo? {
        if (parsed.passwords.isEmpty()) return null
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (parsed.usernames.isEmpty()) 0 else SaveInfo.SAVE_DATA_TYPE_USERNAME)
        val builder = SaveInfo.Builder(type, parsed.passwords.toTypedArray())
        if (parsed.usernames.isNotEmpty()) builder.setOptionalIds(parsed.usernames.toTypedArray())
        return builder.build()
    }

    /** The logins for the fields' app or website, and the offer to save (null when neither applies). */
    @Suppress("DEPRECATION")
    fun datasets(context: Context, parsed: ParsedFields): FillResponse? {
        val matches = Keyless.matches(parsed.webDomain, if (parsed.webDomain == null) parsed.packageName else null).take(8)
        val builder = FillResponse.Builder()
        var count = 0
        for (match in matches) {
            val details = Keyless.item(match.id).getJSONObject("details")
            val fields = details.optJSONArray("fields") ?: continue
            var username: String? = null
            var password: String? = null
            for (i in 0 until fields.length()) {
                val field = fields.getJSONObject(i)
                when (field.optString("purpose")) {
                    "username" -> if (username == null) username = field.optString("value").ifEmpty { null }
                    "password" -> if (password == null) password = field.optString("value").ifEmpty { null }
                }
            }
            if (username == null && password == null) continue
            val dataset = Dataset.Builder(presentation(context, match.title, username))
            var filled = false
            if (username != null) parsed.usernames.forEach { dataset.setValue(it, AutofillValue.forText(username)); filled = true }
            if (password != null) parsed.passwords.forEach { dataset.setValue(it, AutofillValue.forText(password)); filled = true }
            if (!filled) continue
            builder.addDataset(dataset.build())
            count++
        }
        val save = saveInfo(parsed)
        if (save != null) builder.setSaveInfo(save)
        return if (count > 0 || save != null) builder.build() else null
    }

    /** Locked: a suggestion that opens the unlock screen, which answers with the logins. */
    fun locked(context: Context, parsed: ParsedFields): FillResponse {
        val intent = Intent(context, AutofillAuthActivity::class.java)
        val sender = PendingIntent.getActivity(context, 1001, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        val builder = FillResponse.Builder()
            .setAuthentication(parsed.all.toTypedArray(), sender, presentation(context, context.getString(R.string.autofill_unlock), null))
        saveInfo(parsed)?.let { builder.setSaveInfo(it) }
        return builder.build()
    }
}
