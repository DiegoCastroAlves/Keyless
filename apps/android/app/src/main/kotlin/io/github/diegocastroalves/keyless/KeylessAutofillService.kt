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
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews

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

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }
}

object AutofillResponses {
    private fun presentation(context: Context, title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle ?: "")
        }

    /** The logins for the fields' app or website (null when there are none). */
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
        return if (count > 0) builder.build() else null
    }

    /** Locked: a suggestion that opens the unlock screen, which answers with the logins. */
    fun locked(context: Context, parsed: ParsedFields): FillResponse {
        val intent = Intent(context, AutofillAuthActivity::class.java)
        val sender = PendingIntent.getActivity(context, 1001, intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        return FillResponse.Builder()
            .setAuthentication(parsed.all.toTypedArray(), sender, presentation(context, context.getString(R.string.autofill_unlock), null))
            .build()
    }
}
