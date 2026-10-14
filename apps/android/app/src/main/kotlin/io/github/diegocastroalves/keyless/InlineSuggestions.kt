package io.github.diegocastroalves.keyless

import android.app.PendingIntent
import android.app.slice.Slice
import android.app.slice.SliceSpec
import android.content.Context
import android.content.Intent
import android.graphics.BlendMode
import android.graphics.drawable.Icon
import android.net.Uri
import android.service.autofill.InlinePresentation
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.inline.InlinePresentationSpec
import androidx.annotation.RequiresApi

/**
 * Suggestions as chips in the keyboard (Android 11+), for keyboards that
 * ask for them, like Gboard.
 *
 * The keyboard draws them through Android with the renderer of androidx's
 * autofill library, so a chip is a Slice in that library's "v1" format:
 * uri "inline.slice", spec type "androidx.autofill.inline.ui.version:v1",
 * and items told apart by their hints (start icon, title, subtitle, an
 * action to show where the chip comes from, a content description). A
 * keyboard lists the versions it can draw in each spec's style bundle; for
 * any other, no chip is made and Android shows the list under the field.
 */
@RequiresApi(30)
object InlineSuggestions {
    private const val VERSION = "androidx.autofill.inline.ui.version:v1"
    private const val VERSIONS_KEY = "androidx.autofill.inline.ui.version:key"
    private const val SLICE_URI = "inline.slice"
    private const val HINT_START_ICON = "inline_start_icon"
    private const val HINT_TITLE = "inline_title"
    private const val HINT_SUBTITLE = "inline_subtitle"
    private const val HINT_ATTRIBUTION = "inline_attribution"
    private const val HINT_CONTENT_DESCRIPTION = "inline_content_description"

    /** Whether the keyboard can draw our chips with this spec. */
    fun supported(spec: InlinePresentationSpec): Boolean = spec.style.getStringArrayList(VERSIONS_KEY)?.contains(VERSION) == true

    /** Opened by a long press on a chip: the autofill check screen. */
    private fun attribution(context: Context): PendingIntent =
        PendingIntent.getActivity(context, 3900, Intent(context, AutofillCheckActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    fun slice(context: Context, title: String, subtitle: String?): Slice {
        val builder = Slice.Builder(Uri.parse(SLICE_URI), SliceSpec(VERSION, 1))
        // The app's own colors, not the keyboard's tint.
        val icon = Icon.createWithResource(context, R.mipmap.ic_launcher).setTintBlendMode(BlendMode.DST)
        builder.addIcon(icon, null, listOf(HINT_START_ICON))
        builder.addText(title, null, listOf(HINT_TITLE))
        if (!subtitle.isNullOrEmpty()) builder.addText(subtitle, null, listOf(HINT_SUBTITLE))
        builder.addAction(attribution(context), Slice.Builder(builder).addHints(listOf(HINT_ATTRIBUTION)).build(), null)
        val description = if (subtitle.isNullOrEmpty()) title else "$title, $subtitle"
        builder.addText(context.getString(R.string.inline_description, description), null, listOf(HINT_CONTENT_DESCRIPTION))
        return builder.build()
    }

    /** Chips for one answer: as many as the keyboard has room for, each with its spec (the last one repeats). */
    class Chips(private val context: Context, private val request: InlineSuggestionsRequest) {
        private var used = 0

        fun next(title: String, subtitle: String?): InlinePresentation? {
            val specs = request.inlinePresentationSpecs
            if (specs.isEmpty() || used >= request.maxSuggestionCount) return null
            val spec = specs[minOf(used, specs.size - 1)]
            if (!supported(spec)) return null
            used++
            return try {
                InlinePresentation(slice(context, title, subtitle), spec, false)
            } catch (e: Exception) {
                null
            }
        }
    }
}
