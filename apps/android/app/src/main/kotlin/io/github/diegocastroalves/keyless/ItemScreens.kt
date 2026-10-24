package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.format.Formatter
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.MimeTypeMap
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ProgressBar
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/*
 * An item's screens beyond its fields, as the desktop: its history, share
 * links, attached files, Wi-Fi QR code and large type.
 */

private fun dateTime(seconds: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))

private const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

/** A dialog with a bar for a file being moved; `update` may be called from any thread. */
internal fun Activity.progressDialog(title: String): Pair<AlertDialog, Progress> {
    val bar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { max = 1000 }
    val box = column(20).apply { add(bar) }
    val dialog = AlertDialog.Builder(this).setTitle(title).setView(box).setCancelable(false).create()
    dialog.show()
    return dialog to { done, total -> runOnUiThread { bar.progress = if (total <= 0) 1000 else (done * 1000 / total).toInt() } }
}

// ----- history ------------------------------------------------------------------

internal fun MainActivity.showHistory(id: String, writable: Boolean) {
    val page = column(20)
    page.addBack { showItem(id) }
    page.add(label(t("itemHistory.title"), 24f, bold = true), top = 8)
    page.add(label(t("itemHistory.note"), 13f, muted = true), top = 4)
    val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(body, top = 12)
    body.add(label(t("itemHistory.loading"), 14f, muted = true))
    show("history", page)
    thread {
        val versions = try {
            Keyless.itemVersions(id)
        } catch (e: Exception) {
            runOnUiThread {
                body.removeAllViews()
                body.add(label(errorText(e), 14f).apply { setTextColor(getColor(R.color.danger)) })
            }
            return@thread
        }
        runOnUiThread {
            if (screen != "history") return@runOnUiThread
            body.removeAllViews()
            if (versions.length() == 0) body.add(label(t("itemHistory.empty"), 14f, muted = true))
            for (i in 0 until versions.length()) body.add(versionView(id, versions.getJSONObject(i), writable), top = if (i == 0) 0 else 12)
        }
    }
}

private fun MainActivity.versionView(id: String, version: JSONObject, writable: Boolean): View {
    val panel = panel()
    val overview = version.getJSONObject("overview")
    val details = version.getJSONObject("details")
    panel.add(label(dateTime(version.optLong("updatedAt")), 13f, bold = true, muted = true))
    panel.add(label(overview.optString("title"), 17f, bold = true), top = 4)
    val fields = mutableListOf<JSONObject>()
    details.optJSONArray("fields")?.let { list -> for (i in 0 until list.length()) fields.add(list.getJSONObject(i)) }
    details.optJSONArray("sections")?.let { sections ->
        for (s in 0 until sections.length()) sections.getJSONObject(s).optJSONArray("fields")?.let { list -> for (i in 0 until list.length()) fields.add(list.getJSONObject(i)) }
    }
    for (field in fields) {
        val value = field.optString("value")
        if (value.isEmpty()) continue
        val name = Labels.field(this, field.optString("label"))
        val secret = field.optString("kind") in listOf("concealed", "pin", "card_number", "security_question", "totp")
        val line = row()
        line.add(label(name, 13f, muted = true), width = 0, weight = 2f)
        val shown = label(if (secret) "••••••••" else value, 14f).apply { setTextIsSelectable(!secret) }
        line.add(shown, width = 0, weight = 3f)
        if (secret) {
            var open = false
            lateinit var toggle: android.widget.Button
            toggle = plainButton(t("common.show")) {
                open = !open
                shown.text = if (open) value else "••••••••"
                toggle.text = t(if (open) "common.hide" else "common.show")
            }
            line.add(toggle, width = WRAP)
        }
        panel.add(line, top = 2)
    }
    val notes = details.optString("notes")
    if (notes.isNotEmpty()) panel.add(label(notes, 14f).apply { setTextIsSelectable(true) }, top = 4)
    val changed = version.optJSONArray("changed")
    if (changed != null && changed.length() > 0) {
        val names = (0 until changed.length()).map { changed.getString(it) }.map { name ->
            if (name.startsWith(":")) t("itemHistory.changed.${name.removePrefix(":")}") else Labels.field(this, name)
        }
        panel.add(label(t("itemHistory.laterChanged", mapOf("list" to names.joinToString(", "))), 12f, muted = true), top = 6)
    }
    if (writable) {
        panel.add(plainButton(t("itemHistory.restore")) {
            AlertDialog.Builder(this)
                .setMessage(t("itemHistory.restoreConfirm"))
                .setPositiveButton(t("common.restore")) { _, _ ->
                    act({ Keyless.restoreVersion(id, version.getLong("revision")) }) {
                        Toast.makeText(this, t("itemHistory.restored"), Toast.LENGTH_SHORT).show()
                        showItem(id)
                    }
                }
                .setNegativeButton(t("common.cancel"), null)
                .show()
        }, width = WRAP, top = 4)
    }
    return panel
}

// ----- share links ----------------------------------------------------------------

private val SHARE_HOURS = listOf(1, 24, 7 * 24, 14 * 24, 30 * 24)

private fun Context.duration(hours: Int): String =
    if (hours < 24) t("share.hours", mapOf("count" to hours)) else t("share.days", mapOf("count" to hours / 24))

internal fun MainActivity.shareItem(id: String, title: String) {
    val box = column(20)
    box.add(label(t("share.description"), 13f, muted = true))
    box.add(label(t("share.expires"), 14f, bold = true), top = 12)
    val hours = RadioGroup(this)
    for (h in SHARE_HOURS) {
        hours.addView(RadioButton(this).apply {
            text = duration(h)
            this.id = View.generateViewId()
            tag = h
            isChecked = h == 7 * 24
        })
    }
    box.add(hours, top = 2)
    val once = Switch(this).apply { text = t("share.viewOnce") }
    box.add(once, top = 8)
    box.add(label(t("share.who"), 14f, bold = true), top = 12)
    val who = RadioGroup(this)
    val anyone = RadioButton(this).apply { text = t("share.anyone"); this.id = View.generateViewId(); isChecked = true }
    val only = RadioButton(this).apply { text = t("share.onlyEmails"); this.id = View.generateViewId() }
    who.addView(anyone)
    who.addView(only)
    box.add(who, top = 2)
    val emails = field(t("share.emailsPlaceholder"), TEXT_EMAIL).apply { visibility = View.GONE }
    val emailsHint = label(t("share.emailsHint"), 12f, muted = true).apply { visibility = View.GONE }
    box.add(emails, top = 2)
    box.add(emailsHint, top = 2)
    who.setOnCheckedChangeListener { _, checked ->
        val restricted = checked == only.id
        emails.visibility = if (restricted) View.VISIBLE else View.GONE
        emailsHint.visibility = emails.visibility
    }
    val links = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    box.add(links, top = 16)
    val dialog = AlertDialog.Builder(this)
        .setTitle(t("share.title", mapOf("title" to title)))
        .setView(ScrollView(this).apply { addView(box) })
        .setPositiveButton(t("share.create"), null)
        .setNegativeButton(t("common.close"), null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val chosen = hours.findViewById<RadioButton>(hours.checkedRadioButtonId)?.tag as? Int ?: 7 * 24
            val recipients = if (only.isChecked) emails.text.toString().split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() } else emptyList()
            if (only.isChecked && recipients.isEmpty()) {
                emails.error = t("errors.email_invalid")
                return@setOnClickListener
            }
            var made: JSONObject? = null
            act({ made = Keyless.createShare(id, chosen, once.isChecked, recipients) }) {
                dialog.dismiss()
                made?.let { showShareLink(it, recipients) }
            }
        }
    }
    dialog.show()
    loadShareLinks(id, links)
}

/** The link just made, shown once. */
private fun MainActivity.showShareLink(made: JSONObject, recipients: List<String>) {
    val link = made.getString("link")
    val box = column(20)
    box.add(label(t("share.onlyNow", mapOf("date" to dateTime(made.optLong("expiresAt")))), 13f, muted = true))
    if (recipients.isNotEmpty()) box.add(label(t("share.restrictedCreated", mapOf("emails" to recipients.joinToString(", "))), 13f, muted = true), top = 6)
    box.add(label(link, 14f).apply { setTextIsSelectable(true); typeface = Typeface.MONOSPACE }, top = 10)
    AlertDialog.Builder(this)
        .setTitle(t("share.link"))
        .setView(box)
        .setPositiveButton(t("common.copy")) { _, _ -> copy(t("share.link"), link) }
        .setNegativeButton(t("common.close"), null)
        .show()
}

private fun MainActivity.loadShareLinks(id: String, holder: LinearLayout) {
    thread {
        val list = try {
            Keyless.shareList(id, all = false)
        } catch (e: Exception) {
            return@thread
        }
        runOnUiThread {
            holder.removeAllViews()
            if (list.length() == 0) return@runOnUiThread
            holder.add(label(t("share.active"), 14f, bold = true))
            for (i in 0 until list.length()) {
                val share = list.getJSONObject(i)
                val line = row()
                val views = share.optInt("views")
                val text = buildString {
                    append(t("share.until", mapOf("date" to dateTime(share.optLong("expiresAt")))))
                    append(" · ")
                    if (!share.isNull("maxViews")) append(t("share.viewsOf", mapOf("count" to views, "max" to share.optInt("maxViews")))) else append(t("share.views", mapOf("count" to views)))
                    val emails = share.optJSONArray("recipients")
                    if (emails != null && emails.length() > 0) append("\n").append(t("share.onlyFor", mapOf("emails" to (0 until emails.length()).joinToString(", ") { emails.getString(it) })))
                }
                line.add(label(text, 13f), width = 0, weight = 1f)
                line.add(plainButton(t("share.revoke")) {
                    act({ Keyless.revokeShare(share.getString("id")) }) {
                        Toast.makeText(this, t("share.revoked"), Toast.LENGTH_SHORT).show()
                        loadShareLinks(id, holder)
                    }
                }, width = WRAP)
                holder.add(line, top = 4)
            }
        }
    }
}

// ----- an item held down in a list -----------------------------------------------------

/**
 * What can be done with an item without opening it, as the desktop's menu on
 * a right click: copying its username, password or code, marking it, editing,
 * sharing, archiving or deleting it. In Recently Deleted: restoring it, or
 * deleting it for good.
 */
internal fun MainActivity.itemActions(id: String, anchor: View) {
    val item = try {
        Keyless.item(id)
    } catch (e: KeylessException) {
        return
    }
    val overview = item.getJSONObject("overview")
    val details = item.getJSONObject("details")
    val title = overview.optString("title")
    val writable = Keyless.canWrite(item.optString("vaultId"))
    val trashed = overview.has("trashed_at") && !overview.isNull("trashed_at")
    val fields = mutableListOf<JSONObject>()
    fun collect(list: JSONArray?) {
        if (list != null) for (i in 0 until list.length()) fields.add(list.getJSONObject(i))
    }
    collect(details.optJSONArray("fields"))
    val sections = details.optJSONArray("sections")
    if (sections != null) for (i in 0 until sections.length()) collect(sections.getJSONObject(i).optJSONArray("fields"))
    fun value(test: (JSONObject) -> Boolean) = fields.firstOrNull { test(it) && it.optString("value").isNotEmpty() }?.optString("value").orEmpty()
    val username = value { it.optString("purpose") == "username" }
    val password = value { it.optString("purpose") == "password" }
    val totp = value { it.optString("kind") == "totp" }
    // After a change: the list in place, or the tab drawn again.
    val redraw = { if (screen == "list") listRefresh?.invoke() ?: showMain() else showMain() }
    val done = { message: String -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show() }

    val menu = PopupMenu(this, anchor)
    val actions = mutableListOf<() -> Unit>()
    fun add(text: String, run: () -> Unit) {
        menu.menu.add(0, actions.size, actions.size, text)
        actions.add(run)
    }
    if (trashed) {
        if (writable) {
            add(t("common.restore")) { act({ Keyless.setTrashed(id, false) }) { done(t("item.restored")); redraw() } }
            add(getString(R.string.delete_forever)) {
                AlertDialog.Builder(this)
                    .setTitle(R.string.delete_forever)
                    .setMessage(getString(R.string.delete_forever_body, title))
                    .setPositiveButton(R.string.delete_forever) { _, _ -> act({ Keyless.deleteForGood(id) }) { redraw() } }
                    .setNegativeButton(R.string.cancel, null)
                    .show()
            }
        }
    } else {
        if (username.isNotEmpty()) add(t("item.copyUsername")) { copy(t("item.username"), username) }
        if (password.isNotEmpty()) add(t("item.copyPassword")) { copy(t("item.password"), password) }
        if (totp.isNotEmpty()) {
            add(t("item.copyCode")) {
                try {
                    copy(t("item.code"), Keyless.totp(totp).getString("code"))
                } catch (e: KeylessException) {
                    Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
                }
            }
        }
        val favorite = overview.optBoolean("favorite")
        add(t(if (favorite) "item.unfavorite" else "item.favorite")) { act({ Keyless.setFavorite(id, !favorite) }) { redraw() } }
        if (writable) add(t("common.edit")) { editItem(id) }
        add(t("share.action")) { shareItem(id, title) }
        if (writable) {
            val archived = overview.optBoolean("archived")
            add(t(if (archived) "item.unarchive" else "item.archive")) {
                act({ Keyless.setArchived(id, !archived) }) {
                    if (!archived) done(t("item.archived"))
                    redraw()
                }
            }
            add(t("item.moveToTrash")) { act({ Keyless.setTrashed(id, true) }) { done(t("item.movedToTrash")); redraw() } }
        }
    }
    if (actions.isEmpty()) return
    menu.setOnMenuItemClickListener { choice ->
        actions[choice.itemId]()
        true
    }
    menu.show()
}

// ----- passkeys ------------------------------------------------------------------------

/** The item's passkeys, as rows of its fields (after the username), each with a way to delete it. */
internal fun MainActivity.passkeyRows(id: String, passkeys: JSONArray?, writable: Boolean): List<View> {
    if (passkeys == null) return emptyList()
    return (0 until passkeys.length()).map { i ->
        val passkey = passkeys.getJSONObject(i)
        val user = passkey.optString("userName")
        val value = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        value.addView(label(passkey.optString("rpId") + if (user.isNotEmpty()) " · $user" else "", 16f))
        val created = passkey.optLong("createdAt")
        if (created > 0) value.addView(label(t("item.passkeyCreated", mapOf("date" to DateFormat.getDateInstance().format(Date(created * 1000)))), 12f, muted = true))
        val delete = iconButton(R.drawable.ic_trash, t("common.delete")) {
            AlertDialog.Builder(this)
                .setMessage(t("item.passkeyDeleteConfirm"))
                .setPositiveButton(t("common.delete")) { _, _ ->
                    act({ Keyless.removePasskey(id, passkey.getString("credentialId")) }) {
                        Toast.makeText(this, t("item.passkeyDeleted"), Toast.LENGTH_SHORT).show()
                        showItem(id)
                    }
                }
                .setNegativeButton(t("common.cancel"), null)
                .show()
        }
        val row = if (writable) fieldRow(t("item.passkey"), value, delete) else fieldRow(t("item.passkey"), value)
        // Its name with a small fingerprint, as the desktop's.
        ((row.getChildAt(0) as LinearLayout).getChildAt(0) as TextView).apply {
            setCompoundDrawablesRelative(iconDrawable(R.drawable.ic_fingerprint, accent()).apply { setBounds(0, 0, dp(14), dp(14)) }, null, null, null)
            compoundDrawablePadding = dp(6)
        }
        row
    }
}

// ----- attached files -----------------------------------------------------------------

/** The item's files, to save or remove, and a button to attach more. */
internal fun MainActivity.attachmentsSection(page: LinearLayout, id: String, writable: Boolean) {
    val files = try {
        Keyless.attachments(id)
    } catch (e: KeylessException) {
        JSONArray()
    }
    if (files.length() == 0 && !writable) return
    page.add(sectionTitle(t("item.attachments")), top = 20)
    val card = card()
    for (i in 0 until files.length()) {
        val file = files.getJSONObject(i)
        val actions = row()
        actions.addView(iconButton(R.drawable.ic_download, t("item.attachmentSave")) { saveAttachmentAs(id, file) })
        if (writable) {
            actions.addView(iconButton(R.drawable.ic_trash, t("common.delete")) {
                AlertDialog.Builder(this)
                    .setMessage(t("item.attachmentDeleteConfirm"))
                    .setPositiveButton(t("common.delete")) { _, _ ->
                        act({ Keyless.removeAttachment(id, file.getString("id")) }) {
                            Toast.makeText(this, t("item.attachmentDeleted"), Toast.LENGTH_SHORT).show()
                            showItem(id)
                        }
                    }
                    .setNegativeButton(t("common.cancel"), null)
                    .show()
            })
        }
        val clip = icon(R.drawable.ic_paperclip, getColor(R.color.muted), 20)
        card.add(listRow(clip, file.optString("name"), Formatter.formatShortFileSize(this, file.optLong("size")), actions).apply {
            minimumHeight = dp(56)
            background = null
        })
    }
    if (writable) {
        card.add(listRow(icon(R.drawable.ic_plus, accent(), 20), t("item.attach"), null).apply {
            minimumHeight = dp(52)
            ((getChildAt(1) as LinearLayout).getChildAt(0) as TextView).setTextColor(accent())
            setOnClickListener { attachFile(id) }
        })
    }
    page.add(card, top = 8)
}

/** The name and size of a file the user picked. */
internal fun Context.fileInfo(uri: Uri): Pair<String, Long> {
    var name = "file"
    var size = -1L
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            cursor.getString(0)?.let { name = it }
            if (!cursor.isNull(1)) size = cursor.getLong(1)
        }
    }
    if (size < 0) size = contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
    if (size < 0) throw KeylessException("file_unreadable")
    return name to size
}

internal fun MainActivity.attachFile(id: String) = pickFile { attachFiles(id, listOf(it)) }

/** Asks for a file (the system's picker). */
internal fun MainActivity.pickFile(onPick: (Uri) -> Unit) {
    val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
    startForResult(pick) { result, data ->
        val uri = data?.data
        if (result == Activity.RESULT_OK && uri != null) onPick(uri)
    }
}

/** Attaches the files at `uris` to the item, one after the other, each with its progress. */
internal fun MainActivity.attachFiles(id: String, uris: List<Uri>, attached: Int = 0) {
    val uri = uris.firstOrNull() ?: return
    val (name, size) = try {
        fileInfo(uri)
    } catch (e: Exception) {
        Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
        return
    }
    val (dialog, progress) = progressDialog(t("item.attachmentUploading", mapOf("name" to name, "percent" to "")).trimEnd('%', ' '))
    act({
        try {
            contentResolver.openInputStream(uri)?.use { input -> Keyless.attach(id, name, size, input, progress) } ?: throw KeylessException("file_unreadable")
        } finally {
            runOnUiThread { dialog.dismiss() }
        }
    }) {
        if (uris.size > 1) return@act attachFiles(id, uris.drop(1), attached + 1)
        Toast.makeText(this, t("item.attachmentsAdded", mapOf("count" to attached + 1)), Toast.LENGTH_SHORT).show()
        showItem(id)
    }
}

private fun MainActivity.saveAttachmentAs(id: String, file: JSONObject) {
    val name = file.optString("name")
    val type = MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"
    val create = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(type).putExtra(Intent.EXTRA_TITLE, name)
    startForResult(create) { result, data ->
        val uri = data?.data
        if (result != Activity.RESULT_OK || uri == null) return@startForResult
        val (dialog, progress) = progressDialog(t("item.attachmentDownloading", mapOf("name" to name, "percent" to "")).trimEnd('%', ' '))
        act({
            try {
                contentResolver.openOutputStream(uri, "wt")?.use { out -> Keyless.saveAttachment(id, file.getString("id"), out, progress) } ?: throw KeylessException("file_unwritable")
            } catch (e: Exception) {
                // No half-written decrypted file stays behind.
                try {
                    DocumentsContract.deleteDocument(contentResolver, uri)
                } catch (ignored: Exception) {
                }
                throw e
            } finally {
                runOnUiThread { dialog.dismiss() }
            }
        }) {
            Toast.makeText(this, t("item.attachmentSaved"), Toast.LENGTH_SHORT).show()
        }
    }
}

// ----- QR codes and large type ------------------------------------------------------------

/** A QR code drawn from its modules ('1' dark), with its quiet zone, as large as it fits (up to `maxSide` pixels). */
class QrView(context: Context, private val modules: List<String>, private val maxSide: Int = Int.MAX_VALUE) : View(context) {
    private val dark = Paint().apply { color = Color.BLACK }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val side = minOf(MeasureSpec.getSize(widthMeasureSpec), maxSide)
        setMeasuredDimension(side, side)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawColor(Color.WHITE)
        val count = modules.size + 8
        // Whole pixels per module, centered: cells of a fractional size leave
        // seams between them on low-density screens, which readers trip on.
        val cell = maxOf(1, width / count)
        val offset = ((width - cell * count) / 2).toFloat()
        for ((y, line) in modules.withIndex()) {
            for ((x, module) in line.withIndex()) {
                if (module != '1') continue
                val left = offset + (x + 4) * cell
                val top = offset + (y + 4) * cell
                canvas.drawRect(left, top, left + cell, top + cell, dark)
            }
        }
    }
}

/**
 * A QR code in Keyless's look, from `keyless_core::qr::art`: dots, rounded
 * patterns and the logo in the middle, as the desktop draws it. Whole pixels
 * per module, as `QrView`; up to `maxSide` pixels.
 */
class BrandedQrView(context: Context, art: JSONObject, private val maxSide: Int = Int.MAX_VALUE) : View(context) {
    private val size = art.getInt("size")
    private val modules = art.getJSONArray("modules").let { rows -> (0 until rows.length()).map { rows.getString(it) } }
    private val finders = art.getJSONArray("finders").let { list -> (0 until list.length()).map { list.getJSONArray(it).let { p -> p.getInt(0) to p.getInt(1) } } }
    private val alignments = art.getJSONArray("alignments").let { list -> (0 until list.length()).map { list.getJSONArray(it).let { p -> p.getInt(0) to p.getInt(1) } } }
    private val logoRadius = art.getDouble("logo_radius").toFloat()
    private val dot = art.getDouble("dot_radius").toFloat()
    private val finderCorners = art.getJSONArray("finder_corners").let { c -> FloatArray(3) { c.getDouble(it).toFloat() } }
    private val alignmentCorners = art.getJSONArray("alignment_corners").let { c -> FloatArray(2) { c.getDouble(it).toFloat() } }
    // Near black, as the desktop: lighter colors stopped readers finding the code.
    private val dark = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF061A18.toInt() }
    private val light = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val side = minOf(MeasureSpec.getSize(widthMeasureSpec), maxSide)
        setMeasuredDimension(side, side)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawColor(Color.WHITE)
        val count = size + 8
        val cell = maxOf(1, width / count).toFloat()
        val origin = ((width - cell * count) / 2f) + 4 * cell
        fun square(x: Float, y: Float, side: Float, corner: Float, paint: Paint) =
            canvas.drawRoundRect(origin + x * cell, origin + y * cell, origin + (x + side) * cell, origin + (y + side) * cell, corner * cell, corner * cell, paint)
        for ((x, y) in finders) {
            square(x.toFloat(), y.toFloat(), 7f, finderCorners[0], dark)
            square(x + 1f, y + 1f, 5f, finderCorners[1], light)
            square(x + 2f, y + 2f, 3f, finderCorners[2], dark)
        }
        for ((x, y) in alignments) {
            square(x - 2f, y - 2f, 5f, alignmentCorners[0], dark)
            square(x - 1f, y - 1f, 3f, alignmentCorners[1], light)
            canvas.drawCircle(origin + (x + 0.5f) * cell, origin + (y + 0.5f) * cell, dot * cell, dark)
        }
        for ((y, row) in modules.withIndex()) {
            for ((x, kind) in row.withIndex()) {
                when (kind) {
                    '1' -> canvas.drawCircle(origin + (x + 0.5f) * cell, origin + (y + 0.5f) * cell, dot * cell, dark)
                    '2' -> canvas.drawRect(origin + x * cell, origin + y * cell, origin + (x + 1) * cell, origin + (y + 1) * cell, dark)
                }
            }
        }
        drawLogo(canvas, origin + size / 2f * cell, origin + size / 2f * cell, logoRadius * cell * 0.82f)
    }

    /** The app's logo (the desktop's `Logo`), its ring `radius` wide, centered on (cx, cy). */
    private fun drawLogo(canvas: Canvas, cx: Float, cy: Float, radius: Float) {
        val s = radius / 452f
        fun x(v: Float) = cx + (v - 512f) * s
        fun y(v: Float) = cy + (v - 512f) * s
        val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = android.graphics.LinearGradient(x(60f + 0.18f * 904f), y(60f + 0.08f * 904f), x(60f + 0.82f * 904f), y(60f + 0.96f * 904f),
                intArrayOf(0xFF7AF0DD.toInt(), 0xFF14B8A6.toInt(), 0xFF0B5F58.toInt()), floatArrayOf(0f, 0.45f, 1f), android.graphics.Shader.TileMode.CLAMP)
        }
        canvas.drawCircle(cx, cy, radius, ring)
        val core = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = android.graphics.RadialGradient(x(512f), y(194f + 0.32f * 636f), 0.75f * 636f * s,
                intArrayOf(0xFF16524D.toInt(), 0xFF062523.toInt()), null, android.graphics.Shader.TileMode.CLAMP)
        }
        canvas.drawCircle(cx, cy, 318f * s, core)
        val hole = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFFF2FFFC.toInt() }
        canvas.drawCircle(x(512f), y(438f), 94f * s, hole)
        canvas.drawPath(android.graphics.Path().apply {
            moveTo(x(470f), y(486f)); lineTo(x(554f), y(486f)); lineTo(x(586f), y(676f))
            quadTo(x(590f), y(702f), x(564f), y(702f)); lineTo(x(460f), y(702f))
            quadTo(x(434f), y(702f), x(438f), y(676f)); close()
        }, hole)
    }
}

internal fun MainActivity.showQr(title: String, modules: List<String>) {
    val box = column(20)
    box.add(QrView(this, modules))
    AlertDialog.Builder(this).setTitle(title).setView(box).setPositiveButton(t("common.close"), null).show()
}

internal fun MainActivity.showWifiQr(id: String) {
    try {
        showQr(t("item.wifiQr"), Keyless.wifiQr(id))
    } catch (e: Exception) {
        Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
    }
}

/** A value in large type, a character per cell (digits and symbols in color), or as a QR code. */
internal fun MainActivity.showLargeType(value: String) {
    val box = column(16)
    val cells = android.widget.GridLayout(this).apply { columnCount = 6 }
    for ((i, c) in value.withIndex()) {
        val cell = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(6), dp(4), dp(6), dp(4))
        }
        cell.addView(TextView(this).apply {
            text = c.toString()
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 30f)
            gravity = Gravity.CENTER
            when {
                c.isDigit() -> setTextColor(accent())
                !c.isLetter() -> setTextColor(getColor(R.color.danger))
            }
        })
        cell.addView(label((i + 1).toString(), 10f, muted = true).apply { gravity = Gravity.CENTER })
        cells.addView(cell)
    }
    box.add(cells)
    val holder = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    box.add(holder, top = 8)
    box.add(plainButton(t("largeType.qr")) {
        holder.removeAllViews()
        try {
            holder.add(QrView(this, Keyless.qrModules(value)))
        } catch (e: Exception) {
            holder.add(label(errorText(e), 13f, muted = true))
        }
    }, width = WRAP)
    AlertDialog.Builder(this)
        .setView(ScrollView(this).apply { addView(box) })
        .setPositiveButton(t("common.close"), null)
        .show()
}
