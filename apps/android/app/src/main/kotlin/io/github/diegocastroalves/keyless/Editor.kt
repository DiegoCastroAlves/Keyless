package io.github.diegocastroalves.keyless

import android.app.AlertDialog
import android.app.DatePickerDialog
import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.StateListDrawable
import android.net.Uri
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.text.format.Formatter
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import kotlin.concurrent.thread

/** Field kinds the phone edits; the others (address, sign in with, place, link, file) are kept as they are. */
private val EDITABLE_KINDS = setOf("text", "concealed", "email", "url", "phone", "totp", "date", "month_year", "card_number", "pin", "multiline", "security_question")

private val SECRET_KINDS = setOf("concealed", "pin", "card_number", "security_question")

private const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

private fun EditText.onChange(block: (String) -> Unit) {
    addTextChangedListener(object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        override fun afterTextChanged(s: Editable?) = block(s?.toString() ?: "")
    })
}

/** Runs `work` off the main thread; errors show as a message, `then` runs on success. */
internal fun MainActivity.act(work: () -> Unit, then: () -> Unit) {
    thread {
        val failure = try {
            work()
            null
        } catch (e: Exception) {
            e
        }
        runOnUiThread { if (failure != null) Toast.makeText(this, errorText(failure), Toast.LENGTH_LONG).show() else then() }
    }
}

/** A new item: its category first, then the editor with the category's fields. */
internal fun MainActivity.newItem(favorite: Boolean) {
    if (Keyless.writableVaults().isEmpty()) {
        Toast.makeText(this, getString(R.string.err_vault_read_only), Toast.LENGTH_LONG).show()
        return
    }
    showNewItem(favorite)
}

/** A new login starts with the username used most (as the desktop does). */
internal fun prefillUsername(fields: JSONArray) {
    val top = Keyless.items.filter { it.category == "login" && it.subtitle.isNotBlank() }.groupingBy { it.subtitle.trim() }.eachCount()
        .entries.sortedWith(compareByDescending<Map.Entry<String, Int>> { it.value }.thenBy { it.key }).firstOrNull()?.key ?: return
    for (i in 0 until fields.length()) {
        val f = fields.getJSONObject(i)
        if (f.optString("purpose") == "username" && f.optString("value").isEmpty()) f.put("value", top)
    }
}

internal fun MainActivity.editItem(id: String) {
    val draft = try {
        Keyless.draftOf(id)
    } catch (e: KeylessException) {
        Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
        return
    }
    showEditor(draft)
}

/**
 * The editor, laid out as the item: the fields in one card (the passkeys
 * after the username), each typed in its row; sections, websites, apps,
 * files and notes in their own cards; and "Add more" for a field, a section
 * or a file. Every change goes straight into `draft`, saved with the
 * desktop's rules (`saveDraft`); passkeys and files change once it is saved.
 */
internal fun MainActivity.showEditor(draft: JSONObject) {
    val isNew = !draft.has("id") || draft.isNull("id")
    val original = draft.toString()
    val category = draft.optString("category")
    val hasWebsite = Labels.template(this, category)?.optBoolean("hasWebsite") == true
    val itemId = if (isNew) null else draft.optString("id")
    val passkeys = itemId?.let { id ->
        try {
            Keyless.item(id).getJSONObject("details").optJSONArray("passkeys")
        } catch (e: KeylessException) {
            null
        }
    } ?: JSONArray()
    val attachments = itemId?.let { id ->
        try {
            Keyless.attachments(id)
        } catch (e: KeylessException) {
            null
        }
    } ?: JSONArray()
    val removingPasskeys = mutableSetOf<String>()
    val removingFiles = mutableSetOf<String>()
    val newFiles = mutableListOf<Uri>()
    // What was just added gets the focus, so typing can go on.
    var focusOn: JSONObject? = null

    fun leave() {
        val back = { if (isNew) showMain() else showItem(draft.getString("id")) }
        if (draft.toString() == original && removingPasskeys.isEmpty() && removingFiles.isEmpty() && newFiles.isEmpty()) return back()
        AlertDialog.Builder(this)
            .setTitle(R.string.discard_title)
            .setPositiveButton(R.string.discard) { _, _ -> back() }
            .setNegativeButton(R.string.keep_editing, null)
            .show()
    }
    editorBack = { leave() }

    lateinit var render: () -> Unit
    render = {
        val keep = scrollPosition()
        val page = column(20).apply { setPadding(dp(16), dp(4), dp(16), dp(28)) }
        // The phone's autofill service never sees what is typed here.
        page.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        val bar = row().apply { minimumHeight = dp(56) }
        bar.add(plainButton(getString(R.string.cancel)) { leave() }, width = WRAP)
        bar.add(android.widget.Space(this), width = 0, weight = 1f)
        lateinit var save: Button
        save = primaryButton(getString(R.string.save)) {
            save.isEnabled = false
            save.text = getString(R.string.saving)
            thread {
                val result = try {
                    Keyless.saveDraft(JSONObject(draft.toString()))
                } catch (e: Exception) {
                    e
                }
                // Then the passkeys and files to delete, each on its own.
                var failure: Exception? = null
                if (result is String) {
                    for (credential in removingPasskeys) {
                        try {
                            Keyless.removePasskey(result, credential)
                        } catch (e: Exception) {
                            failure = failure ?: e
                        }
                    }
                    for (file in removingFiles) {
                        try {
                            Keyless.removeAttachment(result, file)
                        } catch (e: Exception) {
                            failure = failure ?: e
                        }
                    }
                }
                runOnUiThread {
                    if (result is String) {
                        editorBack = null
                        showItem(result)
                        failure?.let { Toast.makeText(this, errorText(it), Toast.LENGTH_LONG).show() }
                        // The new files go after the item, with their progress.
                        if (newFiles.isNotEmpty()) attachFiles(result, newFiles.toList())
                    } else {
                        save.isEnabled = true
                        save.text = getString(R.string.save)
                        Toast.makeText(this, errorText(result as Exception), Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
        bar.add(save, width = WRAP)
        page.add(bar)

        // The header, as the item's: its icon, the title, its category (and vault).
        val urls = draft.optJSONArray("urls") ?: JSONArray().also { draft.put("urls", it) }
        val header = row().apply { gravity = Gravity.TOP }
        // A linked app's site, as saved (the client works it out).
        val savedIconUrl = Keyless.items.firstOrNull { it.id == draft.optString("id") }?.iconUrl
        header.addView(loginIcon(category, draft.optString("title").ifEmpty { Labels.category(this, category) }, urls, savedIconUrl, 60))
        val names = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, 0, 0)
        }
        names.add(EditText(this).apply {
            bare(24f)
            weight(600)
            hint = getString(R.string.title_hint)
            setSingleLine(true)
            setPadding(dp(4), dp(4), dp(4), dp(4))
            setText(draft.optString("title"))
            onChange { draft.put("title", it) }
            shadeWhileTyping()
        })
        names.add(label(Labels.category(this, category), 14f, muted = true).apply { setPadding(dp(4), 0, 0, 0) })
        header.addView(names, LinearLayout.LayoutParams(0, WRAP, 1f))
        page.add(header, top = 4)

        val vaults = Keyless.writableVaults()
        if (isNew && vaults.size > 1) {
            val line = row()
            line.add(label(getString(R.string.vault), 14f, muted = true), width = WRAP)
            val spinner = Spinner(this)
            spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, vaults.map { it.optString("name") })
            spinner.setSelection(vaults.indexOfFirst { it.getString("id") == draft.optString("vaultId") }.coerceAtLeast(0))
            spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                    draft.put("vaultId", vaults[position].getString("id"))
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
            line.add(spinner, width = 0, weight = 1f)
            page.add(line, top = 8)
        }

        // An SSH key's public key and fingerprint come from its private key.
        val sshFields = if (category == "ssh_key") sshFieldsOf(draft) else null
        val afterChange: ((JSONObject) -> Unit)? = sshFields?.let { ssh ->
            { changed: JSONObject -> if (changed === ssh.first) readSshKey(ssh, null) { render() } }
        }
        if (sshFields != null) {
            page.add(label(Labels.t(this, "sshKey.hint"), 13f, muted = true), top = 12)
            page.add(plainButton(Labels.t(this, "sshKey.generate")) {
                act({ fillSsh(sshFields, Keyless.sshGenerate(draft.optString("title"))) }) { render() }
            }, width = WRAP)
        }

        // A field of the kind picked, named after it ("password").
        fun addField(fields: JSONArray, kind: String) {
            val field = JSONObject().put("id", "").put("label", Labels.defaultFieldLabel(this, kind)).put("kind", kind).put("value", "")
            fields.put(field)
            focusOn = field
            render()
        }

        // A label still the one of its kind follows a change of kind.
        fun changeKind(field: JSONObject, kind: String) {
            val usual = Labels.defaultFieldLabel(this, field.optString("kind"))
            val label = field.optString("label")
            if (label.isEmpty() || label == usual || label == Labels.field(this, usual)) field.put("label", Labels.defaultFieldLabel(this, kind))
            field.put("kind", kind)
            render()
        }

        fun fieldRows(card: LinearLayout, fields: JSONArray) {
            for (i in 0 until fields.length()) {
                val field = fields.getJSONObject(i)
                card.addView(fieldEditor(field, itemId, field === focusOn, afterChange, { changeKind(field, it) }) {
                    fields.remove(i)
                    render()
                })
            }
        }

        val fields = draft.optJSONArray("fields") ?: JSONArray().also { draft.put("fields", it) }
        if (fields.length() > 0 || passkeys.length() > 0) {
            val card = card()
            fieldRows(card, fields)
            // The passkeys come after the username, as in the item.
            val after = (0 until fields.length()).indexOfFirst { fields.getJSONObject(it).optString("purpose") == "username" }
            for (i in 0 until passkeys.length()) {
                val credential = passkeys.getJSONObject(i).getString("credentialId")
                card.addView(passkeyEditor(passkeys.getJSONObject(i), credential in removingPasskeys) {
                    if (!removingPasskeys.remove(credential)) removingPasskeys.add(credential)
                    render()
                }, after + 1 + i)
            }
            page.add(card, top = 20)
        }

        val sections = draft.optJSONArray("sections") ?: JSONArray().also { draft.put("sections", it) }
        for (i in 0 until sections.length()) {
            val section = sections.getJSONObject(i)
            val head = row()
            head.add(EditText(this).apply {
                bare(15f)
                weight(600)
                hint = Labels.t(this@showEditor, "editor.sectionTitle")
                setSingleLine(true)
                setPadding(dp(4), dp(4), dp(4), dp(4))
                setText(section.optString("title"))
                onChange { section.put("title", it) }
                shadeWhileTyping()
                if (section === focusOn) focusSoon()
            }, width = 0, weight = 1f)
            head.add(iconButton(R.drawable.ic_trash, Labels.t(this, "editor.deleteSection")) {
                sections.remove(i)
                render()
            }, width = WRAP)
            page.add(head, top = 20)
            val card = card()
            val inner = section.optJSONArray("fields") ?: JSONArray().also { section.put("fields", it) }
            fieldRows(card, inner)
            card.addView(addRow(getString(R.string.add_field)) { anchor -> kindMenu(anchor) { addField(inner, it) } })
            page.add(card, top = 4)
        }

        // Apps linked to the login are kept among its addresses (AppLinks).
        val isApp = { i: Int -> AppLinks.packageOf(urls.getJSONObject(i).optString("href")) != null }
        if (hasWebsite || (0 until urls.length()).any { !isApp(it) }) {
            val card = card()
            for (i in 0 until urls.length()) {
                if (isApp(i)) continue
                val url = urls.getJSONObject(i)
                val name = EditText(this).apply {
                    labelLook(false)
                    hint = Labels.field(this@showEditor, "website")
                    setText(url.optString("label"))
                    onChange { url.put("label", it) }
                }
                val href = EditText(this).apply {
                    bare(16f)
                    hint = getString(R.string.website_hint)
                    setSingleLine(true)
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                    setText(url.optString("href"))
                    onChange { url.put("href", it) }
                    if (url === focusOn) focusSoon()
                }
                card.addView(editRow(listOf(name, href), removeButton(getString(R.string.remove)) {
                    urls.remove(i)
                    render()
                }).also { it.typingShade(name, href) })
            }
            card.addView(addRow(getString(R.string.add_website)) {
                val url = JSONObject().put("href", "")
                urls.put(url)
                focusOn = url
                render()
            })
            page.add(card, top = 16)
        }

        if (category == "login" || (0 until urls.length()).any { isApp(it) }) {
            page.add(sectionTitle(getString(R.string.apps)), top = 20)
            page.add(label(getString(R.string.apps_hint), 13f, muted = true).apply { setPadding(dp(4), 0, dp(4), 0) }, top = 2)
            val card = card()
            for (i in 0 until urls.length()) {
                val name = AppLinks.packageOf(urls.getJSONObject(i).optString("href")) ?: continue
                val app = AppLinks.label(this, name)
                card.addView(listRow(appIcon(name, 32), app ?: AppLinks.savedName(urls, name) ?: name, if (app == null) getString(R.string.not_installed) else name,
                    removeButton(getString(R.string.remove)) {
                        urls.remove(i)
                        render()
                    }).apply { background = null })
            }
            card.addView(addRow(getString(R.string.link_app)) {
                val linked = AppLinks.linked(urls).toSet()
                pickApp(AppLinks.loginWords(draft.optString("title"), urls), linked) { app ->
                    urls.put(JSONObject().put("href", AppLinks.href(app.packageName)).put("label", app.label))
                    render()
                }
            })
            page.add(card, top = 8)
        }

        if (attachments.length() > 0 || newFiles.isNotEmpty()) {
            page.add(sectionTitle(Labels.t(this, "item.attachments")), top = 20)
            val card = card()
            for (i in 0 until attachments.length()) {
                val file = attachments.getJSONObject(i)
                val id = file.getString("id")
                val gone = id in removingFiles
                val toggle = {
                    if (!removingFiles.remove(id)) removingFiles.add(id)
                    render()
                }
                val size = Formatter.formatShortFileSize(this, file.optLong("size"))
                card.addView(listRow(icon(R.drawable.ic_paperclip, getColor(if (gone) R.color.subtle else R.color.accent), 20), file.optString("name"),
                    if (gone) Labels.t(this, "editor.deleteOnSave") else size,
                    if (gone) plainButton(Labels.t(this, "editor.keepFile")) { toggle() } else removeButton(Labels.t(this, "common.delete")) { toggle() }).apply {
                    minimumHeight = dp(56)
                    background = null
                    if (gone) ((getChildAt(1) as LinearLayout).getChildAt(0) as TextView).apply {
                        paintFlags = paintFlags or Paint.STRIKE_THRU_TEXT_FLAG
                        setTextColor(getColor(R.color.subtle))
                    }
                })
            }
            for (uri in newFiles.toList()) {
                val (name, size) = try {
                    fileInfo(uri)
                } catch (e: Exception) {
                    uri.lastPathSegment.orEmpty() to -1L
                }
                val line = listOfNotNull(if (size >= 0) Formatter.formatShortFileSize(this, size) else null, Labels.t(this, "editor.addOnSave")).joinToString(" · ")
                card.addView(listRow(icon(R.drawable.ic_paperclip, accent(), 20), name, line, removeButton(getString(R.string.remove)) {
                    newFiles.remove(uri)
                    render()
                }).apply {
                    minimumHeight = dp(56)
                    background = null
                })
            }
            page.add(card, top = 8)
        }

        // Under the item's cards: a field (to the first card), a section or a file.
        page.add(addMoreButton { anchor ->
            val more = listOf(Labels.t(this, "editor.section"), Labels.t(this, "editor.attachFile"))
            kindMenu(anchor, more, onMore = { choice ->
                if (choice == 0) {
                    val section = JSONObject().put("id", "").put("title", "").put("fields", JSONArray())
                    sections.put(section)
                    focusOn = section
                    render()
                } else {
                    pickFile { uri ->
                        if (uri !in newFiles) newFiles.add(uri)
                        render()
                    }
                }
            }) { addField(fields, it) }
        }, top = 16)

        page.add(sectionTitle(getString(R.string.notes)), top = 20)
        page.add(card().apply {
            addView(EditText(this@showEditor).apply {
                bare(15f)
                hint = Labels.t(this@showEditor, "editor.notesPlaceholder")
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                minLines = 3
                gravity = Gravity.TOP or Gravity.START
                setLineSpacing(0f, 1.25f)
                setPadding(dp(16), dp(12), dp(16), dp(12))
                setText(draft.optString("notes"))
                onChange { draft.put("notes", it) }
            })
        }, top = 8)

        page.add(sectionTitle(getString(R.string.tags)), top = 20)
        page.add(tagsEditor(draft.optJSONArray("tags") ?: JSONArray().also { draft.put("tags", it) }), top = 8)

        page.add(card().apply {
            val switch = Switch(this@showEditor).apply {
                isChecked = draft.optBoolean("favorite")
                setOnCheckedChangeListener { _, checked -> draft.put("favorite", checked) }
            }
            addView(listRow(icon(R.drawable.ic_star, getColor(R.color.warning), 20), getString(R.string.favorite), null, switch).apply {
                minimumHeight = dp(56)
                setOnClickListener { switch.toggle() }
            })
        }, top = 20)

        show("editor", page)
        restoreScroll(keep)
        focusOn = null
    }
    render()
}

/** An SSH key item's private key, public key and fingerprint fields (as the desktop's template). */
private fun MainActivity.sshFieldsOf(draft: JSONObject): Triple<JSONObject, JSONObject?, JSONObject?>? {
    val fields = draft.optJSONArray("fields") ?: return null
    val all = (0 until fields.length()).map { fields.getJSONObject(it) }
    fun named(english: String) = all.firstOrNull { val l = it.optString("label"); l == english || l == Labels.field(this, english) }
    val private = named("private key") ?: all.firstOrNull { it.optString("kind") == "concealed" } ?: return null
    return Triple(private, named("public key"), named("fingerprint"))
}

private fun fillSsh(ssh: Triple<JSONObject, JSONObject?, JSONObject?>, key: JSONObject) {
    ssh.first.put("value", key.getString("privateKey"))
    ssh.second?.put("value", key.getString("publicKey"))
    ssh.third?.put("value", key.getString("fingerprint"))
}

/** Reads a pasted private key (asking for its passphrase when it has one) into the item's fields. */
private fun MainActivity.readSshKey(ssh: Triple<JSONObject, JSONObject?, JSONObject?>, passphrase: String?, then: () -> Unit) {
    val text = ssh.first.optString("value")
    if (!text.contains("-----END")) return
    thread {
        val result = try {
            Keyless.sshImport(text, passphrase, "")
        } catch (e: Exception) {
            e
        }
        runOnUiThread {
            if (ssh.first.optString("value") != text) return@runOnUiThread
            when {
                result is JSONObject -> {
                    fillSsh(ssh, result)
                    then()
                }
                (result as? KeylessException)?.key == "ssh_key_passphrase" || (result as? KeylessException)?.key == "ssh_key_wrong_passphrase" -> {
                    val input = field(Labels.t(this, "sshKey.passphrase"), TEXT_PASSWORD, secret = true)
                    AlertDialog.Builder(this)
                        .setTitle(Labels.t(this, "sshKey.passphrase"))
                        .setMessage(if ((result as KeylessException).key == "ssh_key_wrong_passphrase") errorText(result) else null)
                        .setView(column(20).apply { add(input) })
                        .setPositiveButton(Labels.t(this, "sshKey.unlock")) { _, _ -> readSshKey(ssh, input.text.toString(), then) }
                        .setNegativeButton(R.string.cancel, null)
                        .show()
                }
                else -> Toast.makeText(this, errorText(result as Exception), Toast.LENGTH_LONG).show()
            }
        }
    }
}

/** A value typed straight in its row, without a box (as the item shows it). */
private fun EditText.bare(size: Float) {
    background = null
    setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
    typeface = context.inter(400)
    setTextColor(context.getColor(R.color.fg))
    setHintTextColor(context.getColor(R.color.subtle))
    minHeight = context.dp(32)
    setPadding(0, context.dp(2), 0, context.dp(2))
}

/** A field's name, small over its value; the login's own fields (username, password) in the accent. */
private fun EditText.labelLook(own: Boolean) {
    bare(12f)
    weight(500)
    setSingleLine(true)
    setTextColor(context.getColor(if (own) R.color.accent else R.color.subtle))
    minHeight = context.dp(22)
    setPadding(0, 0, 0, 0)
}

/** A title typed in place (the item's, a section's): shaded while typing. */
private fun EditText.shadeWhileTyping() {
    background = StateListDrawable().apply {
        addState(intArrayOf(android.R.attr.state_focused), context.shape(context.getColor(R.color.panel_2), 8f))
        addState(intArrayOf(), ColorDrawable(Color.TRANSPARENT))
    }
}

/** A row shaded while one of `inputs` is being typed in (as the desktop's); `typing` hears it too. */
private fun View.typingShade(vararg inputs: EditText, typing: ((Boolean) -> Unit)? = null) {
    val listener = View.OnFocusChangeListener { _, _ ->
        val now = inputs.any { it.hasFocus() }
        setBackgroundColor(if (now) context.getColor(R.color.panel_2) else Color.TRANSPARENT)
        typing?.invoke(now)
    }
    for (input in inputs) input.onFocusChangeListener = listener
}

/** Focuses this field and opens the keyboard, once it is on the screen. */
private fun EditText.focusSoon() {
    post {
        requestFocus()
        context.getSystemService(InputMethodManager::class.java)?.showSoftInput(this, 0)
    }
}

/** A row of the editor's cards: what is typed in it, one over the other, and its actions at the end. */
private fun Context.editRow(lines: List<View>, vararg actions: View): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    minimumHeight = dp(60)
    setPadding(dp(16), dp(8), dp(4), dp(8))
    val texts = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
    for (line in lines) texts.addView(line, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, WRAP))
    addView(texts, LinearLayout.LayoutParams(0, WRAP, 1f))
    for (action in actions) addView(action)
}

/** Removes a row (a field, a website, a file): a red minus. */
private fun Context.removeButton(description: String, onClick: () -> Unit) = iconButton(R.drawable.ic_circle_minus, description, getColor(R.color.danger)) { onClick() }

/** "+ Add website" and the like, as a card's last row; `onClick` gets the row (for a menu). */
private fun Context.addRow(text: String, onClick: (View) -> Unit): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
    minimumHeight = dp(52)
    setPadding(dp(16), 0, dp(16), 0)
    background = pressable(null, 0f)
    addView(icon(R.drawable.ic_plus, accent(), 18))
    addView(label(text, 15f).apply {
        setTextColor(accent())
        weight(500)
        setPadding(dp(12), 0, 0, 0)
    })
    setOnClickListener { onClick(this) }
}

/** "Add more", under the item's cards. */
private fun Context.addMoreButton(onClick: (View) -> Unit): LinearLayout = addRow(Labels.t(this, "editor.addMore"), onClick).apply {
    background = pressable(shape(getColor(R.color.panel), 16f), 16f)
    (getChildAt(1) as TextView).layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
    addView(icon(R.drawable.ic_chevron_down, getColor(R.color.subtle), 18))
}

/** The field kinds the phone adds, in a menu under `anchor`; then `more`, each answered by its place in `onMore`. */
private fun MainActivity.kindMenu(anchor: View, more: List<String> = emptyList(), onMore: (Int) -> Unit = {}, onPick: (String) -> Unit) {
    val menu = PopupMenu(this, anchor)
    menu.menu.setGroupDividerEnabled(true)
    val kinds = Labels.FIELD_KINDS
    for ((i, kind) in kinds.withIndex()) menu.menu.add(0, i, i, Labels.fieldKind(this, kind))
    for ((i, text) in more.withIndex()) menu.menu.add(1 + i, MORE + i, MORE + i, text)
    menu.setOnMenuItemClickListener { choice ->
        if (choice.itemId >= MORE) onMore(choice.itemId - MORE) else onPick(kinds[choice.itemId])
        true
    }
    menu.show()
}

private const val MORE = 100

/** One field: its name over its value as its kind needs, and a button to remove it. */
private fun MainActivity.fieldEditor(field: JSONObject, itemId: String?, focus: Boolean, afterChange: ((JSONObject) -> Unit)?, onKind: (String) -> Unit, onRemove: () -> Unit): View {
    val kind = field.optString("kind", "text")
    val name = EditText(this).apply {
        labelLook(field.optString("purpose").isNotEmpty())
        hint = if (kind == "security_question") Labels.t(this@fieldEditor, "editor.questionPlaceholder") else getString(R.string.field_label)
        setText(Labels.field(this@fieldEditor, field.optString("label")))
        onChange { field.put("label", it) }
    }
    val head = row()
    head.add(name, width = 0, weight = 1f)
    // Its kind, to change while typing in the row (the desktop shows it on hover).
    val kindButton = if (kind !in Labels.FIELD_KINDS) null else label(Labels.fieldKind(this, kind), 11f, muted = true).apply {
        weight(500)
        background = pressable(shape(getColor(R.color.panel_3), 6f), 6f)
        setPadding(dp(8), dp(3), dp(8), dp(3))
        contentDescription = Labels.t(this@fieldEditor, "editor.fieldType")
        visibility = View.GONE
        setOnClickListener { kindMenu(this) { if (it != kind) onKind(it) } }
    }
    if (kindButton != null) head.add(kindButton, width = WRAP)
    val remove = removeButton(Labels.t(this, "editor.deleteField")) { onRemove() }

    if (kind !in EDITABLE_KINDS) {
        val note = label(getString(R.string.edit_on_computer), 12f, muted = true)
        return editRow(listOf(head, label(field.optString("value"), 16f), note), remove).also { it.typingShade(name) }
    }
    val secret = kind in SECRET_KINDS || field.optString("purpose") == "password"
    val value = EditText(this).apply {
        bare(16f)
        setText(field.optString("value"))
        // Before the type: it would replace a password's mask.
        if (kind != "multiline") setSingleLine(true)
        inputType = when (kind) {
            "pin" -> InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            "card_number" -> InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            "email" -> TEXT_EMAIL
            "url" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            "phone" -> InputType.TYPE_CLASS_PHONE
            "multiline" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            "totp" -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            else -> if (secret) TEXT_PASSWORD else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        }
        // The keyboard learns nothing typed here.
        if (secret) imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        if (kind == "multiline") minLines = 2
        if (secret || kind == "totp") typeface = Typeface.MONOSPACE
        when (kind) {
            "totp" -> hint = getString(R.string.totp_hint)
            "month_year" -> hint = getString(R.string.month_year_hint)
        }
        onChange {
            field.put("value", it)
            afterChange?.invoke(field)
        }
    }
    if (kind == "date") {
        // The desktop keeps dates as YYYY-MM-DD.
        value.isFocusable = false
        value.hint = getString(R.string.pick_date)
        value.setOnClickListener {
            val calendar = Calendar.getInstance()
            Regex("^(\\d{4})-(\\d{2})-(\\d{2})$").find(field.optString("value"))?.destructured?.let { (y, m, d) -> calendar.set(y.toInt(), m.toInt() - 1, d.toInt()) }
            DatePickerDialog(this, { _, y, m, d -> value.setText(String.format(java.util.Locale.ROOT, "%04d-%02d-%02d", y, m + 1, d)) },
                calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH), calendar.get(Calendar.DAY_OF_MONTH)).show()
        }
    }
    val line = row()
    line.add(value, width = 0, weight = 1f)
    if (secret) {
        var shown = false
        lateinit var toggle: android.widget.ImageButton
        toggle = iconButton(R.drawable.ic_eye, getString(R.string.show)) {
            shown = !shown
            val start = value.selectionStart
            value.inputType = if (shown) {
                if (kind == "pin" || kind == "card_number") InputType.TYPE_CLASS_NUMBER else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                if (kind == "pin" || kind == "card_number") InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD else TEXT_PASSWORD
            }
            value.typeface = Typeface.MONOSPACE
            value.setSelection(start.coerceIn(0, value.text.length))
            toggle.setImageDrawable(iconDrawable(if (shown) R.drawable.ic_eye_off else R.drawable.ic_eye, getColor(R.color.muted)))
            toggle.contentDescription = getString(if (shown) R.string.hide else R.string.show)
        }
        line.add(toggle, width = WRAP)
    }
    if (kind == "totp") {
        line.add(iconButton(R.drawable.ic_scan, getString(R.string.scan_qr)) {
            scanQr(QrScanActivity.WANT_TOTP) { value.setText(it) }
        }, width = WRAP)
    }
    // Not for an SSH private key: it is generated as a key, not a password.
    val privateKey = field.optString("label").let { it == "private key" || it == Labels.field(this, "private key") }
    if ((kind == "concealed" || field.optString("purpose") == "password") && !privateKey) {
        line.add(iconButton(R.drawable.ic_wand,Labels.t(this, "editor.generate")) {
            showGenerator(onUse = { value.setText(it) }, copy = { copy(getString(R.string.generated_password), it) })
        }, width = WRAP)
    }
    val lines = mutableListOf<View>(head, line)
    // (Not for an SSH key's editor, whose secret is the private key.)
    if (afterChange == null && (field.optString("purpose") == "password" || kind == "concealed")) {
        // How strong the password is, as the desktop's meter.
        val meter = label("", 12f, muted = true)
        val update = { text: String ->
            if (text.isEmpty()) {
                meter.text = ""
                meter.visibility = View.GONE
            } else {
                try {
                    val strength = Keyless.strength(text, itemId)
                    val level = strength.optInt("level")
                    meter.text = Labels.t(this, "filters.strengthChip", mapOf("level" to Labels.t(this, "strength.$level")))
                    meter.setTextColor(getColor(if (strength.optInt("score") < 3) R.color.danger else R.color.accent))
                    meter.visibility = View.VISIBLE
                } catch (e: Exception) {
                    meter.text = ""
                    meter.visibility = View.GONE
                }
            }
        }
        update(field.optString("value"))
        value.onChange {
            field.put("value", it)
            update(it)
        }
        lines.add(meter)
    }
    if (focus) value.focusSoon()
    return editRow(lines, remove).also { row ->
        row.typingShade(name, value) { typing -> kindButton?.visibility = if (typing) View.VISIBLE else View.GONE }
    }
}

/** A passkey of the item while editing: deleted when the item is saved. */
private fun MainActivity.passkeyEditor(passkey: JSONObject, removing: Boolean, onToggle: () -> Unit): View {
    val name = label(t("item.passkey"), 12f).apply {
        weight(500)
        setTextColor(getColor(R.color.subtle))
        setCompoundDrawablesRelative(iconDrawable(R.drawable.ic_fingerprint, accent()).apply { setBounds(0, 0, dp(14), dp(14)) }, null, null, null)
        compoundDrawablePadding = dp(6)
    }
    val user = passkey.optString("userName")
    val site = label(passkey.optString("rpId") + if (user.isNotEmpty()) " · $user" else "", 16f).apply {
        setSingleLine(true)
        ellipsize = android.text.TextUtils.TruncateAt.END
        if (removing) {
            paintFlags = paintFlags or Paint.STRIKE_THRU_TEXT_FLAG
            setTextColor(getColor(R.color.subtle))
        }
    }
    val created = passkey.optLong("createdAt")
    val note = when {
        removing -> t("editor.deleteOnSave")
        created > 0 -> t("item.passkeyCreated", mapOf("date" to DateFormat.getDateInstance().format(Date(created * 1000))))
        else -> null
    }
    val lines = listOfNotNull(name, site, note?.let { label(it, 12f, muted = true).apply { setTextColor(getColor(R.color.subtle)) } })
    val action = if (removing) plainButton(t("editor.keepFile")) { onToggle() } else removeButton(t("common.delete")) { onToggle() }
    return editRow(lines, action)
}

/** The tags as pills, each with a button to remove it, and one to type a new tag in. */
private fun MainActivity.tagsEditor(tags: JSONArray): View {
    val flow = FlowLayout(this, dp(6))
    val input = EditText(this)
    fun pill(tag: String): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(36)
        background = shape(getColor(R.color.panel), 18f)
        setPadding(dp(14), 0, dp(2), 0)
        addView(label(tag, 14f).apply { weight(500) })
        val pill = this
        addView(iconButton(R.drawable.ic_close, "${t("common.remove")}: $tag") {
            val index = (0 until tags.length()).firstOrNull { tags.getString(it) == tag }
            if (index != null) tags.remove(index)
            flow.removeView(pill)
        }.apply {
            layoutParams = LinearLayout.LayoutParams(dp(32), dp(32))
            setPadding(dp(9), dp(9), dp(9), dp(9))
        })
    }
    val add = {
        val tag = input.text.toString().trim().trimEnd(',').trim()
        val have = (0 until tags.length()).map { tags.getString(it) }
        if (tag.isNotEmpty() && have.none { it.equals(tag, ignoreCase = true) }) {
            tags.put(tag)
            flow.addView(pill(tag), flow.childCount - 1)
        }
        if (input.text.isNotEmpty()) input.setText("")
    }
    for (i in 0 until tags.length()) flow.addView(pill(tags.getString(i)))
    input.apply {
        bare(14f)
        hint = t("editor.addTag")
        setHintTextColor(accent())
        setSingleLine(true)
        minWidth = dp(150)
        minHeight = dp(36)
        background = shape(getColor(R.color.panel), 18f)
        setPadding(dp(12), 0, dp(14), 0)
        setCompoundDrawablesRelative(iconDrawable(R.drawable.ic_plus, accent()).apply { setBounds(0, 0, dp(16), dp(16)) }, null, null, null)
        compoundDrawablePadding = dp(6)
        imeOptions = EditorInfo.IME_ACTION_DONE
        setOnEditorActionListener { _, _, _ ->
            add()
            true
        }
        onChange { if (it.endsWith(",")) add() }
        setOnFocusChangeListener { _, focused -> if (!focused) add() }
    }
    flow.addView(input)
    return flow
}

/** Children side by side, on as many lines as they need (tags). */
private class FlowLayout(context: Context, private val gap: Int) : ViewGroup(context) {
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        setMeasuredDimension(width, place(width, false))
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        place(r - l, true)
    }

    /** Lays the children out in lines of `width` (measuring them first, unless `layout`); returns the height. */
    private fun place(width: Int, layout: Boolean): Int {
        var x = 0
        var y = 0
        var line = 0
        for (i in 0 until childCount) {
            val child = getChildAt(i)
            if (child.visibility == View.GONE) continue
            if (!layout) measureChild(child, MeasureSpec.makeMeasureSpec(width, MeasureSpec.AT_MOST), MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED))
            if (x > 0 && x + child.measuredWidth > width) {
                x = 0
                y += line + gap
                line = 0
            }
            if (layout) {
                // Right to left, the lines start on the right.
                val start = if (layoutDirection == View.LAYOUT_DIRECTION_RTL) width - x - child.measuredWidth else x
                child.layout(start, y, start + child.measuredWidth, y + child.measuredHeight)
            }
            x += child.measuredWidth + gap
            line = maxOf(line, child.measuredHeight)
        }
        return y + line
    }
}
