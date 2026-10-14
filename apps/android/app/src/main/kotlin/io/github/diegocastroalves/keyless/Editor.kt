package io.github.diegocastroalves.keyless

import android.app.AlertDialog
import android.app.DatePickerDialog
import android.graphics.Typeface
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.Switch
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.util.Calendar
import kotlin.concurrent.thread

/** Field kinds the phone edits; the others (address, sign in with, place, link, file) are kept as they are. */
private val EDITABLE_KINDS = setOf("text", "concealed", "email", "url", "phone", "totp", "date", "month_year", "card_number", "pin", "multiline", "security_question")

private val SECRET_KINDS = setOf("concealed", "pin", "card_number", "security_question")

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
    val vaults = Keyless.writableVaults()
    if (vaults.isEmpty()) {
        Toast.makeText(this, getString(R.string.err_vault_read_only), Toast.LENGTH_LONG).show()
        return
    }
    val templates = Labels.templates(this)
    val names = templates.map { Labels.category(this, it.getString("id")) }.toTypedArray()
    AlertDialog.Builder(this)
        .setTitle(R.string.choose_category)
        .setItems(names) { _, which ->
            val category = templates[which].getString("id")
            val fields = Labels.templateFields(this, category)
            if (category == "login") prefillUsername(fields)
            val draft = JSONObject()
                .put("vaultId", vaults[0].getString("id"))
                .put("title", "")
                .put("category", category)
                .put("fields", fields)
                .put("sections", JSONArray())
                .put("urls", JSONArray())
                .put("tags", JSONArray())
                .put("notes", "")
                .put("favorite", favorite)
            showEditor(draft)
        }
        .setNegativeButton(R.string.cancel, null)
        .show()
}

/** A new login starts with the username used most (as the desktop does). */
private fun prefillUsername(fields: JSONArray) {
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

/** The editor: every change goes straight into `draft`, saved with the desktop's rules (`saveDraft`). */
internal fun MainActivity.showEditor(draft: JSONObject) {
    val isNew = !draft.has("id") || draft.isNull("id")
    val original = draft.toString()
    val category = draft.optString("category")
    val hasWebsite = Labels.template(this, category)?.optBoolean("hasWebsite") == true

    fun leave() {
        val back = { if (isNew) showList() else showItem(draft.getString("id")) }
        if (draft.toString() == original) return back()
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
        val page = column(20)
        // The phone's autofill service never sees what is typed here.
        page.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        val bar = row()
        bar.add(plainButton(getString(R.string.cancel)) { leave() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        bar.add(View(this), width = 0, weight = 1f)
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
                runOnUiThread {
                    if (result is String) {
                        editorBack = null
                        showItem(result)
                    } else {
                        save.isEnabled = true
                        save.text = getString(R.string.save)
                        Toast.makeText(this, errorText(result as Exception), Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
        bar.add(save, width = ViewGroup.LayoutParams.WRAP_CONTENT)
        page.add(bar)

        page.add(label(Labels.category(this, category), 13f, muted = true), top = 8)
        page.add(EditText(this).apply {
            hint = getString(R.string.title_hint)
            setSingleLine(true)
            textSize = 22f
            setText(draft.optString("title"))
            onChange { draft.put("title", it) }
        })

        val vaults = Keyless.writableVaults()
        if (isNew && vaults.size > 1) {
            val line = row()
            line.add(label(getString(R.string.vault), 14f, muted = true), width = ViewGroup.LayoutParams.WRAP_CONTENT)
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
            page.add(line, top = 4)
        }

        fun fieldList(fields: JSONArray): View {
            val panel = panel()
            for (i in 0 until fields.length()) {
                panel.add(fieldEditor(fields.getJSONObject(i)) {
                    fields.remove(i)
                    render()
                }, top = if (i == 0) 0 else 4)
            }
            panel.add(plainButton("+ " + getString(R.string.add_field)) {
                pickFieldKind { kind ->
                    fields.put(JSONObject().put("id", "").put("label", Labels.fieldKind(this, kind)).put("kind", kind).put("value", ""))
                    render()
                }
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            return panel
        }

        page.add(fieldList(draft.optJSONArray("fields") ?: JSONArray().also { draft.put("fields", it) }), top = 12)

        val sections = draft.optJSONArray("sections") ?: JSONArray().also { draft.put("sections", it) }
        for (i in 0 until sections.length()) {
            val section = sections.getJSONObject(i)
            val head = row()
            head.add(EditText(this).apply {
                hint = getString(R.string.section_title)
                setSingleLine(true)
                setText(section.optString("title"))
                onChange { section.put("title", it) }
            }, width = 0, weight = 1f)
            head.add(plainButton("✕") {
                sections.remove(i)
                render()
            }.apply { contentDescription = getString(R.string.remove) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            page.add(head, top = 16)
            page.add(fieldList(section.optJSONArray("fields") ?: JSONArray().also { section.put("fields", it) }), top = 4)
        }
        page.add(plainButton("+ " + getString(R.string.add_section)) {
            sections.put(JSONObject().put("id", "").put("title", "").put("fields", JSONArray()))
            render()
        }, width = ViewGroup.LayoutParams.WRAP_CONTENT, top = 4)

        val urls = draft.optJSONArray("urls") ?: JSONArray().also { draft.put("urls", it) }
        if (hasWebsite || urls.length() > 0) {
            page.add(label(getString(R.string.websites).uppercase(), 12f, bold = true, muted = true), top = 16)
            val panel = panel()
            for (i in 0 until urls.length()) {
                val url = urls.getJSONObject(i)
                val line = row()
                line.add(EditText(this).apply {
                    hint = getString(R.string.website_hint)
                    setSingleLine(true)
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                    setText(url.optString("href"))
                    onChange { url.put("href", it) }
                }, width = 0, weight = 1f)
                line.add(plainButton("✕") {
                    urls.remove(i)
                    render()
                }.apply { contentDescription = getString(R.string.remove) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                panel.add(line)
            }
            panel.add(plainButton("+ " + getString(R.string.add_website)) {
                urls.put(JSONObject().put("href", ""))
                render()
            }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            page.add(panel, top = 6)
        }

        page.add(label(getString(R.string.notes).uppercase(), 12f, bold = true, muted = true), top = 16)
        page.add(EditText(this).apply {
            hint = getString(R.string.notes_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            minLines = 3
            setText(draft.optString("notes"))
            onChange { draft.put("notes", it) }
        }, top = 4)

        page.add(EditText(this).apply {
            hint = getString(R.string.tags_hint)
            setSingleLine(true)
            val tags = draft.optJSONArray("tags") ?: JSONArray()
            setText((0 until tags.length()).joinToString(", ") { tags.getString(it) })
            onChange { text -> draft.put("tags", JSONArray(text.split(",").map { it.trim() }.filter { it.isNotEmpty() })) }
        }, top = 12)

        page.add(Switch(this).apply {
            text = getString(R.string.favorite)
            isChecked = draft.optBoolean("favorite")
            setOnCheckedChangeListener { _, checked -> draft.put("favorite", checked) }
        }, top = 12)

        show("editor", page)
        restoreScroll(keep)
    }
    render()
}

/** One field: its name, its value as its kind needs, and a button to remove it. */
private fun MainActivity.fieldEditor(field: JSONObject, onRemove: () -> Unit): View {
    val box = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(4), 0, dp(4))
    }
    val head = row()
    head.add(EditText(this).apply {
        hint = getString(R.string.field_label)
        setSingleLine(true)
        textSize = 12f
        setTextColor(getColor(R.color.muted))
        setText(Labels.field(this@fieldEditor, field.optString("label")))
        onChange { field.put("label", it) }
    }, width = 0, weight = 1f)
    head.add(plainButton("✕", onRemove).apply { contentDescription = getString(R.string.remove) }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    box.add(head)

    val kind = field.optString("kind", "text")
    if (kind !in EDITABLE_KINDS) {
        box.add(label(field.optString("value"), 15f))
        box.add(label(getString(R.string.edit_on_computer), 12f, muted = true), top = 2)
        return box
    }
    val secret = kind in SECRET_KINDS || field.optString("purpose") == "password"
    val value = EditText(this).apply {
        setText(field.optString("value"))
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
        if (kind != "multiline") setSingleLine(true) else minLines = 2
        if (secret || kind == "totp") typeface = Typeface.MONOSPACE
        when (kind) {
            "totp" -> hint = getString(R.string.totp_hint)
            "month_year" -> hint = getString(R.string.month_year_hint)
        }
        onChange { field.put("value", it) }
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
        lateinit var toggle: Button
        toggle = plainButton(getString(R.string.show)) {
            shown = !shown
            val start = value.selectionStart
            value.inputType = if (shown) {
                if (kind == "pin" || kind == "card_number") InputType.TYPE_CLASS_NUMBER else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                if (kind == "pin" || kind == "card_number") InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD else TEXT_PASSWORD
            }
            value.typeface = Typeface.MONOSPACE
            value.setSelection(start.coerceIn(0, value.text.length))
            toggle.text = getString(if (shown) R.string.hide else R.string.show)
        }
        line.add(toggle, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    }
    if (kind == "concealed" || field.optString("purpose") == "password") {
        line.add(plainButton(getString(R.string.generate)) {
            showGenerator(onUse = { value.setText(it) }, copy = { copy(getString(R.string.generated_password), it) })
        }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    }
    box.add(line)
    return box
}

private fun MainActivity.pickFieldKind(onPick: (String) -> Unit) {
    val kinds = Labels.FIELD_KINDS
    AlertDialog.Builder(this)
        .setTitle(R.string.add_field)
        .setItems(kinds.map { Labels.fieldKind(this, it) }.toTypedArray()) { _, which -> onPick(kinds[which]) }
        .setNegativeButton(R.string.cancel, null)
        .show()
}
