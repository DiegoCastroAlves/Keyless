package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.graphics.Typeface
import android.view.View
import android.widget.CompoundButton
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.SeekBar
import android.widget.Switch
import org.json.JSONObject

/**
 * The password generator (the desktop's options, made by the Rust core):
 * random, memorable or a PIN. The options are remembered. `onUse` gets the
 * password when the user takes it; without it, the dialog only copies.
 */
fun Activity.showGenerator(onUse: ((String) -> Unit)?, copy: (String) -> Unit) {
    val prefs = getSharedPreferences("keyless", Context.MODE_PRIVATE)
    val options = try {
        JSONObject(prefs.getString("generator", null) ?: DEFAULT_OPTIONS)
    } catch (e: Exception) {
        JSONObject(DEFAULT_OPTIONS)
    }
    val page = column(20)
    page.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    val shown = label("", 20f).apply {
        typeface = Typeface.MONOSPACE
        setTextIsSelectable(true)
        contentDescription = getString(R.string.generated_password)
    }
    var password = ""
    val settings = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

    fun generate() {
        password = try {
            Keyless.generate(JSONObject(options.toString()))
        } catch (e: Exception) {
            ""
        }
        shown.text = password
        prefs.edit().putString("generator", options.toString()).apply()
    }

    fun switch(text: Int, key: String, default: Boolean): Switch = Switch(this).apply {
        this.text = getString(text)
        isChecked = options.optBoolean(key, default)
        setOnCheckedChangeListener { _: CompoundButton, checked: Boolean ->
            options.put(key, checked)
            generate()
        }
    }

    fun slider(format: Int, key: String, min: Int, max: Int, default: Int): View {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val value = options.optInt(key, default).coerceIn(min, max)
        options.put(key, value)
        val caption = label(getString(format, value), 14f)
        box.add(caption)
        box.add(SeekBar(this).apply {
            this.max = max - min
            progress = value - min
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(bar: SeekBar?, p: Int, fromUser: Boolean) {
                    caption.text = getString(format, p + min)
                    options.put(key, p + min)
                    if (fromUser) generate()
                }
                override fun onStartTrackingTouch(bar: SeekBar?) {}
                override fun onStopTrackingTouch(bar: SeekBar?) {}
            })
        }, top = 2)
        return box
    }

    fun radios(choices: List<Pair<String, String>>, current: String, onPick: (String) -> Unit): RadioGroup = RadioGroup(this).apply {
        for ((id, text) in choices) {
            addView(RadioButton(this@showGenerator).apply {
                this.text = text
                this.id = View.generateViewId()
                isChecked = id == current
                setOnClickListener { onPick(id) }
            })
        }
    }

    fun renderSettings() {
        settings.removeAllViews()
        when (options.optString("kind", "random")) {
            "memorable" -> {
                settings.add(slider(R.string.gen_words, "words", 3, 10, 4), top = 8)
                settings.add(radios(
                    listOf("words" to getString(R.string.gen_style_words), "syllables" to getString(R.string.gen_style_syllables), "three_letters" to getString(R.string.gen_style_letters)),
                    options.optString("style", "words"),
                ) { options.put("style", it); generate() }, top = 4)
                settings.add(label(getString(R.string.gen_separator), 14f, bold = true), top = 12)
                val separator = if (options.optString("separators", "fixed") == "fixed") options.optString("separator", "-") else options.optString("separators")
                settings.add(radios(
                    listOf("-" to "-", "." to ".", "_" to "_", " " to getString(R.string.gen_sep_space), "digits" to getString(R.string.gen_sep_digits), "digits_symbols" to getString(R.string.gen_sep_digits_symbols)),
                    separator,
                ) { picked ->
                    if (picked == "digits" || picked == "digits_symbols") {
                        options.put("separators", picked)
                    } else {
                        options.put("separators", "fixed").put("separator", picked)
                    }
                    generate()
                }, top = 4)
                settings.add(switch(R.string.gen_capitalize, "capitalize", false), top = 8)
                settings.add(switch(R.string.gen_number, "include_number", false), top = 4)
            }
            "pin" -> settings.add(slider(R.string.gen_length, "length", 4, 12, 6), top = 8)
            else -> {
                settings.add(slider(R.string.gen_length, "length", 8, 64, 24), top = 8)
                settings.add(switch(R.string.gen_uppercase, "uppercase", true), top = 8)
                settings.add(switch(R.string.gen_lowercase, "lowercase", true), top = 4)
                settings.add(switch(R.string.gen_digits, "digits", true), top = 4)
                settings.add(switch(R.string.gen_symbols, "symbols", true), top = 4)
                settings.add(switch(R.string.gen_avoid, "avoid_ambiguous", false), top = 4)
            }
        }
    }

    val kinds = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
    for ((id, text) in listOf("random" to R.string.gen_random, "memorable" to R.string.gen_memorable, "pin" to R.string.gen_pin)) {
        kinds.addView(RadioButton(this).apply {
            this.text = getString(text)
            this.id = View.generateViewId()
            isChecked = options.optString("kind", "random") == id
            setOnClickListener {
                // Each kind keeps only its own options.
                val length = if (id == "pin") 6 else 24
                options.keys().asSequence().toList().forEach { options.remove(it) }
                options.put("kind", id)
                if (id != "memorable") options.put("length", length)
                renderSettings()
                generate()
            }
        })
    }
    page.add(panel().apply { add(shown) })
    page.add(kinds, top = 12)
    page.add(settings)
    renderSettings()
    generate()

    val dialog = AlertDialog.Builder(this)
        .setTitle(R.string.generator)
        .setView(ScrollView(this).apply { addView(page) })
        .setNeutralButton(R.string.regenerate, null)
        .setNegativeButton(R.string.cancel, null)
        .setPositiveButton(if (onUse != null) R.string.use_password else R.string.copy, null)
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener { generate() }
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if (password.isEmpty()) return@setOnClickListener
            if (onUse != null) onUse(password) else copy(password)
            dialog.dismiss()
        }
    }
    dialog.show()
}

private const val DEFAULT_OPTIONS = """{"kind":"random","length":24}"""
