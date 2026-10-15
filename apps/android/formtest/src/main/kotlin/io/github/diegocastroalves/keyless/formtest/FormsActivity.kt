package io.github.diegocastroalves.keyless.formtest

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillManager
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView

/** A field with its hint text, and Android's autofill hints when given. */
private fun Activity.field(hint: String, type: Int, vararg autofill: String): EditText =
    EditText(this).apply {
        this.hint = hint
        inputType = type
        if (autofill.isNotEmpty()) setAutofillHints(*autofill)
    }

/** Room around a form, in dp: the CI's emulator has a small screen. */
internal fun LinearLayout.padded() {
    val dp = resources.displayMetrics.density
    setPadding((16 * dp).toInt(), (24 * dp).toInt(), (16 * dp).toInt(), (16 * dp).toInt())
}

private fun Activity.form(title: String, views: List<View>, submit: String): View {
    val column = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        padded()
    }
    val status = TextView(this)
    column.addView(TextView(this).apply { text = title; textSize = 22f })
    views.forEach { column.addView(it) }
    column.addView(Button(this).apply {
        text = submit
        setOnClickListener {
            status.text = "Sent"
            getSystemService(AutofillManager::class.java)?.commit()
        }
    })
    column.addView(status)
    return ScrollView(this).apply { addView(column) }
}

private const val TEXT = InputType.TYPE_CLASS_TEXT

/**
 * A payment form, as an app would have one: the number and expiry marked
 * with Android's autofill hints, the security code (hidden) and the name
 * only by their hint text.
 */
class CardActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val fields = listOf(
            field("Card number", InputType.TYPE_CLASS_NUMBER, View.AUTOFILL_HINT_CREDIT_CARD_NUMBER),
            field("Expiry (MM/YY)", TEXT, View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DATE),
            field("CVC", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD),
            field("Name on card", TEXT or InputType.TYPE_TEXT_VARIATION_PERSON_NAME),
        )
        setContentView(form("Payment", fields, "Pay"))
    }
}

/**
 * An address form: its fields known by their hint text only (as many apps
 * do), the postal code by Android's hint, and the country in a list known
 * by its description.
 */
class AddressActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val countries = arrayOf("Select", "Argentina", "Brasil", "Chile", "Portugal")
        val country = Spinner(this).apply {
            adapter = ArrayAdapter(this@AddressActivity, android.R.layout.simple_spinner_item, countries).apply { setAutofillOptions(*countries) }
            contentDescription = "Country"
        }
        val fields = listOf(
            field("First name", TEXT),
            field("Last name", TEXT),
            field("Email", TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS),
            field("Phone", InputType.TYPE_CLASS_PHONE),
            field("Street address", TEXT),
            field("City", TEXT),
            field("State", TEXT),
            field("Postal code", TEXT, View.AUTOFILL_HINT_POSTAL_CODE),
            TextView(this).apply { text = "Country" },
            country,
        )
        setContentView(form("Shipping address", fields, "Save address"))
    }
}
