package io.github.diegocastroalves.keyless

import android.app.AlertDialog
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import org.json.JSONObject
import java.text.DateFormat
import java.time.Instant
import kotlin.concurrent.thread

/** "2026-10-14T10:00:00+00:00" as the phone shows dates, or the text itself. */
private fun when_(text: String): String = try {
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(java.util.Date.from(Instant.parse(text.replace(" ", "T").let { if (it.endsWith("+00")) "${it}:00" else it })))
} catch (e: Exception) {
    text
}

private fun MainActivity.platformName(platform: String): String = when (platform) {
    "android" -> "Android"
    "ios" -> "iPhone"
    "linux" -> "Linux"
    "windows" -> "Windows"
    "macos" -> "Mac"
    "web" -> getString(R.string.platform_web)
    else -> platform
}

/** The account's signed-in devices, with signing one out. */
internal fun MainActivity.showDevices() {
    val page = column(20)
    page.add(plainButton("← " + getString(R.string.back)) { showSettings() }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
    page.add(label(getString(R.string.devices), 24f, bold = true), top = 8)
    page.add(label(getString(R.string.devices_hint), 13f, muted = true), top = 4)
    val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(list, top = 12)
    list.add(label(getString(R.string.syncing), 14f, muted = true))
    show("devices", page)
    thread {
        val result = try {
            Keyless.devices()
        } catch (e: Exception) {
            e
        }
        runOnUiThread {
            if (screen != "devices") return@runOnUiThread
            list.removeAllViews()
            if (result is Exception) {
                list.add(label(errorText(result), 14f).apply { setTextColor(getColor(R.color.danger)) })
                return@runOnUiThread
            }
            @Suppress("UNCHECKED_CAST")
            for (device in result as List<JSONObject>) {
                val name = device.optString("name").ifBlank { getString(R.string.unnamed_device) }
                val panel = panel()
                panel.add(label(name, 16f, bold = true))
                val system = listOf(device.optString("os").ifBlank { platformName(device.optString("platform")) }, device.optString("appVersion").let { if (it.isNotBlank()) "Keyless $it" else "" })
                    .filter { it.isNotBlank() }.joinToString(" · ")
                if (system.isNotEmpty()) panel.add(label(system, 13f, muted = true), top = 2)
                val place = listOf(device.optString("country"), device.optString("ip")).filter { it.isNotBlank() && it != "null" }.joinToString(" · ")
                if (place.isNotEmpty()) panel.add(label(place, 13f, muted = true), top = 2)
                if (device.optBoolean("current")) {
                    panel.add(label(getString(R.string.this_device), 13f).apply { setTextColor(accent()) }, top = 4)
                } else {
                    panel.add(label(getString(R.string.last_seen, when_(device.optString("last_seen_at"))) + " · " + getString(R.string.since, when_(device.optString("created_at"))), 12f, muted = true), top = 4)
                    panel.add(plainButton(getString(R.string.sign_out_device)) {
                        AlertDialog.Builder(this)
                            .setTitle(getString(R.string.sign_out_device_title, name))
                            .setMessage(R.string.sign_out_device_body)
                            .setPositiveButton(R.string.sign_out_device) { _, _ ->
                                act({ Keyless.revokeDevice(device.getString("id")) }) {
                                    Toast.makeText(this, getString(R.string.device_signed_out, name), Toast.LENGTH_SHORT).show()
                                    showDevices()
                                }
                            }
                            .setNegativeButton(R.string.cancel, null)
                            .show()
                    }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
                }
                list.add(panel, top = 8)
            }
        }
    }
}

/** Shows `banner` when a new device asks to sign in to this account. */
internal fun MainActivity.checkDeviceRequests(banner: LinearLayout) {
    thread {
        val waiting = try {
            Keyless.pendingDeviceSetups().filter { it.optString("status") == "pending" }
        } catch (e: Exception) {
            emptyList()
        }
        runOnUiThread {
            banner.removeAllViews()
            val request = waiting.firstOrNull() ?: return@runOnUiThread
            val panel = panel()
            panel.add(label(getString(R.string.new_device_waiting), 14f, bold = true))
            panel.add(plainButton(getString(R.string.review)) { reviewDeviceRequest(request) { checkDeviceRequests(banner) } }, width = ViewGroup.LayoutParams.WRAP_CONTENT)
            banner.add(panel)
        }
    }
}

/** Approving a new device: it is me, then the code the new device shows. */
private fun MainActivity.reviewDeviceRequest(request: JSONObject, done: () -> Unit) {
    val id = request.getString("id")
    val place = listOf(platformName(request.optString("platform")), request.optString("country"), request.optString("ip"), when_(request.optString("created_at")))
        .filter { it.isNotBlank() && it != "null" }.joinToString(" · ")
    AlertDialog.Builder(this)
        .setTitle(R.string.approve_title)
        .setMessage(getString(R.string.approve_body) + "\n\n" + place + "\n\n" + getString(R.string.approve_warning))
        .setPositiveButton(R.string.its_me) { _, _ ->
            var taken = false
            act({ taken = Keyless.answerDeviceSetup(request) }) {
                if (!taken) {
                    Toast.makeText(this, getString(R.string.err_device_setup_expired), Toast.LENGTH_LONG).show()
                    done()
                } else {
                    waitForCode(id, done)
                }
            }
        }
        .setNegativeButton(R.string.deny) { _, _ ->
            act({ Keyless.denyDeviceSetup(id) }) {
                Toast.makeText(this, getString(R.string.denied), Toast.LENGTH_SHORT).show()
                done()
            }
        }
        .setNeutralButton(R.string.cancel, null)
        .show()
}

/** Waits until the new device shows its code, then asks for it. */
private fun MainActivity.waitForCode(id: String, done: () -> Unit) {
    val waiting = AlertDialog.Builder(this).setMessage(R.string.approve_waiting).setNegativeButton(R.string.cancel, null).show()
    thread {
        val deadline = System.currentTimeMillis() + 10 * 60_000L
        var nonce: String? = null
        while (waiting.isShowing && System.currentTimeMillis() < deadline) {
            val request = try {
                Keyless.pendingDeviceSetups().firstOrNull { it.optString("id") == id }
            } catch (e: Exception) {
                null
            }
            if (request == null) break
            if (request.optString("status") == "revealed" && request.optBoolean("mine")) {
                nonce = request.optString("nonce")
                break
            }
            Thread.sleep(2000)
        }
        runOnUiThread {
            val shown = waiting.isShowing
            waiting.dismiss()
            when {
                nonce != null -> askCode(id, nonce!!, done)
                shown -> {
                    Toast.makeText(this, getString(R.string.err_device_setup_expired), Toast.LENGTH_LONG).show()
                    done()
                }
                else -> done()
            }
        }
    }
}

private fun MainActivity.askCode(id: String, nonce: String, done: () -> Unit) {
    val code = EditText(this).apply {
        inputType = InputType.TYPE_CLASS_NUMBER
        hint = "000 000"
        textSize = 24f
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }
    val box = column(20).apply { add(code) }
    val dialog = AlertDialog.Builder(this)
        .setTitle(R.string.approve_type_code)
        .setView(box)
        .setPositiveButton(R.string.approve, null)
        .setNegativeButton(R.string.deny) { _, _ -> act({ Keyless.denyDeviceSetup(id) }) { done() } }
        .create()
    dialog.setOnShowListener {
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val typed = code.text.toString()
            thread {
                val failure = try {
                    Keyless.approveDeviceSetup(id, nonce, typed)
                    null
                } catch (e: Exception) {
                    e
                }
                runOnUiThread {
                    when {
                        failure == null -> {
                            dialog.dismiss()
                            Toast.makeText(this, getString(R.string.approved), Toast.LENGTH_LONG).show()
                            done()
                        }
                        (failure as? KeylessException)?.key == "device_setup_code_wrong" -> {
                            code.setText("")
                            code.error = errorText(failure)
                        }
                        else -> {
                            dialog.dismiss()
                            Toast.makeText(this, errorText(failure), Toast.LENGTH_LONG).show()
                            done()
                        }
                    }
                }
            }
        }
    }
    dialog.show()
}
