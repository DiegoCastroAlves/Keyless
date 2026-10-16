package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.CancellationSignal
import android.text.format.Formatter
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.Toast
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.providerevents.ProviderEventsManager
import androidx.credentials.providerevents.exception.ImportCredentialsCancellationException
import androidx.credentials.providerevents.exception.ImportCredentialsException
import androidx.credentials.providerevents.exception.ImportCredentialsNoExportOptionException
import androidx.credentials.providerevents.exception.ImportCredentialsProviderConfigurationException
import androidx.credentials.providerevents.transfer.CredentialTypes
import androidx.credentials.providerevents.transfer.ImportCredentialsRequest
import androidx.credentials.providerevents.transfer.ProviderImportCredentialsResponse
import org.json.JSONObject
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/*
 * The account's recovery key (making and removing it, and recovering a
 * signed-out account), importing and exporting, as the desktop.
 */

private const val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

/** Asks for the master password, then calls `then` with it. */
internal fun Activity.askMasterPassword(title: String, message: String? = null, then: (String) -> Unit) {
    val input = field(getString(R.string.master_password), TEXT_PASSWORD, autofill = View.AUTOFILL_HINT_PASSWORD)
    AlertDialog.Builder(this)
        .setTitle(title)
        .setMessage(message)
        .setView(column(20).apply { add(input) })
        .setPositiveButton(t("common.continue")) { _, _ -> if (input.text.isNotEmpty()) then(input.text.toString()) }
        .setNegativeButton(t("common.cancel"), null)
        .show()
}

/** A line with a secret to write down, and a button to copy it. */
private fun MainActivity.copyLine(name: String, value: String): View {
    val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    box.add(label(name, 12f, muted = true))
    val line = row()
    line.add(label(value, 16f).apply { typeface = Typeface.MONOSPACE; setTextIsSelectable(true) }, width = 0, weight = 1f)
    line.add(plainButton(t("common.copy")) { copy(name, value) }, width = WRAP)
    box.add(line)
    return box
}

// ----- the recovery key (signed in) --------------------------------------------------------

internal fun MainActivity.showRecoveryKey() {
    val page = column(20)
    page.addBack { showSettingsPage("account") }
    page.add(label(t("recovery.title"), 24f, bold = true), top = 8)
    page.add(label(t("recovery.settingsBody"), 13f, muted = true), top = 4)
    val status = label(t("itemHistory.loading"), 14f, muted = true)
    page.add(status, top = 16)
    val actions = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    page.add(actions, top = 8)
    show("recovery-key", page)
    thread {
        val created = try {
            Result.success(Keyless.recoveryKeyCreated())
        } catch (e: Exception) {
            Result.failure(e)
        }
        runOnUiThread {
            if (screen != "recovery-key") return@runOnUiThread
            val has = created.getOrNull() != null
            status.text = when {
                created.isFailure -> t("recovery.statusUnknown")
                has -> t("recovery.statusCreated", mapOf("date" to isoDate(created.getOrNull() ?: "")))
                else -> t("recovery.statusNone")
            }
            if (created.isFailure) return@runOnUiThread
            actions.add(primaryButton(t(if (has) "recovery.replace" else "recovery.create")) {
                askMasterPassword(t(if (has) "recovery.replace" else "recovery.create"), if (has) t("recovery.replaceBody") else null) { password ->
                    var key = ""
                    act({ key = Keyless.createRecoveryKey(password) }) { showNewRecoveryKey(key) }
                }
            })
            if (has) {
                actions.add(plainButton(t("recovery.remove")) {
                    AlertDialog.Builder(this)
                        .setTitle(t("recovery.removeTitle"))
                        .setMessage(t("recovery.removeBody"))
                        .setPositiveButton(t("recovery.remove")) { _, _ ->
                            askMasterPassword(t("recovery.removeTitle")) { password ->
                                act({ Keyless.removeRecoveryKey(password) }) {
                                    Toast.makeText(this, t("recovery.removed"), Toast.LENGTH_SHORT).show()
                                    showRecoveryKey()
                                }
                            }
                        }
                        .setNegativeButton(t("common.cancel"), null)
                        .show()
                }, width = WRAP, top = 4)
            }
        }
    }
}

private fun isoDate(iso: String): String =
    try {
        val parsed = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).parse(iso.take(10))
        if (parsed != null) DateFormat.getDateInstance().format(parsed) else iso
    } catch (e: Exception) {
        iso
    }

private fun MainActivity.showNewRecoveryKey(key: String) {
    val box = column(20)
    box.add(label(t("recovery.kitIntro"), 13f, muted = true))
    box.add(copyLine(t("recovery.keyLabel"), key), top = 12)
    val saved = CheckBox(this).apply { text = t("recovery.saved") }
    box.add(saved, top = 12)
    val dialog = AlertDialog.Builder(this)
        .setTitle(t("recovery.createdTitle"))
        .setView(ScrollView(this).apply { addView(box) })
        .setCancelable(false)
        .setPositiveButton(t("recovery.done")) { _, _ -> showRecoveryKey() }
        .create()
    dialog.setOnShowListener {
        val done = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
        done.isEnabled = false
        saved.setOnCheckedChangeListener { _, checked -> done.isEnabled = checked }
    }
    dialog.show()
}

// ----- recovering (signed out) ------------------------------------------------------------

internal fun MainActivity.showRecover() {
    val form = column()
    form.add(label(t("recovery.recoverTitle"), 22f, bold = true))
    form.add(label(t("recovery.recoverBody"), 14f, muted = true), top = 6)
    val email = field(getString(R.string.email), TEXT_EMAIL, autofill = View.AUTOFILL_HINT_EMAIL_ADDRESS)
    val key = field("KLRK-XXXX-XXXX-…", TEXT_KEY, secret = true)
    val error = label("", 14f).apply { setTextColor(getColor(R.color.danger)) }
    form.add(email, top = 20)
    form.add(key, top = 8)
    form.add(error, top = 6)
    lateinit var next: Button
    next = primaryButton(t("common.continue")) {
        val address = email.text.toString().trim()
        val typed = key.text.toString()
        if (!address.contains("@") || typed.isBlank()) return@primaryButton
        next.isEnabled = false
        error.text = ""
        thread {
            val failure = try {
                Keyless.recoveryBegin(address, typed)
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                next.isEnabled = true
                if (failure == null) showRecoverPassword(address.lowercase()) else error.text = errorText(failure)
            }
        }
    }
    form.add(next, top = 8)
    form.add(plainButton(t("common.cancel")) { leaveRecovery() }, top = 4)
    show("recover", form)
}

internal fun MainActivity.leaveRecovery() {
    thread { Keyless.recoveryCancel() }
    route()
}

private fun MainActivity.showRecoverPassword(email: String) {
    val form = column()
    form.add(label(t("recovery.newPasswordTitle"), 22f, bold = true))
    form.add(label(t("recovery.newPasswordBody", mapOf("email" to email)), 14f, muted = true), top = 6)
    // The new master password, for the user's password manager to keep.
    val password = field(getString(R.string.master_password), TEXT_PASSWORD, autofill = NEW_PASSWORD)
    val again = field(getString(R.string.master_password), TEXT_PASSWORD, autofill = NEW_PASSWORD)
    val error = label("", 14f).apply { setTextColor(getColor(R.color.danger)) }
    form.add(password, top = 20)
    form.add(again, top = 8)
    form.add(error, top = 6)
    lateinit var next: Button
    next = primaryButton(t("common.continue")) {
        val typed = password.text.toString()
        if (typed != again.text.toString()) {
            error.text = getString(R.string.passwords_differ)
            return@primaryButton
        }
        next.isEnabled = false
        error.text = ""
        thread {
            val result = try {
                Keyless.recoveryPrepare(typed)
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                next.isEnabled = true
                if (result is JSONObject) showRecoverKits(result) else error.text = errorText(result as Exception)
            }
        }
    }
    form.add(next, top = 8)
    form.add(plainButton(t("recovery.restart")) { leaveRecovery() }, top = 4)
    show("recover", form)
}

private fun MainActivity.showRecoverKits(show: JSONObject) {
    val form = column()
    form.add(label(t("recovery.kitsTitle"), 22f, bold = true))
    form.add(label(t("recovery.kitsBody"), 14f, muted = true), top = 6)
    form.add(copyLine(getString(R.string.email), show.getString("email")), top = 16)
    form.add(copyLine(t("common.secretKey"), show.getString("secretKey")), top = 8)
    form.add(copyLine(t("recovery.keyLabel"), show.getString("recoveryKey")), top = 8)
    val saved = CheckBox(this).apply { text = t("recovery.kitsSaved") }
    form.add(saved, top = 12)
    val error = label("", 14f).apply { setTextColor(getColor(R.color.danger)) }
    form.add(error, top = 6)
    lateinit var finish: Button
    finish = primaryButton(t("recovery.finish")) {
        finish.isEnabled = false
        error.text = ""
        thread {
            val failure = try {
                Keyless.recoveryFinish()
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                if (failure == null) {
                    notePasswordTyped()
                    Toast.makeText(this, t("recovery.otherDevices"), Toast.LENGTH_LONG).show()
                    route()
                } else {
                    finish.isEnabled = true
                    error.text = errorText(failure) + "\n\n" + t("recovery.finishRetryHint")
                }
            }
        }
    }.apply { isEnabled = false }
    saved.setOnCheckedChangeListener { _, checked -> finish.isEnabled = checked }
    form.add(finish, top = 8)
    form.add(plainButton(t("recovery.restart")) { leaveRecovery() }, top = 4)
    show("recover", form)
}

// ----- importing ---------------------------------------------------------------------

private class ImportFormat(val id: String, val name: String, val hint: String, val password: String? = null, val passwordRequired: Boolean = false, val keyFile: Boolean = false)

private fun Context.importFormats() = listOf(
    ImportFormat("one_pux", "importer.onePassword", "importer.onePasswordHint"),
    ImportFormat("csv", "importer.csv", "importer.csvHint"),
    ImportFormat("json", "importer.json", "importer.jsonHint", password = "importer.jsonPassword"),
    ImportFormat("kdbx", "importer.keepass", "importer.keepassHint", password = "importer.keepassPassword", keyFile = true),
    ImportFormat("keyless_backup", "importer.backup", "importer.backupHint", password = "importer.backupPassword", passwordRequired = true),
    ImportFormat("keyless_export", "importer.keylessExport", "importer.keylessExportHint"),
    ImportFormat("one_pif", "importer.onePif", "importer.onePifHint"),
    ImportFormat("keeper_csv", "importer.keeperCsv", "importer.keeperCsvHint"),
    ImportFormat("dashlane_zip", "importer.dashlane", "importer.dashlaneHint"),
)

/** Import files larger than this are refused (they are read into memory). */
private const val MAX_IMPORT_BYTES = 256L * 1024 * 1024

private fun MainActivity.readPicked(uri: android.net.Uri): ByteArray {
    val (_, size) = fileInfo(uri)
    if (size > MAX_IMPORT_BYTES) throw KeylessException("file_too_large")
    return contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: throw KeylessException("file_unreadable")
}

internal fun MainActivity.showImport() {
    val page = column(20)
    page.addBack { showSettingsPage("transfer") }
    page.add(label(t("importer.title"), 24f, bold = true), top = 8)
    // Straight from another app on the phone, passkeys included.
    val fromApp = panel()
    fromApp.add(label(getString(R.string.import_from_app), 16f, bold = true))
    fromApp.add(label(getString(R.string.import_from_app_hint), 13f, muted = true), top = 2)
    fromApp.add(primaryButton(getString(R.string.import_from_app_choose)) { importFromApp() }, top = 6)
    page.add(fromApp, top = 12)
    for (format in importFormats()) {
        val panel = panel()
        panel.add(label(t(format.name), 16f, bold = true))
        panel.add(label(t(format.hint), 13f, muted = true), top = 2)
        val password = format.password?.let { field(t(it), TEXT_PASSWORD, secret = true) }
        password?.let { panel.add(it, top = 4) }
        var keyFile: ByteArray? = null
        if (format.keyFile) {
            lateinit var choose: Button
            choose = plainButton(t("importer.keyFile") + ": " + t("importer.keyFileNone")) {
                startForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")) { result, data ->
                    val uri = data?.data ?: return@startForResult
                    if (result != Activity.RESULT_OK) return@startForResult
                    try {
                        keyFile = readPicked(uri)
                        choose.text = t("importer.keyFile") + ": " + fileInfo(uri).first
                    } catch (e: Exception) {
                        Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
                    }
                }
            }
            panel.add(choose, width = WRAP, top = 2)
        }
        panel.add(secondaryButton(t("importer.choose")) {
            val typed = password?.text?.toString()
            if (format.passwordRequired && typed.isNullOrEmpty()) {
                password?.error = t("errors.backup_password_required")
                return@secondaryButton
            }
            startForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")) { result, data ->
                val uri = data?.data
                if (result != Activity.RESULT_OK || uri == null) return@startForResult
                var summary: JSONObject? = null
                act({
                    val name = fileInfo(uri).first.substringBeforeLast('.')
                    summary = Keyless.importParse(format.id, readPicked(uri), typed, keyFile, "Imported ($name)")
                }) { summary?.let { confirmImport(it) } }
            }
        }, top = 6)
        page.add(panel, top = 12)
    }
    show("transfer", page)
}

/**
 * "Import from another app": Android lists the apps on this phone that hand
 * over their items (the Credential Exchange standard: 1Password, Google
 * Password Manager...); the one chosen sends them as CXF, read as any import.
 */
private fun MainActivity.importFromApp() {
    val request = ImportCredentialsRequest(
        setOf(
            CredentialTypes.CREDENTIAL_TYPE_BASIC_AUTH,
            CredentialTypes.CREDENTIAL_TYPE_PUBLIC_KEY,
            CredentialTypes.CREDENTIAL_TYPE_TOTP,
            CredentialTypes.CREDENTIAL_TYPE_NOTE,
            CredentialTypes.CREDENTIAL_TYPE_CREDIT_CARD,
            CredentialTypes.CREDENTIAL_TYPE_ADDRESS,
            CredentialTypes.CREDENTIAL_TYPE_API_KEY,
            CredentialTypes.CREDENTIAL_TYPE_WIFI,
            CredentialTypes.CREDENTIAL_TYPE_CUSTOM_FIELDS,
            CredentialTypes.CREDENTIAL_TYPE_SSH_KEY,
            CredentialTypes.CREDENTIAL_TYPE_PERSON_NAME,
            CredentialTypes.CREDENTIAL_TYPE_DRIVERS_LICENSE,
            CredentialTypes.CREDENTIAL_TYPE_PASSPORT,
            CredentialTypes.CREDENTIAL_TYPE_IDENTITY_DOCUMENT,
        ),
        emptySet(),
    )
    val callback = object : CredentialManagerCallback<ProviderImportCredentialsResponse, ImportCredentialsException> {
        override fun onResult(result: ProviderImportCredentialsResponse) {
            val json = result.response.responseJson
            val from = result.callingAppInfo.packageName.let { name ->
                try {
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(name, 0)).toString()
                } catch (e: Exception) {
                    name
                }
            }
            var summary: JSONObject? = null
            act({ summary = Keyless.importParse("json", json.toByteArray(), null, null, "Imported ($from)") }) { summary?.let { confirmImport(it) } }
        }

        override fun onError(e: ImportCredentialsException) {
            val message = when (e) {
                is ImportCredentialsCancellationException -> return
                is ImportCredentialsNoExportOptionException -> getString(R.string.import_from_app_none)
                is ImportCredentialsProviderConfigurationException -> getString(R.string.import_from_app_unavailable)
                else -> getString(R.string.import_from_app_failed, e.errorMessage ?: e.type)
            }
            Toast.makeText(this@importFromApp, message, Toast.LENGTH_LONG).show()
        }
    }
    try {
        ProviderEventsManager.create(this).importCredentialsAsync(this, request, CancellationSignal(), mainExecutor, callback)
    } catch (e: Exception) {
        Toast.makeText(this, getString(R.string.import_from_app_unavailable), Toast.LENGTH_LONG).show()
    }
}

private fun MainActivity.confirmImport(summary: JSONObject) {
    val total = summary.optInt("total_items")
    val box = column(20)
    box.add(label(t("importer.found", mapOf("count" to total)), 16f, bold = true))
    val vaults = summary.optJSONArray("vaults")
    val sources = (0 until (vaults?.length() ?: 0)).map { vaults!!.getJSONArray(it) }
    for (v in sources) box.add(label(t("importer.vaultLine", mapOf("name" to v.optString(0), "count" to v.optInt(1))), 13f, muted = true), top = 2)
    val files = summary.optInt("files")
    if (files > 0) box.add(label(t("importer.filesLine", mapOf("count" to files, "size" to Formatter.formatShortFileSize(this, summary.optLong("file_bytes")))), 13f, muted = true), top = 2)
    val passkeys = summary.optInt("passkeys")
    if (passkeys > 0) box.add(label(t("importer.passkeysLine", mapOf("count" to passkeys)), 13f, muted = true), top = 2)
    val warnings = summary.optJSONArray("warnings")
    if (warnings != null && warnings.length() > 0) {
        box.add(label(t("importer.warnings"), 14f, bold = true), top = 8)
        for (i in 0 until warnings.length()) {
            val w = warnings.getJSONObject(i)
            box.add(label(t("importer.warn_${w.optString("code")}", mapOf("count" to w.optInt("n"))), 13f, muted = true), top = 2)
        }
    }
    // An import again: some items are in the account already.
    val fresh = summary.optInt("new_items", total)
    val same = summary.optInt("same_items")
    val changed = summary.optInt("changed_items")
    val kept = summary.optInt("kept_items")
    val known = same + changed + kept
    val updateChanged = CheckBox(this).apply {
        text = t("importer.updateChanged")
        isChecked = true
    }
    if (known > 0) {
        val compare = panel()
        compare.add(label(t("importer.compareTitle"), 14f, bold = true))
        compare.add(label(t("importer.compareNew", mapOf("count" to fresh)), 13f).apply { if (fresh > 0) setTextColor(accent()) }, top = 4)
        if (same > 0) compare.add(label(t("importer.compareSame", mapOf("count" to same)), 13f, muted = true), top = 2)
        if (changed > 0) compare.add(label(t("importer.compareChanged", mapOf("count" to changed)), 13f), top = 2)
        if (kept > 0) compare.add(label(t("importer.compareKept", mapOf("count" to kept)), 13f, muted = true), top = 2)
        if (changed > 0) compare.add(updateChanged, top = 6)
        box.add(compare, top = 12)
    }
    val newCounts = summary.optJSONArray("vault_new")
    val targetTitle = label(t(if (known > 0) "importer.newTarget" else "importer.target"), 14f, bold = true)
    box.add(targetTitle, top = 12)
    val choice = RadioGroup(this)
    val existing = RadioButton(this).apply { text = t("importer.existingVault"); id = View.generateViewId() }
    val newVault = RadioButton(this).apply { text = t("importer.newVault"); id = View.generateViewId() }
    val recreate = RadioButton(this).apply { text = t("importer.newVaults"); id = View.generateViewId() }
    val writable = Keyless.writableVaults()
    if (writable.isNotEmpty()) choice.addView(existing)
    choice.addView(newVault)
    if (sources.size > 1) choice.addView(recreate)
    (if (writable.isNotEmpty()) existing else newVault).isChecked = true
    box.add(choice, top = 2)
    val spinner = Spinner(this).apply { adapter = ArrayAdapter(this@confirmImport, android.R.layout.simple_spinner_dropdown_item, writable.map { it.optString("name") }) }
    // An import again: the vault with most of each of its vaults' items.
    val homes = summary.optJSONArray("vault_home")
    val home = { v: Int -> if (homes == null || homes.isNull(v)) null else homes.optString(v) }
    val firstHome = sources.indices.firstNotNullOfOrNull { home(it) }
    writable.indexOfFirst { it.optString("id") == firstHome }.takeIf { it >= 0 }?.let { spinner.setSelection(it) }
    val name = EditText(this).apply { setSingleLine(true); setText(t("importer.newVaultDefault")) }
    box.add(spinner, top = 2)
    box.add(name, top = 2)
    fun update() {
        spinner.visibility = if (existing.isChecked && fresh > 0) View.VISIBLE else View.GONE
        name.visibility = if (newVault.isChecked && fresh > 0) View.VISIBLE else View.GONE
    }
    // Where the new items go: only when there are new items.
    if (fresh == 0) {
        targetTitle.visibility = View.GONE
        choice.visibility = View.GONE
    }
    choice.setOnCheckedChangeListener { _, _ -> update() }
    update()
    fun work() = fresh + if (updateChanged.isChecked) changed else 0
    fun runLabel() = when {
        work() == 0 -> t("common.done")
        updateChanged.isChecked && changed > 0 -> t("importer.runUpdate", mapOf("count" to work()))
        else -> t("importer.run", mapOf("count" to work()))
    }
    val confirm = AlertDialog.Builder(this)
        .setView(ScrollView(this).apply { addView(box) })
        .setPositiveButton(runLabel()) { _, _ ->
            if (work() == 0) {
                thread { Keyless.importCancel() }
                Toast.makeText(this, t("importer.upToDate"), Toast.LENGTH_LONG).show()
                return@setPositiveButton
            }
            val (dialog, progress) = progressDialog(t("importer.title"))
            var outcome: JSONObject? = null
            act({
                try {
                    // New items per vault (all of them, before comparing).
                    val newIn = { v: Int -> newCounts?.optInt(v) ?: sources[v].optInt(1) }
                    val anyWritable = writable.firstOrNull()?.getString("id") ?: ""
                    val targets = when {
                        fresh == 0 -> List(sources.size) { anyWritable }
                        existing.isChecked -> List(sources.size) { writable[spinner.selectedItemPosition.coerceAtLeast(0)].getString("id") }
                        newVault.isChecked -> Keyless.createVault(name.text.toString().ifBlank { t("importer.newVaultDefault") }).let { id -> List(sources.size) { id } }
                        else -> {
                            // Where the file's other items are, or a vault of the same
                            // name from an earlier import, gets them.
                            val made = sources.mapIndexed { v, source ->
                                val vaultName = source.optString(0).ifBlank { t("importer.newVaultDefault") }
                                val open = Keyless.writableVaults()
                                if (newIn(v) == 0) {
                                    ""
                                } else {
                                    open.firstOrNull { it.optString("id") == home(v) }?.getString("id")
                                        ?: open.firstOrNull { it.optString("name").trim().equals(vaultName.trim(), ignoreCase = true) }?.getString("id")
                                        ?: Keyless.createVault(vaultName)
                                }
                            }
                            val any = made.firstOrNull { it.isNotEmpty() } ?: anyWritable
                            made.map { it.ifEmpty { any } }
                        }
                    }
                    outcome = Keyless.importRun(targets, updateChanged.isChecked, progress)
                } finally {
                    runOnUiThread { dialog.dismiss() }
                }
            }) {
                val done = outcome ?: return@act
                val lines = mutableListOf<String>()
                if (done.optInt("items") > 0) lines.add(t("importer.done", mapOf("count" to done.optInt("items"))))
                if (done.optInt("updated") > 0) lines.add(t("importer.updated", mapOf("count" to done.optInt("updated"))))
                if (done.optInt("files") > 0) lines.add(t("importer.filesAdded", mapOf("count" to done.optInt("files"))))
                if (done.optInt("filesFailed") > 0) lines.add(t("importer.filesFailed", mapOf("count" to done.optInt("filesFailed"))))
                lines.add(t("importer.deleteExport"))
                AlertDialog.Builder(this).setMessage(lines.joinToString("\n\n")).setPositiveButton(t("common.done")) { _, _ -> showMain() }.show()
            }
        }
        .setNegativeButton(t("common.cancel")) { _, _ -> thread { Keyless.importCancel() } }
        .setCancelable(false)
        .show()
    updateChanged.setOnCheckedChangeListener { _, _ -> confirm.getButton(AlertDialog.BUTTON_POSITIVE)?.text = runLabel() }
}

// ----- exporting -------------------------------------------------------------------------

internal fun MainActivity.showExport() {
    val page = column(20)
    page.addBack { showSettingsPage("transfer") }
    page.add(label(t("importer.exportDialogTitle"), 24f, bold = true), top = 8)

    // The encrypted backup.
    val backup = panel()
    backup.add(label(t("importer.exportTitle"), 16f, bold = true))
    backup.add(label(t("importer.exportBody"), 13f, muted = true), top = 2)
    val backupPassword = field(t("importer.exportPassword"), TEXT_PASSWORD, secret = true)
    val backupAgain = field(t("importer.exportConfirm"), TEXT_PASSWORD, secret = true)
    backup.add(backupPassword, top = 6)
    backup.add(backupAgain, top = 4)
    backup.add(label(t("importer.exportPasswordHint"), 12f, muted = true), top = 2)
    backup.add(plainButton(getString(R.string.generate)) {
        showGenerator(onUse = { generated ->
            backupPassword.setText(generated)
            backupAgain.setText(generated)
            Toast.makeText(this, t("importer.exportPasswordGenerated"), Toast.LENGTH_LONG).show()
        }, copy = { copy(getString(R.string.generated_password), it) })
    }, width = WRAP)
    val passkeys = Switch(this).apply { text = t("importer.includePasskeys"); isChecked = true }
    backup.add(passkeys, top = 4)
    backup.add(label(t("importer.includePasskeysHint"), 12f, muted = true), top = 2)
    backup.add(primaryButton(t("importer.exportRun")) {
        val password = backupPassword.text.toString()
        if (password != backupAgain.text.toString()) {
            backupAgain.error = getString(R.string.passwords_differ)
            return@primaryButton
        }
        askMasterPassword(t("importer.exportMasterPassword")) { master ->
            runExport("backup", master, password, passkeys.isChecked, "keyless-backup-${today()}.keyless", "application/octet-stream")
        }
    }, top = 6)
    page.add(backup, top = 12)

    // The unencrypted export, to move to another password manager.
    val plain = panel()
    plain.add(label(t("importer.plainTitle"), 16f, bold = true))
    plain.add(label(t("importer.plainWarning"), 13f).apply { setTextColor(getColor(R.color.danger)) }, top = 2)
    val formats = RadioGroup(this)
    for (format in listOf("csv", "json", "zip", "cxf", "1pux")) {
        formats.addView(RadioButton(this).apply {
            text = t("importer.plain_$format") + " — " + t("importer.plain_${format}Hint")
            id = View.generateViewId()
            tag = format
            isChecked = format == "csv"
        })
    }
    plain.add(formats, top = 4)
    plain.add(label(t("importer.plainNoPasskeys"), 12f, muted = true), top = 2)
    val understood = CheckBox(this).apply { text = t("importer.plainUnderstood") }
    plain.add(understood, top = 4)
    val run = primaryButton(t("importer.plainRun")) {
        val format = formats.findViewById<RadioButton>(formats.checkedRadioButtonId)?.tag as? String ?: "csv"
        val (ext, type) = when (format) {
            "csv" -> "csv" to "text/csv"
            "zip" -> "zip" to "application/zip"
            "1pux" -> "1pux" to "application/octet-stream"
            else -> "json" to "application/json"
        }
        askMasterPassword(t("importer.exportMasterPassword")) { master ->
            runExport(format, master, null, false, "keyless-export-${today()}.$ext", type)
        }
    }.apply { isEnabled = false }
    understood.setOnCheckedChangeListener { _, checked -> run.isEnabled = checked }
    plain.add(run, top = 4)
    page.add(plain, top = 12)
    show("transfer", page)
}

private fun today(): String = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(Date())

/** Makes the export, then asks where to save it. */
private fun MainActivity.runExport(format: String, masterPassword: String, password: String?, includePasskeys: Boolean, fileName: String, type: String) {
    val (dialog, progress) = progressDialog(t("importer.exportDialogTitle"))
    var made: Triple<ByteArray, Int, Int>? = null
    act({
        try {
            made = Keyless.export(format, masterPassword, password, includePasskeys, progress)
        } finally {
            runOnUiThread { dialog.dismiss() }
        }
    }) {
        val (bytes, items, missing) = made ?: return@act
        val create = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(type).putExtra(Intent.EXTRA_TITLE, fileName)
        startForResult(create) { result, data ->
            val uri = data?.data
            if (result != Activity.RESULT_OK || uri == null) {
                bytes.fill(0)
                return@startForResult
            }
            act({
                try {
                    contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) } ?: throw KeylessException("file_unwritable")
                } finally {
                    bytes.fill(0)
                }
            }) {
                val lines = mutableListOf(t("importer.exported", mapOf("count" to items)))
                if (missing > 0) lines.add(t("importer.filesMissing", mapOf("count" to missing)))
                if (format != "backup") lines.add(t("importer.plainDelete"))
                AlertDialog.Builder(this).setMessage(lines.joinToString("\n\n")).setPositiveButton(t("common.done"), null).show()
            }
        }
    }
}
