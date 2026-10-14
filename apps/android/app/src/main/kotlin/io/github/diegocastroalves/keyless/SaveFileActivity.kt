package io.github.diegocastroalves.keyless

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.Toast
import kotlin.concurrent.thread

/**
 * "Save in Keyless" in the share menu: a file another app shares becomes a
 * Document item (as the desktop's Document template), encrypted before it
 * leaves the phone.
 */
class SaveFileActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val uri = sharedUri()
        if (uri == null) {
            finish()
            return
        }
        if (!Keyless.hasAccount) {
            Toast.makeText(this, R.string.save_needs_account, Toast.LENGTH_LONG).show()
            finish()
            return
        }
        if (Keyless.isUnlocked) {
            chooseVault(uri)
        } else {
            setContentView(FrameLayout(this).apply { addView(unlockForm(onUnlocked = { chooseVault(uri) }, onSignOut = null)) })
        }
    }

    private fun sharedUri(): Uri? {
        if (intent?.action != Intent.ACTION_SEND) return null
        return if (Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
    }

    private fun chooseVault(uri: Uri) {
        setContentView(FrameLayout(this))
        val vaults = Keyless.writableVaults()
        when {
            vaults.isEmpty() -> {
                Toast.makeText(this, R.string.err_vault_read_only, Toast.LENGTH_LONG).show()
                finish()
            }
            vaults.size == 1 -> save(uri, vaults[0].getString("id"))
            else -> AlertDialog.Builder(this)
                .setTitle(R.string.vault)
                .setItems(vaults.map { it.optString("name") }.toTypedArray()) { _, which -> save(uri, vaults[which].getString("id")) }
                .setOnCancelListener { finish() }
                .show()
        }
    }

    private fun save(uri: Uri, vaultId: String) {
        val (name, size) = try {
            fileInfo(uri)
        } catch (e: Exception) {
            Toast.makeText(this, errorText(e), Toast.LENGTH_LONG).show()
            finish()
            return
        }
        val (dialog, progress) = progressDialog(getString(R.string.save_in_keyless))
        thread {
            val failure = try {
                contentResolver.openInputStream(uri)?.use { input ->
                    Keyless.saveDocument(vaultId, name, size, input, Labels.field(this, "document"), progress)
                } ?: throw KeylessException("file_unreadable")
                null
            } catch (e: Exception) {
                e
            }
            runOnUiThread {
                dialog.dismiss()
                Toast.makeText(this, if (failure == null) getString(R.string.saved_in_keyless, name) else errorText(failure), Toast.LENGTH_LONG).show()
                finish()
            }
        }
    }
}
