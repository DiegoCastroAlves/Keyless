package io.github.diegocastroalves.keyless

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets kept on the phone, encrypted with keys in the Android Keystore
 * (hardware-backed where the phone has it): the Secret Key and the session's
 * refresh token with one key, and, for biometric unlock, the user key with
 * another that only works right after a biometric check.
 */
object SecureStore {
    private const val STORE_KEY = "keyless_store"
    private const val BIOMETRIC_KEY = "keyless_biometric"
    private const val PREFS = "keyless_secure"

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun storeKey(): SecretKey {
        (keyStore().getKey(STORE_KEY, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(STORE_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun unb64(text: String) = Base64.decode(text, Base64.NO_WRAP)

    fun put(context: Context, name: String, value: String?) {
        if (value == null) {
            prefs(context).edit().remove(name).apply()
            return
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, storeKey())
        val sealed = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        prefs(context).edit().putString(name, b64(cipher.iv) + ":" + b64(sealed)).apply()
    }

    fun get(context: Context, name: String): String? {
        val stored = prefs(context).getString(name, null) ?: return null
        return try {
            val (iv, sealed) = stored.split(":").let { unb64(it[0]) to unb64(it[1]) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, storeKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(sealed), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    fun clear(context: Context) {
        prefs(context).edit().clear().apply()
        try {
            keyStore().deleteEntry(BIOMETRIC_KEY)
        } catch (e: Exception) {
            // Nothing to delete.
        }
    }

    // ----- biometric unlock -------------------------------------------------

    fun biometricEnabled(context: Context): Boolean = prefs(context).contains("biometric")

    /** A cipher that encrypts with a new biometric key, once the user is checked. */
    fun biometricEncryptCipher(): Cipher {
        val keys = keyStore()
        if (keys.containsAlias(BIOMETRIC_KEY)) keys.deleteEntry(BIOMETRIC_KEY)
        val builder = KeyGenParameterSpec.Builder(BIOMETRIC_KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(builder.build()) }.generateKey()
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    /** A cipher that decrypts the kept user key once the user is checked, or null (off, or invalidated). */
    fun biometricDecryptCipher(context: Context): Cipher? {
        val stored = prefs(context).getString("biometric", null) ?: return null
        return try {
            val key = keyStore().getKey(BIOMETRIC_KEY, null) as? SecretKey ?: return null
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, unb64(stored.split(":")[0]))) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            disableBiometric(context)
            null
        } catch (e: Exception) {
            null
        }
    }

    fun saveBiometric(context: Context, cipher: Cipher, userKey: String) {
        val sealed = cipher.doFinal(userKey.toByteArray(Charsets.UTF_8))
        prefs(context).edit().putString("biometric", b64(cipher.iv) + ":" + b64(sealed)).apply()
    }

    fun openBiometric(context: Context, cipher: Cipher): String? {
        val stored = prefs(context).getString("biometric", null) ?: return null
        return try {
            String(cipher.doFinal(unb64(stored.split(":")[1])), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    fun disableBiometric(context: Context) {
        prefs(context).edit().remove("biometric").apply()
        try {
            keyStore().deleteEntry(BIOMETRIC_KEY)
        } catch (e: Exception) {
            // Nothing to delete.
        }
    }
}
