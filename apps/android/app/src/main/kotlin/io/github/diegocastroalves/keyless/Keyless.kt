package io.github.diegocastroalves.keyless

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** An item in lists: its id, vault and overview (title, username, websites...). */
class Summary(val id: String, val vaultId: String, val overview: JSONObject) {
    val title: String get() = overview.optString("title")
    val subtitle: String get() = overview.optString("subtitle")
    val category: String get() = overview.optString("category")
    val favorite: Boolean get() = overview.optBoolean("favorite")
    val archived: Boolean get() = overview.optBoolean("archived")
    val trashed: Boolean get() = overview.has("trashed_at") && !overview.isNull("trashed_at")
    val trashedAt: Long get() = overview.optLong("trashed_at")
}

/**
 * The account on this phone: what is kept (the server's ciphertext, in a
 * file; the Secret Key and refresh token, in the Keystore), the session, and
 * the client's unlocked state with its automatic lock. Network calls block:
 * call them off the main thread.
 */
object Keyless {
    private lateinit var app: Context
    private const val PAGE = 500
    private var session: Server.Session? = null
    private var lastActivity = 0L
    /** The items in lists (not archived, not in Recently Deleted). */
    @Volatile var items: List<Summary> = emptyList()
        private set
    @Volatile var archived: List<Summary> = emptyList()
        private set
    @Volatile var trashed: List<Summary> = emptyList()
        private set
    @Volatile var vaults: JSONArray = JSONArray()
        private set

    fun init(context: Context) {
        app = context.applicationContext
        val file = snapshotFile()
        val text = if (file.exists()) file.readText() else ""
        try {
            Native.run("load", text)
        } catch (e: KeylessException) {
            Native.run("load", "")
        }
    }

    private fun snapshotFile() = File(app.filesDir, "vault.json")

    private fun prefs() = app.getSharedPreferences("keyless", Context.MODE_PRIVATE)

    var autoLockMinutes: Int
        get() = prefs().getInt("auto_lock_minutes", 5)
        set(value) = prefs().edit().putInt("auto_lock_minutes", value).apply()

    /** Lock when the phone's screen turns off. */
    var lockOnScreenOff: Boolean
        get() = prefs().getBoolean("lock_on_screen_off", true)
        set(value) = prefs().edit().putBoolean("lock_on_screen_off", value).apply()

    /** How many days biometric unlock works before the master password is asked again. */
    var masterPasswordDays: Int
        get() = prefs().getInt("master_password_days", 14)
        set(value) = prefs().edit().putInt("master_password_days", value).apply()

    fun status(): JSONObject = Native.obj("status")

    val hasAccount: Boolean get() = status().optBoolean("account")

    val email: String get() = status().optString("email", "")

    /** Unlocked and used recently enough; locks itself otherwise. */
    val isUnlocked: Boolean
        get() {
            if (!status().optBoolean("unlocked")) return false
            if (SystemClock.elapsedRealtime() - lastActivity > autoLockMinutes * 60_000L) {
                lock()
                return false
            }
            return true
        }

    fun touch() {
        lastActivity = SystemClock.elapsedRealtime()
    }

    fun lock() {
        Native.run("lock")
        clearCache()
    }

    private fun clearCache() {
        items = emptyList()
        archived = emptyList()
        trashed = emptyList()
        vaults = JSONArray()
    }

    private fun save() {
        val file = snapshotFile()
        val partial = File(file.parentFile, "vault.json.part")
        partial.writeText(Native.run("snapshot").toString())
        partial.renameTo(file)
    }

    /** Signs in with the email, master password and Secret Key, and syncs. */
    fun signIn(email: String, secretKey: String, masterPassword: String) {
        val derived = Native.obj("derive", JSONObject().put("email", email).put("masterPassword", masterPassword).put("secretKey", secretKey))
        val signed = Server.signIn(email.trim().lowercase(), derived.getString("authSecret"))
        val profile = Server.profile(signed.accessToken, signed.userId)
        Native.run("signedIn", JSONObject().put("userId", signed.userId).put("profile", profile ?: JSONObject.NULL))
        session = signed
        SecureStore.put(app, "secret_key", secretKey.trim().uppercase())
        SecureStore.put(app, "refresh_token", signed.refreshToken)
        SecureStore.disableBiometric(app)
        touch()
        save()
        try {
            registerDevice(signed.accessToken)
        } catch (e: KeylessException) {
            // Tried again when the phone is next seen.
        }
        sync()
    }

    /** Unlocks with the master password (the Secret Key is on the phone). */
    fun unlock(masterPassword: String) {
        val secretKey = SecureStore.get(app, "secret_key") ?: throw KeylessException("secret_key_invalid")
        Native.run("unlock", JSONObject().put("email", email).put("masterPassword", masterPassword).put("secretKey", secretKey))
        touch()
        refreshCache()
    }

    fun unlockWithUserKey(userKey: String) {
        Native.run("unlockWithUserKey", JSONObject().put("userKey", userKey))
        touch()
        refreshCache()
    }

    fun exportUserKey(): String = Native.run("exportUserKey") as String

    private fun token(): String {
        val current = session
        if (current != null && current.expiresAt - 60 > System.currentTimeMillis() / 1000) return current.accessToken
        val refresh = current?.refreshToken ?: SecureStore.get(app, "refresh_token") ?: throw KeylessException("session_expired")
        val renewed = try {
            Server.refresh(refresh)
        } catch (e: KeylessException) {
            // Signed out from another device: everything goes from here too.
            if (e.key == "session_expired" && checkRevoked()) throw KeylessException("device_revoked")
            throw e
        }
        session = renewed
        SecureStore.put(app, "refresh_token", renewed.refreshToken)
        deviceSeen(renewed.accessToken)
        return renewed.accessToken
    }

    /** Pulls the vaults and the items that changed, checked by the client. */
    fun sync() {
        val access = token()
        val userId = status().optString("userId")
        Native.run("applyMemberships", Server.memberships(access, userId))
        val vaultList = Native.arr("vaults")
        for (i in 0 until vaultList.length()) {
            val vaultId = vaultList.getJSONObject(i).getString("id")
            while (true) {
                val cursor = (Native.run("cursor", JSONObject().put("vaultId", vaultId)) as Number).toLong()
                val page = Server.itemsSince(access, vaultId, cursor, PAGE)
                Native.run("applyItems", JSONObject().put("vaultId", vaultId).put("items", page))
                if (page.length() < PAGE) break
            }
        }
        save()
        refreshCache()
    }

    private fun refreshCache() {
        vaults = Native.arr("vaults")
        val list = Native.arr("items")
        val all = ArrayList<Summary>(list.length())
        for (i in 0 until list.length()) {
            val row = list.getJSONObject(i)
            all.add(Summary(row.getString("id"), row.getString("vaultId"), row.getJSONObject("overview")))
        }
        all.sortBy { it.title.lowercase() }
        trashed = all.filter { it.trashed }.sortedByDescending { it.trashedAt }
        archived = all.filter { !it.trashed && it.archived }
        items = all.filter { !it.trashed && !it.archived }
    }

    /** The vaults items can be written to, the account's own first. */
    fun writableVaults(): List<JSONObject> =
        (0 until vaults.length()).map { vaults.getJSONObject(it) }.filter { it.optBoolean("canWrite") }.sortedBy { if (it.optString("role") == "owner") 0 else 1 }

    fun canWrite(vaultId: String): Boolean = writableVaults().any { it.optString("id") == vaultId }

    private fun now(): Long = System.currentTimeMillis() / 1000

    /**
     * Uploads a write (`sealItem`, `saveDraft`, `setFlags`, `sealTombstone`...)
     * and keeps what the server answers. When the item changed meanwhile, the
     * desktop's rules settle it (`planConflict`): the most recent edit wins,
     * the other is kept as a conflicted copy. Returns the item's id.
     */
    fun upload(sealed: JSONObject): String {
        val id = sealed.getString("id")
        val vaultId = sealed.getString("vaultId")
        val access = token()
        val deletion = sealed.has("encTombstone")
        var rows = when {
            deletion -> Server.patchItem(access, id, sealed.getLong("baseRevision"), JSONObject().put("enc_tombstone", sealed.getString("encTombstone")))
            sealed.isNull("baseRevision") -> Server.insertItem(access, id, vaultId, sealed.getString("encOverview"), sealed.getString("encDetails"))
            else -> Server.updateItem(access, id, sealed.getLong("baseRevision"), sealed.getString("encOverview"), sealed.getString("encDetails"))
        }
        var attempts = 0
        while (rows.length() == 0 && attempts < 3) {
            attempts++
            val remote = Server.item(access, id) ?: break
            val plan = Native.obj("planConflict", JSONObject(sealed.toString()).put("remote", remote))
            plan.optJSONObject("copy")?.let { copy ->
                val copied = Server.insertItem(access, copy.getString("id"), copy.getString("vaultId"), copy.getString("encOverview"), copy.getString("encDetails"))
                Native.run("applyItems", JSONObject().put("vaultId", vaultId).put("items", copied))
            }
            rows = if (plan.getString("plan") == "overwrite") {
                Server.patchItem(access, id, remote.getLong("revision"), plan.getJSONObject("body"))
            } else {
                JSONArray().put(remote)
            }
        }
        if (rows.length() == 0) throw KeylessException("save_conflict")
        Native.run("applyItems", JSONObject().put("vaultId", vaultId).put("items", rows))
        save()
        refreshCache()
        return id
    }

    /** The item as the editor shows it. */
    fun draftOf(id: String): JSONObject = Native.obj("draftOf", JSONObject().put("id", id))

    /** Saves what the editor made; returns the item's id. */
    fun saveDraft(draft: JSONObject): String = upload(Native.obj("saveDraft", JSONObject().put("draft", draft).put("now", now())))

    fun setFavorite(id: String, favorite: Boolean) {
        upload(Native.obj("setFlags", JSONObject().put("id", id).put("favorite", favorite).put("now", now())))
    }

    fun setArchived(id: String, archived: Boolean) {
        upload(Native.obj("setFlags", JSONObject().put("id", id).put("archived", archived).put("now", now())))
    }

    /** Moves an item to Recently Deleted, or back. */
    fun setTrashed(id: String, trashed: Boolean) {
        upload(Native.obj("setFlags", JSONObject().put("id", id).put("trashed", trashed).put("now", now())))
    }

    fun duplicate(id: String, title: String): String = upload(Native.obj("duplicate", JSONObject().put("id", id).put("title", title).put("now", now())))

    /** Deletes an item for good (from Recently Deleted). */
    fun deleteForGood(id: String) {
        upload(Native.obj("sealTombstone", JSONObject().put("id", id).put("now", now())))
    }

    /** A password for the generator's options. */
    fun generate(options: JSONObject): String = Native.obj("generate", options).getString("password")

    fun item(id: String): JSONObject = Native.obj("item", JSONObject().put("id", id))

    fun totp(uri: String): JSONObject = Native.obj("totp", JSONObject().put("uri", uri).put("now", System.currentTimeMillis() / 1000))

    /** Logins for an app or a website, best first. */
    fun matches(domain: String?, packageName: String?): List<Summary> {
        val args = JSONObject()
        if (domain != null) args.put("domain", domain)
        if (packageName != null) args.put("packageName", packageName)
        val list = Native.arr("match", args)
        return (0 until list.length()).map { i ->
            val row = list.getJSONObject(i)
            Summary(row.getString("id"), row.getString("vaultId"), row.getJSONObject("overview"))
        }
    }

    /**
     * Saves a login typed in another app or a website (autofill): a new one,
     * or a new password for the one with that username there.
     */
    fun saveLogin(domain: String?, packageName: String?, title: String, username: String, password: String) {
        val url = if (domain != null) "https://$domain" else "android://$packageName"
        val args = JSONObject().put("username", username)
        if (domain != null) args.put("domain", domain) else args.put("packageName", packageName)
        val existing = Native.run("findLogin", args) as? String
        val seal = JSONObject().put("url", url).put("title", title).put("username", username).put("password", password).put("now", now())
        if (existing != null) seal.put("id", existing)
        // Null: the same password is already there.
        val sealed = Native.run("sealLogin", seal) as? JSONObject ?: return
        upload(sealed)
    }

    /** The passkeys kept for `rpId` (only `allow` when the site names some). */
    fun passkeysFor(rpId: String, allow: List<String>): List<JSONObject> {
        val list = Native.arr("passkeysFor", JSONObject().put("rpId", rpId).put("allowCredentials", JSONArray(allow)))
        return (0 until list.length()).map { list.getJSONObject(it) }
    }

    /** A new passkey, kept in the site's login (uploaded before the site gets it). */
    fun createPasskey(args: JSONObject): JSONObject {
        val made = Native.obj("passkeyNew", args.put("now", now()))
        upload(made.getJSONObject("item"))
        return made
    }

    /** A login waiting for Keyless to unlock before it is saved (autofill). */
    class PendingSave(val domain: String?, val packageName: String?, val title: String, val username: String, val password: String)

    @Volatile var pendingSave: PendingSave? = null

    /** Removes the account and its data from this phone. */
    fun signOut() {
        session?.let { current ->
            // This phone leaves the account's list of devices.
            deviceId()?.let { id -> devicesCall { Server.rpc("remove_device", JSONObject().put("p_id", id), current.accessToken) } }
            Server.signOut(current.accessToken)
        }
        forgetHere()
    }

    /** Removes the account's data from this phone, without the server. */
    private fun forgetHere() {
        session = null
        seenAt = 0L
        prefs().edit().remove("device_id").remove("device_user").apply()
        Native.run("forget")
        clearCache()
        snapshotFile().delete()
        SentinelData.forget(app)
        SecureStore.clear(app)
    }

    // ----- this phone in the account's devices ---------------------------------

    private var seenAt = 0L
    private var statusCheckedAt = 0L

    /** The server has no devices functions: not asked again until the app restarts. */
    @Volatile private var devicesUnsupported = false

    private fun <T> devicesCall(block: () -> T): T? {
        if (devicesUnsupported) return null
        return try {
            block()
        } catch (e: KeylessException) {
            if (e.key == "missing_function") {
                devicesUnsupported = true
                null
            } else {
                throw e
            }
        }
    }

    fun deviceId(): String? = prefs().getString("device_id", null)

    /** This phone's id and secret for the account, made the first time. */
    private fun deviceIdentity(): Pair<String, String> {
        val userId = status().optString("userId")
        val id = deviceId()
        val secret = SecureStore.get(app, "device_secret")
        if (id != null && secret != null && prefs().getString("device_user", null) == userId) return id to secret
        val newId = java.util.UUID.randomUUID().toString()
        val newSecret = android.util.Base64.encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
        SecureStore.put(app, "device_secret", newSecret)
        prefs().edit().putString("device_id", newId).putString("device_user", userId).apply()
        return newId to newSecret
    }

    private fun deviceName(): String =
        Settings.Global.getString(app.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() } ?: "${Build.MANUFACTURER} ${Build.MODEL}"

    /** Puts this phone in the account's list (after signing in, or when the server does not know it). */
    private fun registerDevice(access: String) {
        if (devicesUnsupported || !status().optBoolean("unlocked")) return
        val (id, secret) = deviceIdentity()
        val version = try {
            app.packageManager.getPackageInfo(app.packageName, 0).versionName ?: ""
        } catch (e: Exception) {
            ""
        }
        val info = Native.run(
            "deviceInfo",
            JSONObject().put("deviceId", id).put("name", deviceName()).put("platform", "android").put("os", "Android ${Build.VERSION.RELEASE}").put("appVersion", version),
        ) as String
        devicesCall { Server.rpc("register_device", JSONObject().put("p_id", id).put("p_secret", secret).put("p_enc_info", info), access) }
    }

    /** Every few minutes: tells the server this phone is in use. */
    private fun deviceSeen(access: String) {
        val now = SystemClock.elapsedRealtime()
        if (devicesUnsupported || (seenAt != 0L && now - seenAt < 5 * 60_000L)) return
        seenAt = now
        try {
            val id = deviceId() ?: return registerDevice(access)
            val answer = devicesCall { Server.rpc("device_seen", JSONObject().put("p_id", id), access) } ?: return
            if (answer.trim().trim('"') != "active") registerDevice(access)
        } catch (e: KeylessException) {
            // Next time.
        }
    }

    /**
     * The server refused this phone's session: when it was signed out from
     * another device, removes the account's data here too.
     */
    private fun checkRevoked(): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (devicesUnsupported || (statusCheckedAt != 0L && now - statusCheckedAt < 60_000L)) return false
        statusCheckedAt = now
        val id = deviceId() ?: return false
        val secret = SecureStore.get(app, "device_secret") ?: return false
        val answer = try {
            devicesCall { Server.rpc("device_status", JSONObject().put("p_id", id).put("p_secret", secret)) }
        } catch (e: KeylessException) {
            null
        } ?: return false
        if (answer.trim().trim('"') != "revoked") return false
        Native.run("lock")
        forgetHere()
        return true
    }

    /** The account's devices, this phone first (with "current"). */
    fun devices(): List<JSONObject> {
        val access = token()
        fun fetch() = JSONArray(devicesCall { Server.devices(access) } ?: throw KeylessException("devices_unavailable"))
        var rows = fetch()
        val current = deviceId()
        if (current == null || (0 until rows.length()).none { rows.getJSONObject(it).optString("id") == current }) {
            registerDevice(access)
            rows = fetch()
        }
        val list = Native.arr("deviceList", rows)
        val id = deviceId()
        return (0 until list.length()).map { list.getJSONObject(it).put("current", list.getJSONObject(it).optString("id") == id) }.sortedBy { if (it.optBoolean("current")) 0 else 1 }
    }

    /** Signs another device out: its session ends at once. */
    fun revokeDevice(id: String) {
        devicesCall { Server.rpc("revoke_device", JSONObject().put("p_id", id), token()) }
    }

    // ----- approving another device's sign-in ------------------------------------

    /** New devices waiting for this account (`pending_device_setups`). */
    fun pendingDeviceSetups(): List<JSONObject> {
        val text = devicesCall { Server.rpc("pending_device_setups", JSONObject(), token()) } ?: return emptyList()
        val list = JSONArray(text)
        return (0 until list.length()).map { list.getJSONObject(it) }
    }

    /** Takes a request on this phone; false when another device took it. */
    fun answerDeviceSetup(request: JSONObject): Boolean {
        val id = request.getString("id")
        val answer = Native.obj("approvalStart", JSONObject().put("id", id).put("publicKey", request.getString("public_key")).put("commitment", request.getString("commitment")))
        val taken = Server.rpc("answer_device_setup", JSONObject().put("p_id", id).put("p_public_key", answer.getString("publicKey")).put("p_nonce", answer.getString("nonce")), token()).trim() == "true"
        if (!taken) Native.run("approvalForget", JSONObject().put("id", id))
        return taken
    }

    /** Sends the email and Secret Key to the new device, when `code` is the one it shows. */
    fun approveDeviceSetup(id: String, nonce: String, code: String) {
        val secretKey = SecureStore.get(app, "secret_key") ?: throw KeylessException("secret_key_invalid")
        val envelope = try {
            Native.run("approvalSeal", JSONObject().put("id", id).put("nonce", nonce).put("code", code.filter { it.isDigit() }).put("secretKey", secretKey)) as String
        } catch (e: KeylessException) {
            // Too many wrong codes: whoever asked is not in front of this phone.
            if (e.key == "device_setup_code_denied") denyDeviceSetup(id)
            throw e
        }
        val approved = Server.rpc("approve_device_setup", JSONObject().put("p_id", id).put("p_enc_payload", envelope), token()).trim() == "true"
        if (!approved) throw KeylessException("device_setup_expired")
    }

    fun denyDeviceSetup(id: String) {
        Native.run("approvalForget", JSONObject().put("id", id))
        Server.rpc("deny_device_setup", JSONObject().put("p_id", id), token())
    }

    // ----- signing in with another device -------------------------------------

    class DeviceRequest(val id: String, val secret: String)

    fun requestDeviceSetup(email: String): DeviceRequest {
        val started = Native.obj("setupStart")
        val id = java.util.UUID.randomUUID().toString()
        val secret = android.util.Base64.encodeToString(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
        val answer = JSONObject(
            try {
                Server.rpc(
                    "request_device_setup",
                    JSONObject().put("p_email", email).put("p_id", id).put("p_secret", secret).put("p_public_key", started.getString("publicKey"))
                        .put("p_commitment", started.getString("commitment")).put("p_platform", "android"),
                )
            } catch (e: KeylessException) {
                throw if (e.key == "missing_function") KeylessException("device_setup_unavailable") else e
            },
        )
        if (answer.has("error")) throw KeylessException(answer.getString("error"))
        return DeviceRequest(id, secret)
    }

    /** Where the request is: "waiting", "code" (with the code), "approved" (with email and Secret Key), "denied" or "expired". */
    fun pollDeviceSetup(request: DeviceRequest, revealed: BooleanArray): JSONObject {
        val state = JSONObject(Server.rpc("device_setup_status", JSONObject().put("p_id", request.id).put("p_secret", request.secret)))
        return when (val status = state.optString("status")) {
            "answered", "revealed" -> {
                val shown = Native.obj("setupCode", JSONObject().put("approverKey", state.getString("approver_key")).put("approverNonce", state.getString("approver_nonce")))
                if (!revealed[0]) {
                    Server.rpc("reveal_device_setup", JSONObject().put("p_id", request.id).put("p_secret", request.secret).put("p_nonce", shown.getString("nonce")))
                    revealed[0] = true
                }
                JSONObject().put("status", "code").put("code", shown.getString("code"))
            }
            "approved" -> {
                val opened = Native.obj(
                    "setupOpen",
                    JSONObject().put("requestId", request.id).put("approverKey", state.getString("approver_key"))
                        .put("approverNonce", state.getString("approver_nonce")).put("payload", state.getString("payload")),
                )
                JSONObject().put("status", "approved").put("email", opened.getString("email")).put("secretKey", opened.getString("secretKey"))
            }
            "pending" -> JSONObject().put("status", "waiting")
            "denied" -> JSONObject().put("status", "denied")
            else -> JSONObject().put("status", if (status.isEmpty()) "expired" else "expired")
        }
    }

    fun cancelDeviceSetup(request: DeviceRequest) {
        try {
            Server.rpc("cancel_device_setup", JSONObject().put("p_id", request.id).put("p_secret", request.secret))
        } catch (e: KeylessException) {
            // Gone already.
        }
    }
}
