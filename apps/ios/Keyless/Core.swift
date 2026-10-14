import Foundation
import LocalAuthentication
import Security

/// An error from the client or the server, with a key the app translates.
struct KeylessError: Error, LocalizedError {
    let key: String
    let message: String

    var errorDescription: String? { Texts.error(key, message) }
}

/// The Keyless client in Rust (crates/keyless-ios): keys, checks and
/// decryption. One function, JSON in and out.
enum Native {
    static func call(_ method: String, _ args: Any? = nil) throws -> Any? {
        var text = ""
        if let args {
            if let string = args as? String {
                text = string
            } else {
                let data = try JSONSerialization.data(withJSONObject: args, options: [.fragmentsAllowed])
                text = String(decoding: data, as: UTF8.self)
            }
        }
        guard let raw = keyless_call(method, text) else { throw KeylessError(key: "internal", message: "no answer") }
        defer { keyless_free(raw) }
        let answer = String(cString: raw)
        let json = (try JSONSerialization.jsonObject(with: Data(answer.utf8), options: [.fragmentsAllowed]) as? [String: Any]) ?? [:]
        if let error = json["error"] as? [String: Any] {
            throw KeylessError(key: error["key"] as? String ?? "internal", message: error["message"] as? String ?? "")
        }
        let ok = json["ok"]
        return ok is NSNull ? nil : ok
    }

    static func object(_ method: String, _ args: Any? = nil) throws -> [String: Any] {
        (try call(method, args) as? [String: Any]) ?? [:]
    }

    static func array(_ method: String, _ args: Any? = nil) throws -> [[String: Any]] {
        ((try call(method, args) as? [Any]) ?? []).compactMap { $0 as? [String: Any] }
    }
}

/// The server session.
struct Session {
    var accessToken: String
    var refreshToken: String
    var expiresAt: Double
    var userId: String
}

/// The Keyless server (Supabase Auth and the Data API), as the desktop app
/// uses it. What is sent is ciphertext, a proof or the derived sign-in secret.
enum Server {
    static let base = "https://ednfhgbjtgkrmtnudcjr.supabase.co"
    static let key = "sb_publishable_3SSYrJqgt-zB30WaRHnuSw_YN7WaHqD"

    static func request(_ path: String, method: String = "GET", body: Any? = nil, token: String? = nil, headers: [String: String] = [:]) async throws -> Data {
        guard let url = URL(string: "\(base)/\(path)") else { throw KeylessError(key: "internal", message: path) }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(key, forHTTPHeaderField: "apikey")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw KeylessError(key: "offline", message: error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else { throw mapError(status, data) }
        return data
    }

    private static func mapError(_ status: Int, _ data: Data) -> KeylessError {
        let body = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
        let code = (body["error_code"] as? String) ?? (body["code"] as? String) ?? (body["error"] as? String) ?? ""
        let message = (body["msg"] as? String) ?? (body["message"] as? String) ?? (body["error_description"] as? String) ?? "HTTP \(status)"
        if code == "invalid_credentials" || code == "invalid_grant" { return KeylessError(key: "invalid_credentials", message: message) }
        if code == "email_not_confirmed" { return KeylessError(key: "email_not_confirmed", message: message) }
        if status == 429 || code.hasPrefix("over_") { return KeylessError(key: "too_many_attempts", message: message) }
        if code == "PGRST202" || code == "PGRST205" { return KeylessError(key: "missing_function", message: message) }
        if status == 401 || status == 403 { return KeylessError(key: "session_expired", message: message) }
        return KeylessError(key: "unknown", message: "\(message) (\(code))")
    }

    private static func session(_ data: Data) throws -> Session {
        guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = raw["access_token"] as? String,
              let refresh = raw["refresh_token"] as? String,
              let user = raw["user"] as? [String: Any],
              let userId = user["id"] as? String
        else { throw KeylessError(key: "unknown", message: "bad session") }
        let now = Date().timeIntervalSince1970
        let expiresAt = (raw["expires_at"] as? Double) ?? (now + ((raw["expires_in"] as? Double) ?? 3600))
        return Session(accessToken: access, refreshToken: refresh, expiresAt: expiresAt, userId: userId)
    }

    static func signIn(email: String, authSecret: String) async throws -> Session {
        try session(await request("auth/v1/token?grant_type=password", method: "POST", body: ["email": email, "password": authSecret]))
    }

    static func refresh(_ refreshToken: String) async throws -> Session {
        try session(await request("auth/v1/token?grant_type=refresh_token", method: "POST", body: ["refresh_token": refreshToken]))
    }

    static func signOut(_ token: String) async {
        _ = try? await request("auth/v1/logout?scope=local", method: "POST", body: [String: Any](), token: token)
    }

    private static func encoded(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) ?? value
    }

    static func profile(token: String, userId: String) async throws -> Any {
        let data = try await request("rest/v1/profiles?user_id=eq.\(encoded(userId))&select=format,kdf,enc_user_key,public_key,enc_private_key,pending_kdf,pending_enc_user_key", token: token)
        let rows = (try JSONSerialization.jsonObject(with: data) as? [Any]) ?? []
        return rows.first ?? NSNull()
    }

    static func memberships(token: String, userId: String) async throws -> String {
        let data = try await request("rest/v1/vault_members?user_id=eq.\(encoded(userId))&select=vault_id,role,enc_vault_key,vaults(owner_id,enc_meta,seq,deleted_at,enc_tombstone)", token: token)
        return String(decoding: data, as: UTF8.self)
    }

    static func itemsSince(token: String, vaultId: String, cursor: Int, limit: Int) async throws -> [Any] {
        let data = try await request("rest/v1/items?select=*&vault_id=eq.\(encoded(vaultId))&seq=gt.\(cursor)&order=seq.asc&limit=\(limit)", token: token)
        return (try JSONSerialization.jsonObject(with: data) as? [Any]) ?? []
    }

    static func rpc(_ name: String, _ args: [String: Any], token: String? = nil) async throws -> Any {
        let data = try await request("rest/v1/rpc/\(name)", method: "POST", body: args, token: token)
        return (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) ?? NSNull()
    }
}

/// Secrets in the Keychain: the Secret Key and refresh token (this device
/// only, while unlocked), and for Face ID the user key, behind the current
/// biometrics.
enum Secure {
    private static let service = "io.github.diegocastroalves.keyless"

    private static func query(_ name: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name]
    }

    static func set(_ name: String, _ value: String?) {
        SecItemDelete(query(name) as CFDictionary)
        guard let value else { return }
        var add = query(name)
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    static func get(_ name: String) -> String? {
        var search = query(name)
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(search as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static var biometricEnabled: Bool { UserDefaults.standard.bool(forKey: "biometric") }

    static func setBiometric(_ userKey: String?) {
        let name = "biometric_user_key"
        SecItemDelete(query(name) as CFDictionary)
        UserDefaults.standard.set(false, forKey: "biometric")
        guard let userKey,
              let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil)
        else { return }
        var add = query(name)
        add[kSecValueData as String] = Data(userKey.utf8)
        add[kSecAttrAccessControl as String] = control
        if SecItemAdd(add as CFDictionary, nil) == errSecSuccess {
            UserDefaults.standard.set(true, forKey: "biometric")
        }
    }

    /// The user key, after Face ID or Touch ID (nil when refused or changed).
    static func biometricUserKey(reason: String) -> String? {
        let context = LAContext()
        context.localizedReason = reason
        var search = query("biometric_user_key")
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        search[kSecUseAuthenticationContext as String] = context
        var out: AnyObject?
        let status = SecItemCopyMatching(search as CFDictionary, &out)
        if status == errSecItemNotFound { UserDefaults.standard.set(false, forKey: "biometric") }
        guard status == errSecSuccess, let data = out as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static func clear() {
        for name in ["secret_key", "refresh_token", "biometric_user_key"] { SecItemDelete(query(name) as CFDictionary) }
        UserDefaults.standard.set(false, forKey: "biometric")
    }
}
