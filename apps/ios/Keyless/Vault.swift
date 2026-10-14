import Foundation
import SwiftUI

/// An item in lists: its id, vault and overview (title, username, websites...).
struct Item: Identifiable {
    let id: String
    let vaultId: String
    let overview: [String: Any]

    var title: String { overview["title"] as? String ?? "" }
    var subtitle: String { overview["subtitle"] as? String ?? "" }
    var category: String { overview["category"] as? String ?? "" }
    var favorite: Bool { overview["favorite"] as? Bool ?? false }
    var urls: [String] { (overview["urls"] as? [[String: Any]] ?? []).compactMap { $0["href"] as? String } }
}

/// The account on this device: what is kept (the server's ciphertext in a
/// file; the Secret Key and refresh token in the Keychain), the session, and
/// the client's unlocked state with its automatic lock.
@MainActor
final class Vault: ObservableObject {
    enum Phase { case signedOut, locked, unlocked }

    @Published var phase: Phase = .signedOut
    @Published var items: [Item] = []
    @Published var syncing = false
    @Published var syncError: String?
    /// The email and Secret Key a setup link gave.
    @Published var received: (email: String, secretKey: String)?

    private var session: Session?
    private var lastActivity = Date()
    private let page = 500

    var autoLockMinutes: Int {
        get { UserDefaults.standard.object(forKey: "auto_lock_minutes") as? Int ?? 5 }
        set { UserDefaults.standard.set(newValue, forKey: "auto_lock_minutes") }
    }

    private var file: URL {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("vault.json")
    }

    init() {
        let text = (try? String(contentsOf: file, encoding: .utf8)) ?? ""
        if (try? Native.call("load", text)) == nil { _ = try? Native.call("load", "") }
        phase = hasAccount ? .locked : .signedOut
    }

    var status: [String: Any] { (try? Native.object("status")) ?? [:] }
    var hasAccount: Bool { status["account"] as? Bool ?? false }
    var email: String { status["email"] as? String ?? "" }

    func touch() { lastActivity = Date() }

    /// Locks when unused for too long (called as the app comes back).
    func checkAutoLock() {
        if phase == .unlocked && Date().timeIntervalSince(lastActivity) > Double(autoLockMinutes * 60) { lock() }
    }

    func lock() {
        _ = try? Native.call("lock")
        items = []
        phase = hasAccount ? .locked : .signedOut
    }

    private func save() {
        guard let snapshot = try? Native.call("snapshot"),
              let data = try? JSONSerialization.data(withJSONObject: snapshot)
        else { return }
        try? data.write(to: file, options: [.atomic, .completeFileProtection])
    }

    /// Key derivation takes a while: off the main thread.
    private func background<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    continuation.resume(returning: try work())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func signIn(email: String, secretKey: String, masterPassword: String) async throws {
        let address = email.trimmingCharacters(in: .whitespaces).lowercased()
        let derived = try await background { try Native.object("derive", ["email": address, "masterPassword": masterPassword, "secretKey": secretKey]) }
        guard let authSecret = derived["authSecret"] as? String else { throw KeylessError(key: "internal", message: "no secret") }
        let signed = try await Server.signIn(email: address, authSecret: authSecret)
        let profile = try await Server.profile(token: signed.accessToken, userId: signed.userId)
        _ = try Native.call("signedIn", ["userId": signed.userId, "profile": profile])
        session = signed
        Secure.set("secret_key", secretKey.trimmingCharacters(in: .whitespaces).uppercased())
        Secure.set("refresh_token", signed.refreshToken)
        Secure.setBiometric(nil)
        received = nil
        touch()
        save()
        phase = .unlocked
        try await sync()
    }

    func unlock(masterPassword: String) async throws {
        guard let secretKey = Secure.get("secret_key") else { throw KeylessError(key: "secret_key_invalid", message: "") }
        let address = email
        _ = try await background { try Native.call("unlock", ["email": address, "masterPassword": masterPassword, "secretKey": secretKey]) }
        touch()
        refresh()
        phase = .unlocked
    }

    func unlockWithBiometrics(reason: String) async throws {
        let userKey = try await background { Secure.biometricUserKey(reason: reason) }
        guard let userKey else { return }
        _ = try Native.call("unlockWithUserKey", ["userKey": userKey])
        touch()
        refresh()
        phase = .unlocked
    }

    func setBiometrics(_ on: Bool) {
        if on, let key = try? Native.call("exportUserKey") as? String {
            Secure.setBiometric(key)
        } else {
            Secure.setBiometric(nil)
        }
        objectWillChange.send()
    }

    private func token() async throws -> String {
        if let current = session, current.expiresAt - 60 > Date().timeIntervalSince1970 { return current.accessToken }
        guard let refresh = session?.refreshToken ?? Secure.get("refresh_token") else { throw KeylessError(key: "session_expired", message: "") }
        let renewed = try await Server.refresh(refresh)
        session = renewed
        Secure.set("refresh_token", renewed.refreshToken)
        return renewed.accessToken
    }

    /// Pulls the vaults and the items that changed, checked by the client.
    func sync() async throws {
        syncing = true
        defer { syncing = false }
        let access = try await token()
        let userId = status["userId"] as? String ?? ""
        let memberships = try await Server.memberships(token: access, userId: userId)
        _ = try Native.call("applyMemberships", memberships)
        for vault in try Native.array("vaults") {
            guard let vaultId = vault["id"] as? String else { continue }
            while true {
                let cursor = (try Native.call("cursor", ["vaultId": vaultId]) as? Int) ?? 0
                let rows = try await Server.itemsSince(token: access, vaultId: vaultId, cursor: cursor, limit: page)
                _ = try Native.call("applyItems", ["vaultId": vaultId, "items": rows])
                if rows.count < page { break }
            }
        }
        save()
        refresh()
    }

    func refresh() {
        let list = (try? Native.array("items")) ?? []
        items = list.compactMap { row in
            guard let id = row["id"] as? String, let vaultId = row["vaultId"] as? String, let overview = row["overview"] as? [String: Any] else { return nil }
            if let trashed = overview["trashed_at"], !(trashed is NSNull) { return nil }
            if overview["archived"] as? Bool == true { return nil }
            return Item(id: id, vaultId: vaultId, overview: overview)
        }
        .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    func item(_ id: String) throws -> [String: Any] { try Native.object("item", ["id": id]) }

    func totp(_ uri: String) -> (code: String, remaining: Int)? {
        guard let answer = try? Native.object("totp", ["uri": uri, "now": Int(Date().timeIntervalSince1970)]),
              let code = answer["code"] as? String
        else { return nil }
        return (code, answer["remaining"] as? Int ?? 0)
    }

    /// A keyless://setup link fills the sign-in form.
    func receive(link: String) throws {
        let parsed = try Native.object("parseSetupLink", ["text": link])
        if let email = parsed["email"] as? String, let key = parsed["secretKey"] as? String { received = (email, key) }
    }

    func signOut() async {
        if let current = session { await Server.signOut(current.accessToken) }
        session = nil
        _ = try? Native.call("forget")
        try? FileManager.default.removeItem(at: file)
        Secure.clear()
        items = []
        phase = .signedOut
    }
}
