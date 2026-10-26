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
    var archived: Bool { overview["archived"] as? Bool ?? false }
    /// In Recently Deleted.
    var trashed: Bool {
        guard let at = overview["trashed_at"] else { return false }
        return !(at is NSNull)
    }
    var urls: [String] { (overview["urls"] as? [[String: Any]] ?? []).compactMap { $0["href"] as? String } }

    /// The Android app an address names (android://<package>,
    /// androidapp://<package>, Chrome's android://<hash>@<package>), or nil.
    static func appOf(_ href: String) -> String? {
        let text = href.trimmingCharacters(in: .whitespaces)
        for scheme in ["android://", "androidapp://"] where text.lowercased().hasPrefix(scheme) {
            let name = text.dropFirst(scheme.count).split(separator: "@", omittingEmptySubsequences: false).last ?? ""
            let package = name.split(whereSeparator: { "/?#".contains($0) }).first.map(String.init) ?? ""
            return package.isEmpty ? nil : package
        }
        return nil
    }
}

/// The account on this device: what is kept (the server's ciphertext in a
/// file; the Secret Key and refresh token in the Keychain), the session, and
/// the client's unlocked state with its automatic lock.
@MainActor
final class Vault: ObservableObject {
    enum Phase { case signedOut, locked, unlocked }

    @Published var phase: Phase = .signedOut
    /// Every item, archived and in Recently Deleted too.
    @Published var all: [Item] = []
    @Published var syncing = false
    @Published var syncError: String?
    /// The email and Secret Key a setup link gave.
    @Published var received: (email: String, secretKey: String)?

    private var session: Session?
    private var lastActivity = Date()
    private let page = 500
    /// When the last sync finished; nil until one has since unlocking.
    private var syncedAt: Date?
    /// The sync signals and the periodic sync, while the app is open and unlocked.
    private let realtime = Realtime()
    private var ticker: Timer?
    private var syncRequested = false

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

    /// The items in use (not archived, not in Recently Deleted).
    var items: [Item] { all.filter { !$0.archived && !$0.trashed } }
    var archivedItems: [Item] { all.filter { $0.archived && !$0.trashed } }
    var trashedItems: [Item] { all.filter(\.trashed) }

    func lock() {
        stopLive()
        _ = try? Native.call("lock")
        all = []
        syncedAt = nil
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
        startLive()
    }

    func unlock(masterPassword: String) async throws {
        guard let secretKey = Secure.get("secret_key") else { throw KeylessError(key: "secret_key_invalid", message: "") }
        let address = email
        _ = try await background { try Native.call("unlock", ["email": address, "masterPassword": masterPassword, "secretKey": secretKey]) }
        touch()
        refresh()
        phase = .unlocked
        startLive()
        Task { await syncIfStale(30) }
    }

    func unlockWithBiometrics(reason: String) async throws {
        let userKey = try await background { Secure.biometricUserKey(reason: reason) }
        guard let userKey else { return }
        _ = try Native.call("unlockWithUserKey", ["userKey": userKey])
        touch()
        refresh()
        phase = .unlocked
        startLive()
        Task { await syncIfStale(30) }
    }

    func setBiometrics(_ on: Bool) {
        if on, let key = try? Native.call("exportUserKey") as? String {
            Secure.setBiometric(key)
        } else {
            Secure.setBiometric(nil)
        }
        objectWillChange.send()
    }

    /// The session's access token, refreshed when it is about to expire.
    func token() async throws -> String {
        if let current = session, current.expiresAt - 60 > Date().timeIntervalSince1970 { return current.accessToken }
        guard let refresh = session?.refreshToken ?? Secure.get("refresh_token") else { throw KeylessError(key: "session_expired", message: "") }
        let renewed = try await Server.refresh(refresh)
        session = renewed
        Secure.set("refresh_token", renewed.refreshToken)
        return renewed.accessToken
    }

    /// Pulls the vaults and the items that changed, checked by the client;
    /// answers whether anything changed.
    @discardableResult
    func sync() async throws -> Bool {
        syncing = true
        defer { syncing = false }
        let access = try await token()
        let userId = status["userId"] as? String ?? ""
        // Once: every item again, for those an older version skipped (its own
        // writes moved the cursor past items not pulled yet).
        let repull = !UserDefaults.standard.bool(forKey: "cursors_reset")
        if repull { _ = try Native.call("resetCursors") }
        let memberships = try await Server.memberships(token: access, userId: userId)
        var changed = try Native.object("applyMemberships", memberships)["changed"] as? Bool ?? false
        for vault in try Native.array("vaults") {
            guard let vaultId = vault["id"] as? String else { continue }
            while true {
                let cursor = (try Native.call("cursor", ["vaultId": vaultId]) as? Int) ?? 0
                let rows = try await Server.itemsSince(token: access, vaultId: vaultId, cursor: cursor, limit: page)
                if (try Native.object("applyItems", ["vaultId": vaultId, "items": rows])["changed"] as? Int ?? 0) > 0 { changed = true }
                if rows.count < page { break }
            }
        }
        save()
        if repull { UserDefaults.standard.set(true, forKey: "cursors_reset") }
        refresh()
        syncedAt = Date()
        return changed
    }

    /// Syncs, without a word, unless one is under way or the last finished
    /// less than `maxAge` seconds ago.
    func syncIfStale(_ maxAge: TimeInterval) async {
        guard phase == .unlocked, !syncing else { return }
        if let syncedAt, Date().timeIntervalSince(syncedAt) < maxAge { return }
        do {
            try await sync()
            syncError = nil
        } catch {
            // Offline or signed out: the next one, or the user's.
        }
    }

    /// The sync signals (Realtime.swift) and a sync every minute, or every 5
    /// while signals arrive: while the app is open and unlocked.
    func startLive() {
        guard phase == .unlocked else { return }
        realtime.start(vault: self)
        if ticker == nil {
            ticker = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    await self.syncIfStale(self.realtime.listening ? 290 : 55)
                }
            }
        }
    }

    func stopLive() {
        realtime.stop()
        ticker?.invalidate()
        ticker = nil
    }

    /// A sync signal (or a join: changes made meanwhile): one sync for signals close together.
    func signalled() {
        guard !syncRequested else { return }
        syncRequested = true
        Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            syncRequested = false
            await syncIfStale(0)
        }
    }

    func refresh() {
        let list = (try? Native.array("items")) ?? []
        all = list.compactMap { row in
            guard let id = row["id"] as? String, let vaultId = row["vaultId"] as? String, let overview = row["overview"] as? [String: Any] else { return nil }
            return Item(id: id, vaultId: vaultId, overview: overview)
        }
        .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    /// Items of this vault can be changed here (not a vault shared to read only).
    func canWrite(_ vaultId: String) -> Bool {
        ((try? Native.array("vaults")) ?? []).contains { $0["id"] as? String == vaultId && $0["canWrite"] as? Bool == true }
    }

    private var now: Int { Int(Date().timeIntervalSince1970) }

    /// Uploads a write (`setFlags`, `sealTombstone`, `passkeyRemove`...) and
    /// keeps what the server answers. When the item changed meanwhile, the
    /// desktop's rules settle it (`planConflict`), as on Android: the most
    /// recent edit wins, the other is kept as a conflicted copy.
    private func upload(_ sealed: [String: Any]) async throws {
        guard let id = sealed["id"] as? String, let vaultId = sealed["vaultId"] as? String else {
            throw KeylessError(key: "internal", message: "bad write")
        }
        touch()
        let access = try await token()
        let base = sealed["baseRevision"] as? Int
        var rows: [Any]
        if let tombstone = sealed["encTombstone"] as? String, let base {
            rows = try await Server.patchItem(token: access, id: id, baseRevision: base, body: ["enc_tombstone": tombstone])
        } else if let base {
            let body: [String: Any] = ["enc_overview": sealed["encOverview"] as? String ?? "", "enc_details": sealed["encDetails"] as? String ?? ""]
            rows = try await Server.patchItem(token: access, id: id, baseRevision: base, body: body)
        } else {
            rows = try await Server.insertItem(token: access, id: id, vaultId: vaultId, encOverview: sealed["encOverview"] as? String ?? "", encDetails: sealed["encDetails"] as? String ?? "")
        }
        var attempts = 0
        while rows.isEmpty && attempts < 3 {
            attempts += 1
            guard let remote = try await Server.item(token: access, id: id) else { break }
            var conflict = sealed
            conflict["remote"] = remote
            let plan = try Native.object("planConflict", conflict)
            if let copy = plan["copy"] as? [String: Any], let copyId = copy["id"] as? String {
                let copyVault = copy["vaultId"] as? String ?? vaultId
                let copied = try await Server.insertItem(token: access, id: copyId, vaultId: copyVault, encOverview: copy["encOverview"] as? String ?? "", encDetails: copy["encDetails"] as? String ?? "")
                _ = try Native.call("applyItems", ["vaultId": copyVault, "items": copied, "pushed": true])
            }
            if plan["plan"] as? String == "overwrite", let revision = remote["revision"] as? Int, let body = plan["body"] as? [String: Any] {
                rows = try await Server.patchItem(token: access, id: id, baseRevision: revision, body: body)
            } else {
                rows = [remote]
            }
        }
        if rows.isEmpty { throw KeylessError(key: "save_conflict", message: "") }
        _ = try Native.call("applyItems", ["vaultId": vaultId, "items": rows, "pushed": true])
        save()
        refresh()
    }

    func setFavorite(_ id: String, _ favorite: Bool) async throws {
        try await upload(Native.object("setFlags", ["id": id, "favorite": favorite, "now": now]))
    }

    func setArchived(_ id: String, _ archived: Bool) async throws {
        try await upload(Native.object("setFlags", ["id": id, "archived": archived, "now": now]))
    }

    /// Moves an item to Recently Deleted, or back.
    func setTrashed(_ id: String, _ trashed: Bool) async throws {
        try await upload(Native.object("setFlags", ["id": id, "trashed": trashed, "now": now]))
    }

    /// Deletes an item for good (from Recently Deleted).
    func deleteForGood(_ id: String) async throws {
        try await upload(Native.object("sealTombstone", ["id": id, "now": now]))
    }

    /// Removes one of an item's passkeys: the site then asks for another way
    /// to sign in.
    func removePasskey(_ id: String, credentialId: String) async throws {
        try await upload(Native.object("passkeyRemove", ["itemId": id, "credentialId": credentialId, "now": now]))
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
        stopLive()
        if let current = session { await Server.signOut(current.accessToken) }
        session = nil
        _ = try? Native.call("forget")
        try? FileManager.default.removeItem(at: file)
        Secure.clear()
        all = []
        phase = .signedOut
    }
}
