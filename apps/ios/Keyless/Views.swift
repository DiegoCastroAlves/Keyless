import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Copies with an expiry (the system clears it after 90 seconds), on this device only.
func copySecret(_ value: String) {
    UIPasteboard.general.setItems([[UTType.utf8PlainText.identifier: value]], options: [.expirationDate: Date().addingTimeInterval(90), .localOnly: true])
}

struct RootView: View {
    @EnvironmentObject var vault: Vault
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch vault.phase {
            case .signedOut: SignInView()
            case .locked: UnlockView()
            case .unlocked: ItemsView()
            }
        }
        .onOpenURL { url in try? vault.receive(link: url.absoluteString) }
        .onChange(of: scenePhase) { phase in
            if phase == .active { vault.checkAutoLock() }
            if phase == .background { vault.touch() }
        }
    }
}

struct SignInView: View {
    @EnvironmentObject var vault: Vault
    @State private var email = ""
    @State private var secretKey = ""
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(Texts.t("signInIntro")).font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    TextField(Texts.t("email"), text: $email)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if let received = vault.received {
                        HStack {
                            Label(Texts.t("keyReceived"), systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                            Spacer()
                            Button(Texts.t("typeKey")) { vault.received = nil }
                        }
                        .onAppear { email = received.email }
                    } else {
                        TextField("K1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX", text: $secretKey)
                            .font(.system(.body, design: .monospaced))
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                            .onChange(of: secretKey) { value in
                                if value.lowercased().hasPrefix("keyless://setup") {
                                    do { try vault.receive(link: value) } catch { self.error = error.localizedDescription }
                                    secretKey = ""
                                }
                            }
                    }
                } footer: {
                    if vault.received == nil { Text(Texts.t("secretKeyHint")) }
                }
                Section {
                    SecureField(Texts.t("masterPassword"), text: $password).textContentType(.password)
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
                Section {
                    Button {
                        Task { await signIn() }
                    } label: {
                        HStack {
                            Text(Texts.t("signIn"))
                            if busy { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(busy || email.isEmpty || password.isEmpty || (vault.received == nil && secretKey.isEmpty))
                }
            }
            .navigationTitle(Texts.t("signInTitle"))
        }
    }

    private func signIn() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await vault.signIn(email: email, secretKey: vault.received?.secretKey ?? secretKey, masterPassword: password)
            password = ""
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject var vault: Vault
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false
    @State private var confirmSignOut = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(vault.email).foregroundStyle(.secondary)
                    SecureField(Texts.t("masterPassword"), text: $password)
                        .textContentType(.password)
                        .onSubmit { Task { await unlock() } }
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
                Section {
                    Button(Texts.t("unlock")) { Task { await unlock() } }.disabled(busy || password.isEmpty)
                    if Secure.biometricEnabled {
                        Button(Texts.t("unlockBiometric")) { Task { await biometric() } }
                    }
                }
                Section {
                    Button(Texts.t("signOut"), role: .destructive) { confirmSignOut = true }
                }
            }
            .navigationTitle(Texts.t("lockedTitle"))
            .confirmationDialog(Texts.t("signOutBody"), isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button(Texts.t("signOut"), role: .destructive) { Task { await vault.signOut() } }
            }
            .task { if Secure.biometricEnabled { await biometric() } }
        }
    }

    private func unlock() async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            try await vault.unlock(masterPassword: password)
            password = ""
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func biometric() async {
        do {
            try await vault.unlockWithBiometrics(reason: Texts.t("biometricReason"))
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct ItemsView: View {
    @EnvironmentObject var vault: Vault
    @State private var query = ""
    @State private var filter = "all"
    @State private var showSettings = false

    /// What the filter lists from: the items in use, the Archive or
    /// Recently Deleted.
    private var source: [Item] {
        switch filter {
        case "archive": return vault.archivedItems
        case "trash": return vault.trashedItems
        default: return vault.items
        }
    }

    private var shown: [Item] {
        // Each word anywhere, case and accents aside (see Search.swift).
        let words = Search.words(query)
        return source.filter { item in
            if filter == "favorites" && !item.favorite { return false }
            if filter.hasPrefix("category:") && item.category != String(filter.dropFirst("category:".count)) { return false }
            return Search.has(words, in: [item.title, item.subtitle] + item.urls)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Picker("", selection: $filter) {
                    Text(Texts.t("allItems")).tag("all")
                    Text(Texts.t("favorites")).tag("favorites")
                    ForEach(Array(Set(vault.items.map(\.category))).sorted(), id: \.self) { category in
                        Text(Texts.categoryPlural(category)).tag("category:\(category)")
                    }
                    Text(Texts.t("archive")).tag("archive")
                    Text(Texts.t("recentlyDeleted")).tag("trash")
                }
                .pickerStyle(.menu)
                if let error = vault.syncError { Text(error).foregroundStyle(.red).font(.footnote) }
                if shown.isEmpty { Text(Texts.t("noItems")).foregroundStyle(.secondary) }
                ForEach(shown) { item in
                    NavigationLink {
                        ItemView(id: item.id)
                    } label: {
                        HStack(spacing: 12) {
                            Text(String(item.title.prefix(1)).uppercased())
                                .font(.headline)
                                .frame(width: 36, height: 36)
                                .background(Color.teal.opacity(0.15), in: RoundedRectangle(cornerRadius: 9))
                                .foregroundStyle(.teal)
                            VStack(alignment: .leading) {
                                Text(item.title).lineLimit(1)
                                if !item.subtitle.isEmpty { Text(item.subtitle).font(.footnote).foregroundStyle(.secondary).lineLimit(1) }
                            }
                            if item.favorite {
                                Spacer()
                                Image(systemName: "star.fill").font(.caption).foregroundStyle(.yellow)
                            }
                        }
                    }
                    // Held down: what can be copied or done without opening it (as Android's menu).
                    .contextMenu { ItemMenu(id: item.id) }
                }
            }
            .searchable(text: $query, prompt: Texts.t("search"))
            .refreshable { await sync() }
            .navigationTitle("Keyless")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button(Texts.t("lock")) { vault.lock() } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .task { if vault.items.isEmpty { await sync() } }
            .simultaneousGesture(TapGesture().onEnded { vault.touch() })
        }
    }

    private func sync() async {
        do {
            try await vault.sync()
            vault.syncError = nil
        } catch {
            vault.syncError = error.localizedDescription
        }
    }
}

/// An item held down in the list: its username, password or code to copy,
/// and what can be done with it (as Android's menu).
struct ItemMenu: View {
    let id: String
    @EnvironmentObject var vault: Vault

    var body: some View {
        let summary = vault.all.first { $0.id == id }
        let writable = summary.map { vault.canWrite($0.vaultId) } ?? false
        let fields = Self.fields((try? vault.item(id))?["details"] as? [String: Any] ?? [:])
        let username = fields.first(where: { $0["purpose"] as? String == "username" })?["value"] as? String ?? ""
        let password = fields.first(where: { $0["purpose"] as? String == "password" })?["value"] as? String ?? ""
        let totp = fields.first(where: { $0["kind"] as? String == "totp" })?["value"] as? String ?? ""
        if !username.isEmpty {
            Button { copy(username) } label: { Label(Texts.t("copyUsername"), systemImage: "person") }
        }
        if !password.isEmpty {
            Button { copy(password) } label: { Label(Texts.t("copyPassword"), systemImage: "key") }
        }
        if !totp.isEmpty {
            Button {
                if let code = vault.totp(totp) { copy(code.code) }
            } label: { Label(Texts.t("copyCode"), systemImage: "clock") }
        }
        if let summary, writable {
            Divider()
            ItemActions(item: summary, onDeleteForever: nil) { _, work in run(work) }
        }
    }

    private func copy(_ text: String) {
        copySecret(text)
        vault.touch()
    }

    private func run(_ work: @escaping () async throws -> Void) {
        Task {
            do {
                try await work()
                vault.syncError = nil
            } catch {
                vault.syncError = error.localizedDescription
            }
        }
    }

    /// The item's fields that have a value, in its sections too.
    static func fields(_ details: [String: Any]) -> [[String: Any]] {
        var all = details["fields"] as? [[String: Any]] ?? []
        for section in details["sections"] as? [[String: Any]] ?? [] {
            all += section["fields"] as? [[String: Any]] ?? []
        }
        return all.filter { !($0["value"] as? String ?? "").isEmpty }
    }
}

/// What can be done with an item, in its menus: favorite, archive, move to
/// Recently Deleted; from there, restore or delete permanently (when the
/// screen can ask first: `onDeleteForever`). `run` runs one, told whether
/// the item leaves the screen's list.
struct ItemActions: View {
    let item: Item
    let onDeleteForever: (() -> Void)?
    let run: (Bool, @escaping () async throws -> Void) -> Void
    @EnvironmentObject var vault: Vault

    var body: some View {
        let id = item.id
        if item.trashed {
            Button { run(false) { try await vault.setTrashed(id, false) } } label: {
                Label(Texts.t("restore"), systemImage: "arrow.uturn.backward")
            }
            if let onDeleteForever {
                Button(role: .destructive) { onDeleteForever() } label: {
                    Label(Texts.t("deleteForever"), systemImage: "trash.slash")
                }
            }
        } else {
            Button { run(false) { try await vault.setFavorite(id, !item.favorite) } } label: {
                Label(Texts.t(item.favorite ? "unfavorite" : "favorite"), systemImage: item.favorite ? "star.slash" : "star")
            }
            Button { run(false) { try await vault.setArchived(id, !item.archived) } } label: {
                Label(Texts.t(item.archived ? "unarchive" : "toArchive"), systemImage: item.archived ? "tray.and.arrow.up" : "archivebox")
            }
            Button(role: .destructive) { run(true) { try await vault.setTrashed(id, true) } } label: {
                Label(Texts.t("moveToTrash"), systemImage: "trash")
            }
        }
    }
}

/// One of an item's passkeys: the site and account, and a way to delete it.
struct PasskeyRow: View {
    let passkey: [String: Any]
    let itemId: String
    let removable: Bool
    let run: (@escaping () async throws -> Void) -> Void
    @EnvironmentObject var vault: Vault
    @State private var confirm = false

    var body: some View {
        let site = passkey["rpId"] as? String ?? ""
        let user = passkey["userName"] as? String ?? ""
        let created = passkey["createdAt"] as? Double ?? 0
        let credentialId = passkey["credentialId"] as? String ?? ""
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(user.isEmpty ? site : "\(site) · \(user)")
                if created > 0 {
                    Text(String(format: Texts.t("passkeyCreated"), Date(timeIntervalSince1970: created).formatted(date: .abbreviated, time: .omitted)))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if removable {
                Button(Texts.t("remove"), role: .destructive) { confirm = true }.buttonStyle(.borderless)
            }
        }
        .confirmationDialog(Texts.t("passkeyRemoveBody"), isPresented: $confirm, titleVisibility: .visible) {
            Button(Texts.t("remove"), role: .destructive) {
                run { try await vault.removePasskey(itemId, credentialId: credentialId) }
            }
        }
    }
}

struct FieldRow: View {
    let field: [String: Any]
    @EnvironmentObject var vault: Vault
    @State private var shown = false
    @State private var copied = false

    private var kind: String { field["kind"] as? String ?? "text" }
    private var value: String { field["value"] as? String ?? "" }
    private var secret: Bool { ["concealed", "pin", "card_number", "security_question"].contains(kind) }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(Texts.field(field["label"] as? String ?? "")).font(.caption).foregroundStyle(.secondary)
            HStack {
                if kind == "totp" {
                    TimelineView(.periodic(from: .now, by: 1)) { _ in
                        let code = vault.totp(value)
                        Text(code.map { "\($0.code)  ·  \($0.remaining)s" } ?? "—").font(.system(.body, design: .monospaced))
                    }
                    Spacer()
                    Button(Texts.t("copy")) { if let code = vault.totp(value) { copy(code.code) } }.buttonStyle(.borderless)
                } else {
                    Text(secret && !shown ? "••••••••••••" : value)
                        .font(secret ? .system(.body, design: .monospaced) : .body)
                        .textSelection(.enabled)
                    Spacer()
                    if secret {
                        Button(Texts.t(shown ? "hide" : "show")) { shown.toggle() }.buttonStyle(.borderless)
                    }
                    Button(Texts.t("copy")) { copy(value) }.buttonStyle(.borderless)
                }
            }
            if copied { Text(Texts.t("copied")).font(.caption2).foregroundStyle(.secondary) }
        }
    }

    private func copy(_ text: String) {
        copySecret(text)
        copied = true
        vault.touch()
    }
}

struct ItemView: View {
    let id: String
    @EnvironmentObject var vault: Vault
    @Environment(\.dismiss) private var dismiss
    @State private var error: String?
    @State private var confirmDelete = false

    var body: some View {
        let summary = vault.all.first { $0.id == id }
        let writable = summary.map { vault.canWrite($0.vaultId) } ?? false
        let item = (try? vault.item(id)) ?? [:]
        let overview = item["overview"] as? [String: Any] ?? [:]
        let details = item["details"] as? [String: Any] ?? [:]
        let fields = (details["fields"] as? [[String: Any]] ?? []).filter { !(($0["value"] as? String) ?? "").isEmpty }
        let sections = details["sections"] as? [[String: Any]] ?? []
        let urls = (overview["urls"] as? [[String: Any]] ?? []).compactMap { $0["href"] as? String }.filter { !$0.isEmpty }
        let notes = details["notes"] as? String ?? ""
        let tags = overview["tags"] as? [String] ?? []
        let passkeys = details["passkeys"] as? [[String: Any]] ?? []
        return List {
            if let error { Section { Text(error).foregroundStyle(.red) } }
            Section {
                Text(Texts.category(overview["category"] as? String ?? "")).font(.footnote).foregroundStyle(.secondary)
                if summary?.trashed == true {
                    Text(Texts.t("inTrash")).font(.footnote).foregroundStyle(.secondary)
                } else if summary?.archived == true {
                    Text(Texts.t("inArchive")).font(.footnote).foregroundStyle(.secondary)
                }
            }
            if !fields.isEmpty {
                Section { ForEach(fields.indices, id: \.self) { FieldRow(field: fields[$0]) } }
            }
            ForEach(sections.indices, id: \.self) { index in
                let section = sections[index]
                let inner = (section["fields"] as? [[String: Any]] ?? []).filter { !(($0["value"] as? String) ?? "").isEmpty }
                if !inner.isEmpty {
                    Section(section["title"] as? String ?? "") { ForEach(inner.indices, id: \.self) { FieldRow(field: inner[$0]) } }
                }
            }
            if !urls.isEmpty {
                Section(Texts.t("websites")) {
                    ForEach(urls, id: \.self) { href in
                        let target = href.hasPrefix("http://") || href.hasPrefix("https://") ? href : "https://\(href)"
                        if let url = URL(string: target), url.scheme == "https" || url.scheme == "http" {
                            Link(href, destination: url)
                        } else {
                            Text(href)
                        }
                    }
                }
            }
            if !passkeys.isEmpty {
                passkeysSection(passkeys, removable: writable && summary?.trashed != true)
            }
            if !notes.isEmpty { Section(Texts.t("notes")) { Text(notes).textSelection(.enabled) } }
            if !tags.isEmpty { Section(Texts.t("tags")) { Text(tags.joined(separator: " · ")) } }
            Section { Text(Texts.t("readOnly")).font(.footnote).foregroundStyle(.secondary) }
        }
        .navigationTitle(overview["title"] as? String ?? "")
        .toolbar { menu(summary, writable: writable) }
        .confirmationDialog(Texts.t("deleteForeverBody"), isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(Texts.t("deleteForever"), role: .destructive) {
                run(leaving: true) { try await vault.deleteForGood(id) }
            }
        }
        .onAppear { vault.touch() }
    }

    private func passkeysSection(_ passkeys: [[String: Any]], removable: Bool) -> some View {
        Section(Texts.t("passkeys")) {
            ForEach(passkeys.indices, id: \.self) { index in
                PasskeyRow(passkey: passkeys[index], itemId: id, removable: removable) { work in run(work) }
            }
        }
    }

    /// The item's actions (see `ItemActions`), for an item that can be changed.
    @ToolbarContentBuilder
    private func menu(_ summary: Item?, writable: Bool) -> some ToolbarContent {
        ToolbarItem(placement: .navigationBarTrailing) {
            if let summary, writable {
                Menu {
                    ItemActions(item: summary, onDeleteForever: { confirmDelete = true }) { leaving, work in
                        run(leaving: leaving, work)
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
    }

    /// Runs an action; `leaving`: the screen closes once it is done.
    private func run(leaving: Bool = false, _ work: @escaping () async throws -> Void) {
        Task {
            do {
                try await work()
                error = nil
                if leaving { dismiss() }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var vault: Vault
    @Environment(\.dismiss) private var dismiss
    @State private var biometric = Secure.biometricEnabled
    @State private var minutes = 5
    @State private var confirmSignOut = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(Texts.t("biometric"), isOn: $biometric)
                        .onChange(of: biometric) { on in vault.setBiometrics(on) }
                } footer: {
                    Text(Texts.t("biometricHint"))
                }
                Section(Texts.t("autoLock")) {
                    Picker(Texts.t("autoLock"), selection: $minutes) {
                        ForEach([1, 5, 10, 30], id: \.self) { value in
                            Text(String(format: Texts.t("minutes"), value)).tag(value)
                        }
                    }
                    .onChange(of: minutes) { value in vault.autoLockMinutes = value }
                }
                Section(Texts.t("account")) {
                    Text(vault.email).foregroundStyle(.secondary)
                    Button(Texts.t("signOut"), role: .destructive) { confirmSignOut = true }
                }
            }
            .navigationTitle(Texts.t("settings"))
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button(Texts.t("done")) { dismiss() } } }
            .onAppear { minutes = vault.autoLockMinutes }
            .confirmationDialog(Texts.t("signOutBody"), isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button(Texts.t("signOut"), role: .destructive) {
                    Task {
                        await vault.signOut()
                        dismiss()
                    }
                }
            }
        }
    }
}
