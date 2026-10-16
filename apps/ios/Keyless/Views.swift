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

    private var shown: [Item] {
        // Each word anywhere, case and accents aside (see Search.swift).
        let words = Search.words(query)
        return vault.items.filter { item in
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
                        }
                    }
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

    var body: some View {
        let item = (try? vault.item(id)) ?? [:]
        let overview = item["overview"] as? [String: Any] ?? [:]
        let details = item["details"] as? [String: Any] ?? [:]
        let fields = (details["fields"] as? [[String: Any]] ?? []).filter { !(($0["value"] as? String) ?? "").isEmpty }
        let sections = details["sections"] as? [[String: Any]] ?? []
        let urls = (overview["urls"] as? [[String: Any]] ?? []).compactMap { $0["href"] as? String }.filter { !$0.isEmpty }
        let notes = details["notes"] as? String ?? ""
        let tags = overview["tags"] as? [String] ?? []
        return List {
            Section {
                Text(Texts.category(overview["category"] as? String ?? "")).font(.footnote).foregroundStyle(.secondary)
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
            if !notes.isEmpty { Section(Texts.t("notes")) { Text(notes).textSelection(.enabled) } }
            if !tags.isEmpty { Section(Texts.t("tags")) { Text(tags.joined(separator: " · ")) } }
            Section { Text(Texts.t("readOnly")).font(.footnote).foregroundStyle(.secondary) }
        }
        .navigationTitle(overview["title"] as? String ?? "")
        .onAppear { vault.touch() }
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
