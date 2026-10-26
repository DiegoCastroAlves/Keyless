import Foundation

/// Sync signals, as the desktop's realtime.rs and Android's Realtime.kt:
/// while the app is open and unlocked, a WebSocket to Supabase Realtime
/// joined to the account's private topic, "user:<id>". The server sends
/// "sync" there when an item, a vault or its members change on another
/// device (supabase/migrations/20261026000000_sync_signals.sql), and the app
/// syncs. A signal carries nothing: what changed comes from the sync, checked
/// as always. Only the account's own session can join the topic.
@MainActor
final class Realtime {
    /// Realtime drops a connection without a heartbeat for 30 s.
    private let heartbeat: UInt64 = 25
    /// A heartbeat unanswered for this long: the connection is gone.
    private let noAnswer: TimeInterval = 15
    /// Seconds between failed connections, then the last one over and over.
    private let backoff: [UInt64] = [1, 2, 5, 10, 30, 60]

    /// Joined to the topic: signals are arriving.
    private(set) var listening = false
    private var task: Task<Void, Never>?
    private var socket: URLSessionWebSocketTask?
    /// The connection's state (one at a time): its last ref, the heartbeat
    /// not answered yet, and the token Realtime has.
    private var ref = 1
    private var waiting: (ref: String, since: Date)?
    private var token = ""

    func start(vault: Vault) {
        guard task == nil, let url = Server.realtime else { return }
        task = Task { [weak self, weak vault] in
            var failures = 0
            while !Task.isCancelled {
                guard let self, let vault, vault.phase == .unlocked else { return }
                do {
                    try await self.listen(vault: vault, url: url)
                    failures = 0
                } catch {
                    self.listening = false
                    if Task.isCancelled { return }
                    let wait = self.backoff[min(failures, self.backoff.count - 1)]
                    failures += 1
                    try? await Task.sleep(nanoseconds: wait * 1_000_000_000)
                }
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        socket?.cancel(with: .normalClosure, reason: nil)
        socket = nil
        listening = false
    }

    private func frame(_ topic: String, _ event: String, _ payload: [String: Any], _ ref: Int) -> String {
        let message: [String: Any] = ["topic": topic, "event": event, "payload": payload, "ref": String(ref), "join_ref": "1"]
        let data = (try? JSONSerialization.data(withJSONObject: message)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    /// Listens until stopped or locked (returns) or the connection fails (throws).
    private func listen(vault: Vault, url: URL) async throws {
        token = try await vault.token()
        ref = 1
        waiting = nil
        guard let userId = vault.status["userId"] as? String, !userId.isEmpty else { throw KeylessError(key: "signed_out", message: "") }
        let socket = URLSession.shared.webSocketTask(with: url)
        self.socket = socket
        socket.resume()
        defer {
            socket.cancel(with: .normalClosure, reason: nil)
            if self.socket === socket { self.socket = nil }
        }
        let topic = "realtime:user:\(userId)"
        let config: [String: Any] = ["broadcast": ["ack": false, "self": false], "presence": ["enabled": false], "private": true]
        try await socket.send(.string(frame(topic, "phx_join", ["config": config, "access_token": token], 1)))

        // Heartbeats, a refreshed session for Realtime, and a connection that
        // stopped answering: closed, so `receive` below throws.
        let beats = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: (self?.heartbeat ?? 25) * 1_000_000_000)
                guard let self, !Task.isCancelled else { return }
                if let pending = self.waiting, Date().timeIntervalSince(pending.since) > self.noAnswer {
                    socket.cancel(with: .goingAway, reason: nil)
                    return
                }
                self.ref += 1
                try? await socket.send(.string(self.frame("phoenix", "heartbeat", [:], self.ref)))
                self.waiting = (String(self.ref), Date())
                if let fresh = try? await vault.token(), fresh != self.token {
                    self.token = fresh
                    self.ref += 1
                    try? await socket.send(.string(self.frame(topic, "access_token", ["access_token": fresh], self.ref)))
                }
            }
        }
        defer { beats.cancel() }

        while !Task.isCancelled {
            guard vault.phase == .unlocked else { return }
            let message = try await socket.receive()
            guard case .string(let text) = message,
                  let json = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
            else { continue }
            let event = json["event"] as? String ?? ""
            let atTopic = json["topic"] as? String == topic
            let payload = json["payload"] as? [String: Any] ?? [:]
            switch event {
            case "phx_reply" where json["ref"] as? String == "1":
                guard payload["status"] as? String == "ok" else { throw KeylessError(key: "offline", message: "join refused") }
                listening = true
                vault.signalled()
            case "phx_reply":
                if json["ref"] as? String == waiting?.ref { waiting = nil }
            case "broadcast" where atTopic && payload["event"] as? String == "sync":
                vault.signalled()
            case "phx_close" where atTopic, "phx_error" where atTopic:
                throw KeylessError(key: "offline", message: event)
            case "system" where atTopic && payload["status"] as? String == "error":
                throw KeylessError(key: "offline", message: payload["message"] as? String ?? "")
            default:
                break
            }
        }
    }
}
