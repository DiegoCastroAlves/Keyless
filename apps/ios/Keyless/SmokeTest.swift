import Foundation

/// What works without an account, run by CI on the simulator
/// (`--smoke`): the Rust client answers, a setup link is read, the search
/// folds text as the other apps do, items are sorted into the Archive and
/// Recently Deleted, changes wait for the unlock, a mistyped Secret Key is
/// refused, and a
/// well-formed one goes through key derivation to the server, which refuses
/// the made-up account. Prints one line per check and quits (1 if one
/// failed).
enum SmokeTest {
    /// A well-formed Secret Key of no account (made for this test only).
    static let key = "K1-D0NPNM-CYKQXE-NYFN0-HMDYM-7S6MG"
    static let email = "smoke@example.invalid"

    static func run() async {
        var failed = 0
        func check(_ name: String, _ ok: Bool) {
            print("SMOKE \(ok ? "PASS" : "FAIL") \(name)")
            fflush(stdout)
            if !ok { failed += 1 }
        }
        let status = try? Native.object("status")
        check("the Rust client answers", status?["unlocked"] as? Bool == false)
        let parsed = try? Native.object("parseSetupLink", ["text": "keyless://setup#email=\(email)&key=\(key)"])
        check("a setup link is read", parsed?["secretKey"] as? String == key)
        // The search's rule, as keyless-core's search::fold.
        check("the search folds case and accents", Search.fold("Mãe AÇÃO José") == "mae acao jose")
        check("the search spells out letters", Search.fold("Straße Æble Łódź ﬁle²") == "strasse aeble lodz file2")
        check("the search plains quotes and dashes", Search.fold("d’água – e‑mail") == "d'agua - e-mail")
        check("the search finds each word", Search.has(Search.words("conta MAE"), in: ["Mãe", "conta@x.com"]))
        // The lists: Archive and Recently Deleted, as the client marks them.
        let archived = Item(id: "a", vaultId: "v", overview: ["archived": true, "trashed_at": NSNull()])
        let trashed = Item(id: "t", vaultId: "v", overview: ["trashed_at": 1_760_000_000])
        check("an archived item is not in Recently Deleted", archived.archived && !archived.trashed)
        check("an item in Recently Deleted", trashed.trashed && !trashed.archived)
        do {
            _ = try Native.object("setFlags", ["id": "a", "favorite": true, "now": 0])
            check("changes need the vault unlocked", false)
        } catch let error as KeylessError {
            check("changes need the vault unlocked", error.key == "locked")
        } catch {
            check("changes need the vault unlocked", false)
        }
        do {
            _ = try Native.object("derive", ["email": email, "masterPassword": "x", "secretKey": "K1-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE"])
            check("a mistyped Secret Key is refused", false)
        } catch let error as KeylessError {
            check("a mistyped Secret Key is refused", error.key == "secret_key_invalid")
        } catch {
            check("a mistyped Secret Key is refused", false)
        }
        do {
            let derived = try Native.object("derive", ["email": email, "masterPassword": "not-the-right-password-1", "secretKey": key])
            let secret = derived["authSecret"] as? String ?? ""
            check("key derivation", secret.count == 43)
            _ = try await Server.signIn(email: email, authSecret: secret)
            check("the server refuses the made-up account", false)
        } catch let error as KeylessError {
            check("the server refuses the made-up account", error.key == "invalid_credentials")
        } catch {
            check("the server refuses the made-up account", false)
        }
        print("SMOKE DONE \(failed)")
        fflush(stdout)
        exit(failed == 0 ? 0 : 1)
    }
}
