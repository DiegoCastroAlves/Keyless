import SwiftUI

@main
struct KeylessApp: App {
    @StateObject private var vault = Vault()

    init() {
        // CI: `--smoke` runs the self-test (SmokeTest) and quits.
        if CommandLine.arguments.contains("--smoke") {
            Task { await SmokeTest.run() }
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(vault)
        }
    }
}
