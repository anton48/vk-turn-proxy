import SwiftUI

@main
struct VKTurnProxyApp: App {
    init() {
        SharedLogger.shared.log("[App] VKTurnProxy launched")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
