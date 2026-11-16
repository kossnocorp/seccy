import SwiftUI

@main
struct SeccyGalleryApp: App {
    @NSApplicationDelegateAdaptor(GalleryAppDelegate.self) private var delegate

    init() {
        UITrace.enable()
        NativeNotifications.shared.configure()
        if let url = Bundle.main.url(forResource: "Seccy", withExtension: "icns") {
            NSApplication.shared.applicationIconImage = NSImage(contentsOf: url)
        }
    }
    var body: some Scene {
        WindowGroup(Copy.text("gallery-title")) { GalleryView() }
    }
}

final class GalleryAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { UITrace.event("app.launched") }
    func applicationDidBecomeActive(_ notification: Notification) { UITrace.event("app.active") }
    func applicationDidResignActive(_ notification: Notification) { UITrace.event("app.inactive") }
    func applicationDidHide(_ notification: Notification) { UITrace.event("app.hidden") }
    func applicationDidUnhide(_ notification: Notification) { UITrace.event("app.unhidden") }
    func applicationWillTerminate(_ notification: Notification) { UITrace.event("app.terminating") }
}
