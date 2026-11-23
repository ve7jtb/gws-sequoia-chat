// Native-only PIN entry: Chrome never receives the PIN. Standard output is an
// anonymous pipe owned by the native host, never a terminal or diagnostic log.
import AppKit

final class PinPromptDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let app = NSApplication.shared
        let stage = CommandLine.arguments.dropFirst().first ?? "Authorize operation"
        let serial = CommandLine.arguments.count == 3 ? CommandLine.arguments[2] : "configured key"
        let alert = NSAlert()
        alert.messageText = "Sequoia IWA — YubiKey PIN"
        alert.informativeText = stage + "\nKey \(serial). Touch when it flashes. No keys or policies will change."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 330, height: 28))
        field.placeholderString = "YubiKey PIN (not saved)"
        alert.accessoryView = field
        alert.addButton(withTitle: "Authorize")
        alert.addButton(withTitle: "Cancel")

        // Finish AppKit's launch lifecycle before showing or activating the
        // modal window. Activating an accessory process before runModal orders
        // its window can leave the prompt behind Chrome or on another Space.
        // A temporary Dock/Cmd-Tab entry also gives users a way to find it.
        alert.layout()
        let window = alert.window
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.level = .floating
        window.initialFirstResponder = field
        window.center()
        window.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        window.makeFirstResponder(field)

        guard alert.runModal() == .alertFirstButtonReturn else { exit(2) }
        let pin = field.stringValue
        field.stringValue = ""
        // Reject malformed local input before the host can contact the token.
        guard (6...8).contains(pin.utf8.count),
              pin.utf8.allSatisfy({ $0 >= 32 && $0 <= 126 }) else { exit(3) }
        FileHandle.standardOutput.write(Data(pin.utf8))
        // AppKit may retain temporary copies; process exit bounds their life.
        exit(0)
    }
}

let app = NSApplication.shared
let delegate = PinPromptDelegate()
app.setActivationPolicy(.regular)
app.delegate = delegate
app.run()
