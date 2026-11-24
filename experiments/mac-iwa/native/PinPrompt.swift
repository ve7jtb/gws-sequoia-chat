// Native-only PIN entry: Chrome never receives the PIN. Standard output is an
// anonymous pipe owned by the native host, never a terminal or diagnostic log.
import AppKit

final class PinPromptDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Finish the launch notification before starting a nested modal loop.
        // Do not use DispatchQueue.main.async here: running the entire modal
        // loop inside a serial main-queue block prevents AppKit's later main-
        // queue work from running until the dialog closes. A run-loop selector
        // leaves the dispatch queue available for rendering and button events.
        perform(#selector(presentPrompt), with: nil, afterDelay: 0, inModes: [.default])
    }

    @objc private func presentPrompt() {
        let app = NSApplication.shared
        // The dedicated diagnostic .app is permanently display-only through
        // its Info.plist. Launching it with no arguments cannot request a PIN.
        // Neither this diagnostic nor the real helper has any smart-card API.
        let visibilityCheck = CommandLine.arguments.dropFirst().first == "--visibility-check"
            || (Bundle.main.object(forInfoDictionaryKey: "PQMailPinVisibilityCheck") as? Bool == true)
        if !visibilityCheck && CommandLine.arguments.count != 3 { exit(64) }
        let stage = visibilityCheck ? "" : CommandLine.arguments[1]
        let serial = visibilityCheck ? "" : CommandLine.arguments[2]
        let alert = NSAlert()
        let field: NSSecureTextField?
        if visibilityCheck {
            alert.messageText = "Sequoia IWA — PIN dialog display check"
            alert.informativeText = "This is a display-only check. No PIN is requested and no YubiKey operation is possible. Close this window when you can see it."
            alert.addButton(withTitle: "Close")
            field = nil
        } else {
            // PIN entry and physical presence are separate steps. A user can
            // correctly submit the PIN but miss the subsequent flashing/touch
            // request after this dialog closes. Name the PIV credential and
            // selected serial prominently, retain the algorithm/purpose stage,
            // and explain the sequence without changing authentication or
            // inferring a touch policy that the helper does not inspect.
            alert.messageText = "Sequoia IWA — PIV PIN\nYubiKey \(serial)"
            alert.informativeText = stage + "\n\nEnter this YubiKey’s PIV PIN, not its FIDO/passkey PIN.\n\nAfter you click Continue, wait for the physical key to flash, then touch its sensor promptly. Keep the key connected until the operation finishes.\n\nIf the existing policy does not require touch, the operation finishes without flashing. No keys or policies will change."
            let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 330, height: 28))
            input.placeholderString = "PIV PIN (not saved)"
            alert.accessoryView = input
            alert.addButton(withTitle: "Continue — then touch key")
            alert.addButton(withTitle: "Cancel")
            field = input
        }

        // A native helper started by a browser or test process can inherit a
        // different Space/activation context. Keep this short-lived modal panel
        // visible on every Space, including fullscreen, rather than asking
        // macOS to move it to a possibly inactive application's Space.
        alert.layout()
        let window = alert.window
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.level = .modalPanel
        window.hidesOnDeactivate = false
        window.sharingType = visibilityCheck ? .readOnly : .none
        window.initialFirstResponder = field
        window.center()
        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        app.activate(ignoringOtherApps: true)
        if let field = field { window.makeFirstResponder(field) }

        // Reassert ordering once after the nested modal loop starts. Its timer
        // runs in the modal-panel mode, not inside a dispatch-main block, so it
        // cannot hold the serial queue hostage during the user's interaction.
        // This is presentation only; it never retries PIN or card operations.
        let activation = Timer(timeInterval: 0.05, repeats: false) { _ in
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            app.activate(ignoringOtherApps: true)
            window.orderFrontRegardless()
            window.makeKeyAndOrderFront(nil)
            if let field = field { window.makeFirstResponder(field) }
        }
        RunLoop.main.add(activation, forMode: .modalPanel)
        let response = alert.runModal()
        activation.invalidate()
        if visibilityCheck { exit(0) }
        guard response == .alertFirstButtonReturn, let field = field else { exit(2) }
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
