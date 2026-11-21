// Native-only PIN entry: the IWA and Chrome extension never receive the PIN.
// stdout is an anonymous pipe to the native host, not a log or terminal.
import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
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
alert.window.initialFirstResponder = field
app.activate(ignoringOtherApps: true)
guard alert.runModal() == .alertFirstButtonReturn else { exit(2) }
let pin = field.stringValue
field.stringValue = ""
guard (6...8).contains(pin.utf8.count), pin.utf8.allSatisfy({ $0 >= 32 && $0 <= 126 }) else { exit(3) }
FileHandle.standardOutput.write(Data(pin.utf8))
// Swift/AppKit may retain copies until process exit; no persistent caching.
