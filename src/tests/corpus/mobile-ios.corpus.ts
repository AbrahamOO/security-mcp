import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "IOS_ATS_WEAK",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Info.plist",
      content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>NSAppTransportSecurity</key>
\t<dict>
\t\t<key>NSAllowsArbitraryLoads</key>
\t\t<true/>
\t</dict>
\t<key>CFBundleIdentifier</key>
\t<string>com.example.myapp</string>
</dict>
</plist>
`
    },
    negative: {
      file: "MyApp/Info.plist",
      content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>NSAppTransportSecurity</key>
\t<dict>
\t\t<key>NSExceptionDomains</key>
\t\t<dict>
\t\t\t<key>legacy-partner.example.com</key>
\t\t\t<dict>
\t\t\t\t<key>NSExceptionMinimumTLSVersion</key>
\t\t\t\t<string>TLSv1.2</string>
\t\t\t\t<key>NSExceptionRequiresForwardSecrecy</key>
\t\t\t\t<true/>
\t\t\t\t<key>NSIncludesSubdomains</key>
\t\t\t\t<true/>
\t\t\t</dict>
\t\t</dict>
\t</dict>
\t<key>CFBundleIdentifier</key>
\t<string>com.example.myapp</string>
</dict>
</plist>
`
    },
    note: "Negative scopes the ATS exception to one named legacy domain with TLS 1.2 + forward secrecy required, and never sets NSAllowsArbitraryLoads — the rule only looks for that literal (or 'allowsarbitraryloads') substring."
  },
  {
    ruleId: "IOS_BACKUP_ALLOWED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Storage/CredentialStore.swift",
      content: `import Foundation

final class CredentialStore {
    func persistSessionToken(_ token: String) {
        let path = "Documents/session/token.json"
        FileManager.default.createFile(atPath: path, contents: Data(token.utf8))
    }
}
`
    },
    negative: {
      file: "MyApp/Storage/CredentialStore.swift",
      content: `import Foundation

final class CredentialStore {
    func persistSessionToken(_ token: String) throws {
        let path = "Documents/session/token.json"
        let fileURL = URL(fileURLWithPath: path)
        FileManager.default.createFile(atPath: path, contents: Data(token.utf8))
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        var mutableURL = fileURL
        try mutableURL.setResourceValues(resourceValues)
    }
}
`
    },
    note: "Negative writes to the same Documents/session sensitive path but sets isExcludedFromBackup = true via URLResourceValues, matching BACKUP_EXCLUDE_RE, before the file is left on disk."
  },
  {
    ruleId: "IOS_KEYCHAIN_WEAK_ACCESS",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Security/KeychainManager.swift",
      content: `import Security
import Foundation

func storeToken(_ token: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "authToken",
        kSecValueData as String: Data(token.utf8),
        kSecAttrAccessible as String: kSecAttrAccessibleAlways
    ]
    SecItemAdd(query as CFDictionary, nil)
}
`
    },
    negative: {
      file: "MyApp/Security/KeychainManager.swift",
      content: `import Security
import Foundation

func storeToken(_ token: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "authToken",
        kSecValueData as String: Data(token.utf8),
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemAdd(query as CFDictionary, nil)
}
`
    },
    note: "Negative uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly, which does not contain the 'kSecAttrAccessibleAlways' substring KEYCHAIN_WEAK_RE looks for."
  },
  {
    ruleId: "IOS_USERDEFAULTS_SENSITIVE",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Auth/SessionManager.swift",
      content: `import Foundation

final class SessionManager {
    func cacheAuthToken(_ token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
    }
}
`
    },
    negative: {
      file: "MyApp/Auth/SessionManager.swift",
      content: `import Foundation
import Security

final class SessionManager {
    func cacheAuthToken(_ token: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "authToken",
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }
}
`
    },
    note: "Negative moves the token to the Keychain (Security framework) and never references UserDefaults at all, so neither the direct nor the broad UserDefaults+keyword pass can match."
  },
  {
    ruleId: "IOS_LOG_SENSITIVE",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Auth/AuthService.swift",
      content: `import Foundation

final class AuthService {
    func login(username: String, password: String) {
        print("Logging in with password: \\(password)")
        performLogin(username: username, password: password)
    }

    private func performLogin(username: String, password: String) {}
}
`
    },
    negative: {
      file: "MyApp/Auth/AuthService.swift",
      content: `import Foundation

final class AuthService {
    func login(username: String, password: String) {
        Logger.shared.info("Login attempt for user \\(username)")
        performLogin(username: username, password: password)
    }

    private func performLogin(username: String, password: String) {}
}

enum Logger {
    static let shared = LoggerCore()
}

final class LoggerCore {
    func info(_ message: String) {
        // Redacted logging wrapper: never receives password/token/secret values.
    }
}
`
    },
    note: "Negative replaces the print(...) call with a redacting Logger wrapper that only ever logs the username — no NSLog/os_log/print/debugPrint call is adjacent to a password/token/secret identifier, exactly the rule's requiredActions."
  },
  {
    ruleId: "IOS_HARDCODED_SECRET",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Networking/APIClient.swift",
      content: `import Foundation

enum AppConfig {
    static let apiKey = "sk_live_51Hh2eKZvKYlo2C9x"
}
`
    },
    negative: {
      file: "MyApp/Networking/APIClient.swift",
      content: `import Foundation

enum AppConfig {
    static var apiKey: String {
        ProcessInfo.processInfo.environment["API_KEY"] ?? ""
    }
}
`
    },
    note: "Negative reads the key from the CI-injected environment at runtime instead of assigning a quoted literal, so HARDCODED_RE's `keyword = \"...\"` shape never matches (apiKey is followed by ': String {', not '=')."
  },
  {
    ruleId: "IOS_BUNDLE_SECRETS",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Config.plist",
      content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>AnalyticsAPIKey</key>
\t<string>AKIAIOSFODNN7EXAMPLE1</string>
</dict>
</plist>
`
    },
    negative: {
      file: "MyApp/Config.plist",
      content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>AnalyticsAPIKey</key>
\t<string>$(ANALYTICS_API_KEY)</string>
</dict>
</plist>
`
    },
    note: "Negative substitutes an Xcode build-setting reference ($(ANALYTICS_API_KEY)) resolved at build time from CI secrets, instead of a literal value — the '$' immediately after <string> breaks PLIST_SECRET_RE's [A-Za-z0-9+=_-]{8,} value class."
  },
  {
    ruleId: "IOS_WEAK_CRYPTO",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Crypto/HashHelper.swift",
      content: `import CommonCrypto
import Foundation

final class HashHelper {
    static func legacyChecksum(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return Data(digest)
    }
}
`
    },
    negative: {
      file: "MyApp/Crypto/HashHelper.swift",
      content: `import CryptoKit
import Foundation

final class HashHelper {
    static func checksum(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
`
    },
    note: "Negative uses CryptoKit's SHA256 and contains none of CC_MD5/CC_SHA1/kCCAlgorithmDES/RC2/RC4/kCCOptionECBMode that WEAK_CRYPTO_RE looks for."
  },
  {
    ruleId: "IOS_ARC_DISABLED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Legacy/LegacyBridge.m",
      content: `// Compiler Flags: -fno-objc-arc
#import "LegacyBridge.h"

@implementation LegacyBridge

- (void)releaseManually:(id)object {
    [object retain];
    [object release];
}

@end
`
    },
    negative: {
      file: "MyApp/Legacy/LegacyBridge.m",
      content: `#import "LegacyBridge.h"

@implementation LegacyBridge

- (void)releaseManually:(id)object {
    // ARC manages retain/release automatically; no manual memory management needed.
}

@end
`
    },
    note: "Negative drops the -fno-objc-arc compiler-flag reference entirely (file compiles under default ARC), so ARC_DISABLED_RE finds nothing in either the source or a pbxproj."
  },
  {
    ruleId: "IOS_JAILBREAK_DETECTION_MISSING",
    check: "mobile-ios",
    positive: {
      file: "MyApp/AppDelegate.swift",
      content: `import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        configureAppearance()
        return true
    }

    private func configureAppearance() {
        UINavigationBar.appearance().tintColor = .systemBlue
    }
}
`
    },
    negative: {
      file: "MyApp/AppDelegate.swift",
      content: `import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        if JailbreakDetector.isCompromised() {
            handleCompromisedDevice()
        }
        return true
    }

    private func handleCompromisedDevice() {
        // Log and restrict functionality on jailbroken devices.
    }
}

enum JailbreakDetector {
    static func isCompromised() -> Bool {
        let suspiciousPaths = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib"]
        for path in suspiciousPaths where FileManager.default.fileExists(atPath: path) {
            return true
        }
        if UIApplication.shared.canOpenURL(URL(string: "cydia://package/com.example.package")!) {
            return true
        }
        return false
    }
}
`
    },
    note: "This rule fires on the ABSENCE of jailbreak-related keywords across the whole codebase. Negative adds a real detector referencing Cydia/MobileSubstrate/canOpenURL(cydia), so JAILBREAK_RE finds a match and the rule stays silent."
  },
  {
    ruleId: "IOS_CERTIFICATE_PINNING_MISSING",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Networking/APIService.swift",
      content: `import Foundation

final class APIService {
    func fetchProfile(completion: @escaping (Data?) -> Void) {
        let url = URL(string: "https://api.example.com/profile")!
        let task = URLSession.shared.dataTask(with: url) { data, _, _ in
            completion(data)
        }
        task.resume()
    }
}
`
    },
    negative: {
      file: "MyApp/Networking/APIService.swift",
      content: `import Foundation

final class APIService: NSObject, URLSessionDelegate {
    func fetchProfile(completion: @escaping (Data?) -> Void) {
        let url = URL(string: "https://api.example.com/profile")!
        let session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: url) { data, _, _ in
            completion(data)
        }
        task.resume()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust, evaluateTrust(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }

    private func evaluateTrust(_ trust: SecTrust) -> Bool {
        return true
    }
}
`
    },
    note: "Negative keeps URLSession but adds a URLSessionDelegate implementing didReceive challenge with an evaluateTrust(...) call, matching PINNING_RE, so pinningFiles is non-empty and the rule returns null."
  },
  {
    ruleId: "IOS_PASTEBOARD_SENSITIVE",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Utilities/ClipboardHelper.swift",
      content: `import UIKit

final class OtpFieldView: UIView {
    var otpTextField: UITextField!

    func autoFillFromClipboard() {
        if let code = UIPasteboard.general.string {
            otpTextField.text = code
        }
    }
}
`
    },
    negative: {
      file: "MyApp/Utilities/ClipboardHelper.swift",
      content: `import UIKit

final class OtpFieldView: UIView {
    var otpTextField: UITextField!
    private let internalPasteboard = UIPasteboard(name: UIPasteboard.Name("com.example.myapp.internal"), create: true)

    func autoFillFromInternalClipboard() {
        if let code = internalPasteboard?.string {
            otpTextField.text = code
        }
    }
}
`
    },
    note: "Negative uses a private named pasteboard (UIPasteboard(name:create:)) instead of UIPasteboard.general, exactly the rule's remediation — PASTEBOARD_RE only matches the literal 'UIPasteboard.general' substring."
  },
  {
    ruleId: "IOS_SCREENSHOT_UNPROTECTED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Views/PaymentViewController.swift",
      content: `import UIKit

final class PaymentViewController: UIViewController {
    @IBOutlet weak var cardNumberField: UITextField!

    override func viewDidLoad() {
        super.viewDidLoad()
        cardNumberField.placeholder = "Card number"
    }
}
`
    },
    negative: {
      file: "MyApp/Views/PaymentViewController.swift",
      content: `import UIKit

final class PaymentViewController: UIViewController {
    @IBOutlet weak var cardNumberField: UITextField!

    override func viewDidLoad() {
        super.viewDidLoad()
        cardNumberField.placeholder = "Card number"
        cardNumberField.isSecureTextEntry = true
        NotificationCenter.default.addObserver(self, selector: #selector(handleScreenshot), name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    }

    @objc private func handleScreenshot() {
        // Blur sensitive fields when a screenshot is detected.
    }
}
`
    },
    note: "Negative sets isSecureTextEntry = true and observes userDidTakeScreenshotNotification, both matching SCREEN_CAPTURE_RE, which makes the whole check return null before the sensitive-VC-name heuristic is even consulted."
  },
  {
    ruleId: "IOS_WEBVIEW_JS_ENABLED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/WebView/BridgeWebViewController.m",
      content: `#import "BridgeWebViewController.h"
#import <WebKit/WebKit.h>

@implementation BridgeWebViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    WKUserContentController *contentController = [[WKUserContentController alloc] init];
    [contentController addScriptMessageHandler:self name:@"nativeBridge"];
}

- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    [self handleBridgeMessage:message.body];
}

@end
`
    },
    negative: {
      file: "MyApp/WebView/BridgeWebViewController.m",
      content: `#import "BridgeWebViewController.h"
#import <WebKit/WebKit.h>

@implementation BridgeWebViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
    configuration.preferences.javaScriptEnabled = NO;
    self.webView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:configuration];
    [self.view addSubview:self.webView];
}

@end
`
    },
    note: "Negative never registers a WKScriptMessageHandler at all and disables JavaScript outright, so the literal 'addScriptMessageHandler' substring WEBVIEW_HANDLER_RE looks for is absent."
  },
  {
    ruleId: "IOS_CORE_DATA_UNENCRYPTED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Persistence/PersistenceController.swift",
      content: `import CoreData

final class PersistenceController {
    let container: NSPersistentContainer

    init() {
        container = NSPersistentContainer(name: "MyApp")
        container.loadPersistentStores { _, error in
            if let error = error {
                fatalError("Unresolved error \\(error)")
            }
        }
    }
}
`
    },
    negative: {
      file: "MyApp/Persistence/PersistenceController.swift",
      content: `import CoreData

final class PersistenceController {
    let container: NSPersistentContainer

    init() {
        container = NSPersistentContainer(name: "MyApp")
        if let description = container.persistentStoreDescriptions.first {
            description.setOption(FileProtectionType.complete as NSObject, forKey: NSPersistentStoreFileProtectionKey)
        }
        container.loadPersistentStores { _, error in
            if let error = error {
                fatalError("Unresolved error \\(error)")
            }
        }
    }
}
`
    },
    note: "Negative sets NSPersistentStoreFileProtectionKey on the store description before loading, matching PROTECTION_RE, exactly the rule's requiredActions fix."
  },
  {
    ruleId: "IOS_FILE_PROTECTION_NONE",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Storage/FileStorageManager.swift",
      content: `import Foundation

final class FileStorageManager {
    func writeCache(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .noFileProtection)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.none], ofItemAtPath: url.path)
    }
}
`
    },
    negative: {
      file: "MyApp/Storage/FileStorageManager.swift",
      content: `import Foundation

final class FileStorageManager {
    func writeCache(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .completeFileProtection)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }
}
`
    },
    note: "Negative sets FileProtectionType.complete instead of .none, so none of NSFileProtectionNone / .noProtection / FileProtectionType.none appear anywhere in the file."
  },
  {
    ruleId: "IOS_APPSTORAGE_SENSITIVE",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Views/SettingsView.swift",
      content: `import SwiftUI

struct SettingsView: View {
    @AppStorage("userAuthToken") private var authToken: String = ""

    var body: some View {
        Text("Token: \\(authToken)")
    }
}
`
    },
    negative: {
      file: "MyApp/Views/SettingsView.swift",
      content: `import SwiftUI

struct SettingsView: View {
    @AppStorage("preferredColorScheme") private var colorScheme: String = "system"

    private var authToken: String {
        get { KeychainWrapper.shared.string(forKey: "userAuthToken") ?? "" }
        set { KeychainWrapper.shared.set(newValue, forKey: "userAuthToken") }
    }

    var body: some View {
        Text("Theme: \\(colorScheme)")
    }
}
`
    },
    note: "Negative keeps @AppStorage only for a non-sensitive preference ('preferredColorScheme') and moves the credential-class authToken to a Keychain wrapper property, so APPSTORAGE_RE's @AppStorage(...token|password|secret|credential|auth|key...) never matches inside the AppStorage parens."
  },
  {
    ruleId: "IOS_SQLITE_UNENCRYPTED",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Database/DatabaseManager.swift",
      content: `import FMDB

final class DatabaseManager {
    let db: FMDatabase

    init() {
        db = FMDatabase(path: "app.db")
        db.open()
    }
}
`
    },
    negative: {
      file: "MyApp/Database/DatabaseManager.swift",
      content: `import FMDB

final class DatabaseManager {
    let db: FMDatabase

    init(passphrase: String) {
        db = FMDatabase(path: "app.db")
        db.open()
        db.setKey(passphrase)
        // SQLCipher-backed FMDB build enforces PRAGMA key on open.
    }
}
`
    },
    note: "Negative documents/uses the SQLCipher-backed build and calls setKey with a caller-supplied passphrase; the literal 'SQLCipher' substring matches CIPHER_RE and filters this file out."
  },
  {
    ruleId: "IOS_WEBVIEW_HTTP_LOAD",
    check: "mobile-ios",
    positive: {
      file: "MyApp/WebView/LegacyWebViewController.swift",
      content: `import WebKit

final class LegacyWebViewController: UIViewController {
    let webView = WKWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        webView.configuration.preferences.javaScriptEnabled = true
        let url = URL(string: "http://legacy.example.com/portal")!
        webView.load(URLRequest(url: url))
    }
}
`
    },
    negative: {
      file: "MyApp/WebView/LegacyWebViewController.swift",
      content: `import WebKit

final class LegacyWebViewController: UIViewController {
    let webView = WKWebView()

    override func viewDidLoad() {
        super.viewDidLoad()
        webView.configuration.preferences.javaScriptEnabled = false
        let url = URL(string: "https://legacy.example.com/portal")!
        webView.load(URLRequest(url: url))
    }
}
`
    },
    note: "Negative loads https:// only (no literal 'http://' substring is present — 'https://' does not contain it) and disables JavaScript, failing both the raw http:// gate and JS_BRIDGE_RE."
  },
  {
    ruleId: "IOS_BIOMETRIC_WEAK",
    check: "mobile-ios",
    positive: {
      file: "MyApp/Auth/BiometricAuthManager.swift",
      content: `import LocalAuthentication

final class BiometricAuthManager {
    func authenticate(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            completion(false)
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your account") { success, _ in
            completion(success)
        }
    }
}
`
    },
    negative: {
      file: "MyApp/Auth/BiometricAuthManager.swift",
      content: `import LocalAuthentication

final class BiometricAuthManager {
    private var savedDomainState: Data?

    func authenticate(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            completion(false)
            return
        }
        if let saved = savedDomainState, saved != context.evaluatedPolicyDomainState {
            savedDomainState = nil
            completion(false)
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock your account") { success, _ in
            if success {
                self.savedDomainState = context.evaluatedPolicyDomainState
            }
            completion(success)
        }
    }
}
`
    },
    note: "Negative compares context.evaluatedPolicyDomainState across authentications and uses deviceOwnerAuthenticationWithBiometrics, both matching ENROLLMENT_RE, so an attacker who enrolls a new fingerprint invalidates the saved session instead of silently passing."
  }
];
