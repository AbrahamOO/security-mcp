/**
 * iOS MASVS L1/L2 gate check — runs automatically on every PR.
 *
 * Covers the following OWASP MASVS control categories:
 *   MASVS-STORAGE   : keychain access levels, NSUserDefaults, Core Data encryption, backup exclusion, bundle secrets
 *   MASVS-CRYPTO    : weak algorithms (MD5/SHA1/DES/ECB), hardcoded secrets/IVs
 *   MASVS-AUTH      : biometric / LAContext enrollment change detection
 *   MASVS-NETWORK   : ATS / NSAllowsArbitraryLoads, certificate pinning, SSRF via URL schemes
 *   MASVS-PLATFORM  : pasteboard leakage, WKWebView JS bridge, custom URL scheme validation
 *   MASVS-CODE      : ARC disabled, bitcode in release, debug flags in production, network loggers
 *   MASVS-RESILIENCE: jailbreak detection, screenshot protection
 *
 * Each check is a standalone function returning Finding | null so results stay
 * actionable and deduplicated. File reads are grouped up-front via loadContext()
 * to avoid redundant I/O across checks.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";
import { searchRepo } from "../../repo/search.js";

// ── types ──────────────────────────────────────────────────────────────────────

type ScanContext = {
	infoPlistEntries: Array<[string, string]>;
	resourcePlistEntries: Array<[string, string]>;
	allNativeSources: Map<string, string>;
	objcSources: Map<string, string>;
	xcconfigs: Map<string, string>;
	pbxprojs: Map<string, string>;
};

// ── I/O helpers ────────────────────────────────────────────────────────────────

async function readFileMap(patterns: string[], ignore: string[]): Promise<Map<string, string>> {
	const paths = await fg(patterns, { dot: true, ignore });
	const result = new Map<string, string>();
	await Promise.all(
		paths.map(async (p) => {
			const text = await readFileSafe(p).catch(() => "");
			result.set(p, text);
		})
	);
	return result;
}

async function loadContext(): Promise<ScanContext> {
	const baseIgnore = ["**/node_modules/**", "**/.git/**"];
	const iosIgnore = [...baseIgnore, "**/Pods/**"];

	const allPlists = await readFileMap(["**/*.plist"], baseIgnore);
	const infoPlistEntries: Array<[string, string]> = [];
	const resourcePlistEntries: Array<[string, string]> = [];
	for (const [p, text] of allPlists) {
		if (p.toLowerCase().endsWith("info.plist")) {
			infoPlistEntries.push([p, text]);
		} else {
			resourcePlistEntries.push([p, text]);
		}
	}

	const swiftSources = await readFileMap(["**/*.swift"], iosIgnore);
	const objcSources = await readFileMap(["**/*.m", "**/*.mm"], iosIgnore);
	const xcconfigs = await readFileMap(["**/*.xcconfig"], iosIgnore);
	const pbxprojs = await readFileMap(["**/*.pbxproj"], iosIgnore);
	const allNativeSources = new Map<string, string>([...swiftSources, ...objcSources]);

	return { infoPlistEntries, resourcePlistEntries, allNativeSources, objcSources, xcconfigs, pbxprojs };
}

// ── scan utilities ─────────────────────────────────────────────────────────────

function filesWithMatch(sourceMap: Map<string, string>, re: RegExp): string[] {
	const matched: string[] = [];
	for (const [path, content] of sourceMap) {
		if (re.test(content)) matched.push(path);
	}
	return matched;
}

function evidenceLines(sourceMap: Map<string, string>, re: RegExp, maxLines = 10): string[] {
	const lines: string[] = [];
	for (const [path, content] of sourceMap) {
		if (lines.length >= maxLines) break;
		const fileLines = content.split("\n");
		for (let i = 0; i < fileLines.length && lines.length < maxLines; i++) {
			if (re.test(fileLines[i])) {
				lines.push(`${path}:${i + 1}:${fileLines[i].slice(0, 200)}`);
			}
		}
	}
	return lines;
}

// ── individual checks ─────────────────────────────────────────────────────────

/** CHECK 1: ATS weakened — NSAllowsArbitraryLoads present in Info.plist. MASVS-NETWORK-1 */
function checkAtsWeak(ctx: ScanContext): Finding[] {
	const found: Finding[] = [];
	for (const [p, text] of ctx.infoPlistEntries) {
		const lower = text.toLowerCase();
		if (lower.includes("nsallowsarbitraryloads") || lower.includes("allowsarbitraryloads")) {
			found.push({
				id: "IOS_ATS_WEAK",
				title: "iOS ATS appears weakened (NSAllowsArbitraryLoads)",
				severity: "CRITICAL",
				files: [p],
				requiredActions: [
					"Remove NSAllowsArbitraryLoads. Enforce TLS 1.3. Restrict exceptions to specific domains with justification.",
					"Enable certificate pinning for high-risk APIs where appropriate."
				]
			});
		}
	}
	return found;
}

/** CHECK 2: Sensitive file paths written without iCloud backup exclusion. MASVS-STORAGE-1 / CWE-312 */
function checkBackupAllowed(ctx: ScanContext): Finding | null {
	const SENSITIVE_PATH_RE = /(?:documents|library|caches|applicationSupport)[/\\](?:user|account|session|token|credential|secret|key|db|database)/i;
	const BACKUP_EXCLUDE_RE = /NSURLIsExcludedFromBackupKey|isExcludedFromBackup\s*=\s*true/;
	const violations = filesWithMatch(ctx.allNativeSources, SENSITIVE_PATH_RE).filter(
		(f) => !BACKUP_EXCLUDE_RE.test(ctx.allNativeSources.get(f) ?? "")
	);
	if (violations.length === 0) return null;
	return {
		id: "IOS_BACKUP_ALLOWED",
		title: "Sensitive file paths written without iCloud backup exclusion (NSURLIsExcludedFromBackupKey absent)",
		severity: "HIGH",
		files: violations.slice(0, 10),
		requiredActions: [
			"Set NSURLIsExcludedFromBackupKey to true on all URLs pointing to sensitive files (credentials, DB, tokens).",
			"MASVS-STORAGE-1: sensitive local data must not be backed up to iCloud without explicit user consent.",
			"Fix: try fileURL.setResourceValue(true, forKey: .isExcludedFromBackupKey)"
		]
	};
}

/** CHECK 3: kSecAttrAccessibleAlways* keychain access — accessible while device is locked. MASVS-STORAGE-1 / CWE-311 */
function checkKeychainWeakAccess(ctx: ScanContext): Finding | null {
	const KEYCHAIN_WEAK_RE = /kSecAttrAccessibleAlways(?:ThisDeviceOnly)?(?!\w)/;
	const files = filesWithMatch(ctx.allNativeSources, KEYCHAIN_WEAK_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_KEYCHAIN_WEAK_ACCESS",
		title: "Keychain items use kSecAttrAccessibleAlways or kSecAttrAccessibleAlwaysThisDeviceOnly — accessible while device is locked",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, KEYCHAIN_WEAK_RE),
		requiredActions: [
			"Replace kSecAttrAccessibleAlways with kSecAttrAccessibleWhenUnlockedThisDeviceOnly for most secrets.",
			"Use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for highest-value credentials.",
			"MASVS-STORAGE-1 / CWE-311: data accessible while the device is locked undermines the iOS Secure Enclave model."
		]
	};
}

/** CHECK 4: Credentials or tokens stored in NSUserDefaults (unencrypted). MASVS-STORAGE-1 / CWE-312 */
function checkUserDefaultsSensitive(ctx: ScanContext): Finding | null {
	const DIRECT_RE = /UserDefaults[^;\n]*(?:password|token|secret|apikey|api_key|credential|authToken|auth_token)/i;
	const directFiles = filesWithMatch(ctx.allNativeSources, DIRECT_RE);

	if (directFiles.length > 0) {
		return {
			id: "IOS_USERDEFAULTS_SENSITIVE",
			title: "Sensitive credentials or tokens stored in NSUserDefaults (unencrypted)",
			severity: "HIGH",
			files: directFiles.slice(0, 10),
			evidence: evidenceLines(ctx.allNativeSources, DIRECT_RE),
			requiredActions: [
				"Move all credential-class data to the iOS Keychain (Security framework kSecClassGenericPassword).",
				"NSUserDefaults is unencrypted and backed up by default — never store tokens, passwords, or secrets here.",
				"MASVS-STORAGE-1 / CWE-312"
			]
		};
	}

	// Broader pass: any file using UserDefaults that also contains sensitive-sounding identifiers
	const USERDEFAULTS_RE = /UserDefaults/;
	const SENSITIVE_KEY_RE = /(?:password|token|secret|credential)/i;
	const broadRisk = filesWithMatch(ctx.allNativeSources, USERDEFAULTS_RE).filter(
		(f) => SENSITIVE_KEY_RE.test(ctx.allNativeSources.get(f) ?? "")
	);
	if (broadRisk.length === 0) return null;
	return {
		id: "IOS_USERDEFAULTS_SENSITIVE",
		title: "Potential sensitive data stored in NSUserDefaults — verify no credentials or tokens are persisted here",
		severity: "HIGH",
		files: broadRisk.slice(0, 10),
		requiredActions: [
			"Do not store passwords, tokens, or secrets in NSUserDefaults — it is not encrypted and is included in iTunes/iCloud backups by default.",
			"Use the Keychain (Security framework) for all credential-class data.",
			"MASVS-STORAGE-1 / CWE-312"
		]
	};
}

/** CHECK 5: NSLog/print/os_log leaking sensitive data. MASVS-STORAGE-3 / CWE-532 */
async function checkLogSensitive(ctx: ScanContext): Promise<Finding | null> {
	const searchHits = await searchRepo({
		query: String.raw`(?:NSLog|os_log|print|debugPrint)\s*\([^;\n]*(?:password|token|secret|apiKey|credential)`,
		isRegex: true,
		maxMatches: 200
	});
	const iosHits = searchHits.filter((h) => /\.swift$|\.m$|\.mm$/.test(h.file));

	if (iosHits.length > 0) {
		return {
			id: "IOS_LOG_SENSITIVE",
			title: "NSLog/print/os_log call with potentially sensitive data (password, token, secret)",
			severity: "HIGH",
			files: [...new Set(iosHits.map((h) => h.file))].slice(0, 10),
			evidence: iosHits.slice(0, 10).map((h) => `${h.file}:${h.line}:${h.preview}`),
			requiredActions: [
				"Remove all log statements that print passwords, tokens, API keys, or PII.",
				"Use a logging wrapper that redacts sensitive fields in production builds.",
				"MASVS-STORAGE-3 / CWE-532: log files persist on device and may be exfiltrated or read in crash reports."
			]
		};
	}

	// Fallback: direct scan of loaded source files
	const LOG_SENSITIVE_RE = /(?:NSLog|os_log|print|debugPrint|NSLogv)\s*\([^;)]*(?:password|token|secret|apiKey|api_key|credential|ssn|cardNumber)/i;
	const logFiles = filesWithMatch(ctx.allNativeSources, LOG_SENSITIVE_RE);
	if (logFiles.length === 0) return null;
	return {
		id: "IOS_LOG_SENSITIVE",
		title: "NSLog/print/os_log call with potentially sensitive data (password, token, secret)",
		severity: "HIGH",
		files: logFiles.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, LOG_SENSITIVE_RE),
		requiredActions: [
			"Remove all log statements that print passwords, tokens, API keys, or PII.",
			"Use a logging wrapper that redacts sensitive fields in production builds.",
			"MASVS-STORAGE-3 / CWE-532: log files persist on device and may be exfiltrated or read in crash reports."
		]
	};
}

/** CHECK 6: Hardcoded API keys/secrets in Swift/ObjC source. MASVS-STORAGE-2 / CWE-798 */
function checkHardcodedSecret(ctx: ScanContext): Finding | null {
	const HARDCODED_RE = /(?:apiKey|APIKey|api_key|secret\s*=|password\s*=|secretKey|accessKey)\s*=\s*["'][A-Za-z0-9+=_-]{8,}["']/i;
	const files = filesWithMatch(ctx.allNativeSources, HARDCODED_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_HARDCODED_SECRET",
		title: "Hardcoded API key, secret, or password literal found in iOS source (CWE-798)",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, HARDCODED_RE),
		requiredActions: [
			"Remove all hardcoded secrets from source files — treat the current secret as compromised and rotate it immediately.",
			"Store secrets server-side and fetch them at runtime with authentication, or use encrypted config injected at build time via CI secrets.",
			"MASVS-STORAGE-2 / CWE-798: hardcoded secrets are trivially extracted from compiled binaries using strings(1) or disassembly."
		]
	};
}

// Matches a plist key whose name suggests a credential followed by a non-trivial string value.
// Forward-slash excluded from value class to avoid /…/ delimiter ambiguity (S5869).
const PLIST_SECRET_RE = /<key>[^<]*(?:Key|Secret|Password|Token|Credential)[^<]*<\/key>\s*<string>[A-Za-z0-9+=_-]{8,}<\/string>/i;
const PLIST_KEY_NAME_RE = /(?:Key|Secret|Password|Token|Credential)/i;
const PLIST_STRING_TAG_RE = /<string>/;

/** Extract up to maxLines evidence snippets from a single plist file. */
function extractPlistEvidence(path: string, text: string, maxLines: number): string[] {
	const evidence: string[] = [];
	const lines = text.split("\n");
	for (let i = 0; i < lines.length && evidence.length < maxLines; i++) {
		if (PLIST_KEY_NAME_RE.test(lines[i]) && i + 1 < lines.length && PLIST_STRING_TAG_RE.test(lines[i + 1])) {
			evidence.push(`${path}:${i + 1}:${lines[i].slice(0, 200)}`);
		}
	}
	return evidence;
}

/** CHECK 6b: Secrets embedded in bundled .plist resource files. MASVS-STORAGE-2 / CWE-798 */
function checkBundleSecrets(ctx: ScanContext): Finding | null {
	const infoFiles: string[] = [];
	const infoEvidence: string[] = [];
	for (const [p, text] of ctx.infoPlistEntries) {
		if (!PLIST_SECRET_RE.test(text)) continue;
		infoFiles.push(p);
		if (infoEvidence.length < 10) {
			infoEvidence.push(...extractPlistEvidence(p, text, 10 - infoEvidence.length));
		}
	}

	const resourceFiles = ctx.resourcePlistEntries
		.filter(([, text]) => PLIST_SECRET_RE.test(text))
		.map(([p]) => p);

	const allFiles = [...infoFiles, ...resourceFiles];
	if (allFiles.length === 0) return null;

	return {
		id: "IOS_BUNDLE_SECRETS",
		title: "Potential secret or API key embedded in Info.plist or bundled .plist resource file (CWE-798)",
		severity: "CRITICAL",
		files: allFiles.slice(0, 10),
		evidence: infoEvidence.slice(0, 10),
		requiredActions: [
			"Do not ship API keys or secrets in bundled plist files — the app bundle is extractable from any device.",
			"Fetch secrets from a secure backend endpoint authenticated by the user's identity, or use a key derivation approach.",
			"MASVS-STORAGE-2 / CWE-798"
		]
	};
}

/** CHECK 7: MD5/SHA1/DES/ECB usage in CommonCrypto. MASVS-CRYPTO-1 / CWE-327 */
function checkWeakCrypto(ctx: ScanContext): Finding | null {
	const WEAK_CRYPTO_RE = /kCCAlgorithmDES|kCCAlgorithmRC2|kCCAlgorithmRC4|CC_MD5|CC_SHA1\b|kCCOptionECBMode/;
	const files = filesWithMatch(ctx.allNativeSources, WEAK_CRYPTO_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_WEAK_CRYPTO",
		title: "Weak cryptographic algorithm used: MD5/SHA1/DES/ECB via CommonCrypto (MASVS-CRYPTO-1)",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, WEAK_CRYPTO_RE),
		requiredActions: [
			"Replace DES/RC2/RC4 with AES-256-GCM (kCCAlgorithmAES + kCCOptionPKCS7Padding with GCM mode via CryptoKit).",
			"Replace CC_MD5/CC_SHA1 with SHA-256 or SHA-3 (CC_SHA256 or CryptoKit's SHA256/SHA512).",
			"Never use ECB mode — it leaks plaintext patterns; use CBC with random IV or GCM.",
			"MASVS-CRYPTO-1 / CWE-327 / NIST SP 800-131A Rev 2"
		]
	};
}

/** CHECK 8: Objective-C files compiled without ARC (-fno-objc-arc). MASVS-CODE-4 / CWE-401 */
function checkArcDisabled(ctx: ScanContext): Finding | null {
	const ARC_DISABLED_RE = /-fno-objc-arc/;
	const srcFiles = filesWithMatch(ctx.objcSources, ARC_DISABLED_RE);
	const pbxFiles = filesWithMatch(ctx.pbxprojs, ARC_DISABLED_RE);
	const allFiles = [...new Set([...srcFiles, ...pbxFiles])];
	if (allFiles.length === 0) return null;
	return {
		id: "IOS_ARC_DISABLED",
		title: "Objective-C source compiled without ARC (-fno-objc-arc) — memory safety risk",
		severity: "HIGH",
		files: allFiles.slice(0, 10),
		evidence: evidenceLines(ctx.objcSources, ARC_DISABLED_RE),
		requiredActions: [
			"Enable ARC for all Objective-C files. Remove -fno-objc-arc compiler flag from build settings and file-level flags.",
			"Manual memory management is error-prone and substantially increases the risk of use-after-free and heap corruption vulnerabilities.",
			"MASVS-CODE-4 / CWE-401"
		]
	};
}

/** CHECK 9: No jailbreak detection in iOS codebase. MASVS-RESILIENCE-1 */
function checkJailbreakDetectionMissing(ctx: ScanContext): Finding | null {
	if (ctx.allNativeSources.size === 0) return null;
	const JAILBREAK_RE = /jailbreak|cydia|substrate|MobileSubstrate|fileExistsAtPath.*Applications|canOpenURL.*cydia|checkJailbreak/i;
	const found = filesWithMatch(ctx.allNativeSources, JAILBREAK_RE);
	if (found.length > 0) return null;
	return {
		id: "IOS_JAILBREAK_DETECTION_MISSING",
		title: "No jailbreak detection found in iOS codebase (MASVS-RESILIENCE-1)",
		severity: "MEDIUM",
		requiredActions: [
			"Implement jailbreak detection for high-risk apps: check for Cydia, substrate, /Applications paths, and dyld injection.",
			"Consider using a commercial RASP SDK (e.g., Guardsquare iXGuard) for tamper-resistant detection.",
			"MASVS-RESILIENCE-1: apps without jailbreak detection run in a fully compromised security context without warning.",
			"At minimum, detect and log — do not silently trust jailbroken environments for financial, healthcare, or government apps."
		]
	};
}

/** CHECK 10: URLSession without certificate pinning. MASVS-NETWORK-2 / CWE-295 */
function checkCertPinningMissing(ctx: ScanContext): Finding | null {
	const URL_SESSION_RE = /URLSession/;
	const PINNING_RE = /didReceive.*challenge|URLSession.*pinning|TrustKit|Alamofire.*ServerTrustManager|ServerTrustPolicy|pinnedCertificates|evaluateTrust/i;
	const urlSessionFiles = filesWithMatch(ctx.allNativeSources, URL_SESSION_RE);
	if (urlSessionFiles.length === 0) return null;
	const pinningFiles = filesWithMatch(ctx.allNativeSources, PINNING_RE);
	if (pinningFiles.length > 0) return null;
	return {
		id: "IOS_CERTIFICATE_PINNING_MISSING",
		title: "URLSession usage detected but no certificate pinning implementation found (MASVS-NETWORK-2)",
		severity: "HIGH",
		files: urlSessionFiles.slice(0, 10),
		requiredActions: [
			"Implement certificate pinning via URLSessionDelegate didReceive(_:challenge:completionHandler:) or use TrustKit.",
			"Pin the SPKI (SubjectPublicKeyInfo) hash rather than the full leaf certificate to survive cert renewals.",
			"MASVS-NETWORK-2 / CWE-295: without pinning, all HTTPS traffic is vulnerable to interception by trusted-but-malicious CAs."
		]
	};
}

/** CHECK 11: UIPasteboard.general used — sensitive data may leak. MASVS-PLATFORM-4 / CWE-200 */
function checkPasteboardSensitive(ctx: ScanContext): Finding | null {
	const PASTEBOARD_RE = /UIPasteboard\.general/;
	const files = filesWithMatch(ctx.allNativeSources, PASTEBOARD_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_PASTEBOARD_SENSITIVE",
		title: "UIPasteboard.general used — sensitive data may leak to other apps via system clipboard",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, PASTEBOARD_RE),
		requiredActions: [
			"Audit all UIPasteboard.general writes to ensure no passwords, tokens, or PII are placed on the general pasteboard.",
			"For app-internal copy/paste of sensitive data, use UIPasteboard(name:create:) with a private named pasteboard.",
			"Set expiration: pasteboard.setItems([data], options: [.expirationDate: Date().addingTimeInterval(30)])",
			"MASVS-PLATFORM-4 / CWE-200: the general pasteboard is readable by all installed apps."
		]
	};
}

/** CHECK 12: Sensitive view controllers without screenshot / screen-capture protection. MASVS-RESILIENCE-2 / CWE-359 */
function checkScreenshotUnprotected(ctx: ScanContext): Finding | null {
	const SCREEN_CAPTURE_RE = /UIScreen\.main\.isCaptured|isSecureTextEntry\s*=\s*true|userDidTakeScreenshotNotification/;
	if (filesWithMatch(ctx.allNativeSources, SCREEN_CAPTURE_RE).length > 0) return null;
	const SENSITIVE_VC_RE = /ViewController.*(?:Password|Payment|Auth|Secret|Credential|Card|Account)|(?:Password|Payment|Auth|Secret|Credential|Card|Account).*ViewController/i;
	const sensitiveFiles = filesWithMatch(ctx.allNativeSources, SENSITIVE_VC_RE);
	if (sensitiveFiles.length === 0) return null;
	return {
		id: "IOS_SCREENSHOT_UNPROTECTED",
		title: "Sensitive view controllers detected without screenshot / screen-capture protection",
		severity: "MEDIUM",
		files: sensitiveFiles.slice(0, 10),
		requiredActions: [
			"Check UIScreen.main.isCaptured and hide/blur sensitive fields when the screen is being recorded or mirrored.",
			"Subscribe to UIScreen.capturedDidChangeNotification to react to capture-state changes.",
			"Set isSecureTextEntry = true on all password and sensitive input fields.",
			"MASVS-RESILIENCE-2 / CWE-359: screen recordings and screenshots expose sensitive data to malicious screen-capture apps."
		]
	};
}

/** CHECK 13: WKWebView addScriptMessageHandler exposes native bridge to JS. MASVS-PLATFORM-5 / CWE-749 */
function checkWebviewJsBridge(ctx: ScanContext): Finding | null {
	const WEBVIEW_HANDLER_RE = /addScriptMessageHandler/;
	const files = filesWithMatch(ctx.allNativeSources, WEBVIEW_HANDLER_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_WEBVIEW_JS_ENABLED",
		title: "WKWebView addScriptMessageHandler exposes native bridge to JavaScript — XSS can reach native code",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, WEBVIEW_HANDLER_RE),
		requiredActions: [
			"Audit all WKScriptMessageHandler implementations: validate every message name and payload type strictly.",
			"Never expose sensitive native APIs (file system, keychain, network) through the JS bridge.",
			"Disable JavaScript if it is not required: config.preferences.javaScriptEnabled = false",
			"Load only trusted first-party content in webviews that have a native bridge — never load external URLs.",
			"MASVS-PLATFORM-5 / CWE-749: XSS in a bridged WKWebView is equivalent to remote code execution in the native context."
		]
	};
}

/** CHECK 14: CFBundleURLTypes registered without source-level origin validation. MASVS-PLATFORM-3 / CWE-939 */
function checkUrlSchemeUnvalidated(ctx: ScanContext): Finding | null {
	const URL_SCHEME_PLIST_RE = /CFBundleURLTypes/;
	const plistsWithSchemes = ctx.infoPlistEntries
		.filter(([, text]) => URL_SCHEME_PLIST_RE.test(text))
		.map(([p]) => p);
	if (plistsWithSchemes.length === 0) return null;
	const VALIDATION_RE = /application.*open.*url.*options|openURL.*validat|url\.scheme|url\.host|allowedSchemes/i;
	if (filesWithMatch(ctx.allNativeSources, VALIDATION_RE).length > 0) return null;
	return {
		id: "IOS_URL_SCHEME_UNVALIDATED",
		title: "Custom URL scheme registered in Info.plist but no scheme/origin validation found in source",
		severity: "HIGH",
		files: plistsWithSchemes.slice(0, 10),
		requiredActions: [
			"In application(_:open:options:), validate the full URL: scheme, host, and path against a strict allowlist before acting on it.",
			"Check UIApplicationOpenURLOptionsSourceApplicationKey to verify the calling app's bundle ID.",
			"MASVS-PLATFORM-3 / CWE-939: unvalidated URL schemes allow any installed app to trigger deep-link actions with attacker-controlled parameters."
		]
	};
}

/** CHECK 15: LAContext without evaluatedPolicyDomainState enrollment-change detection. MASVS-AUTH-3 / CWE-287 */
function checkBiometricWeak(ctx: ScanContext): Finding | null {
	const LACONTEXT_RE = /LAContext/;
	const laContextFiles = filesWithMatch(ctx.allNativeSources, LACONTEXT_RE);
	if (laContextFiles.length === 0) return null;
	const ENROLLMENT_RE = /evaluatedPolicyDomainState|domainState|LABiometryType|deviceOwnerAuthenticationWithBiometrics/;
	if (filesWithMatch(ctx.allNativeSources, ENROLLMENT_RE).length > 0) return null;
	return {
		id: "IOS_BIOMETRIC_WEAK",
		title: "LAContext used without evaluatedPolicyDomainState enrollment-change detection",
		severity: "HIGH",
		files: laContextFiles.slice(0, 10),
		requiredActions: [
			"After each successful biometric authentication, save context.evaluatedPolicyDomainState and compare on the next auth to detect added/removed fingerprints.",
			"If the domain state changes, invalidate the session and require re-authentication.",
			"MASVS-AUTH-3 / CWE-287: without enrollment detection, an attacker who adds their own fingerprint to the device can bypass biometric authentication."
		]
	};
}

/** CHECK 16: ENABLE_BITCODE = YES in release xcconfig or pbxproj. MASVS-CODE-2 */
function checkBitcodeEnabled(ctx: ScanContext): Finding | null {
	const BITCODE_RE = /ENABLE_BITCODE\s*=\s*YES/i;
	const files = [...new Set([...filesWithMatch(ctx.xcconfigs, BITCODE_RE), ...filesWithMatch(ctx.pbxprojs, BITCODE_RE)])];
	if (files.length === 0) return null;
	return {
		id: "IOS_BITCODE_ENABLED",
		title: "ENABLE_BITCODE = YES found — Apple recompiles your binary from bitcode, reducing reverse-engineering barrier",
		severity: "LOW",
		files: files.slice(0, 10),
		requiredActions: [
			"Set ENABLE_BITCODE = NO for release builds if your threat model requires controlling the exact compiled binary.",
			"Apple deprecated bitcode for iOS/tvOS in Xcode 14 — leaving it enabled has no benefit on modern toolchains.",
			"MASVS-CODE-2: submitted bitcode can be inspected by Apple and recompiled into a different optimization level than tested."
		]
	};
}

/** CHECK 17: DEBUG preprocessor flag or debug plist entries in production. MASVS-CODE-2 / CWE-11 */
function checkDebugFlagProduction(ctx: ScanContext): Finding | null {
	const DEBUG_PLIST_RE = /(?:<key>NSAssertionHandler<\/key>|<key>LSEnvironment<\/key>[^]*?DEBUG\s*=\s*1|<key>DEBUG<\/key>\s*<true\/>)/i;
	const debugPlistFiles = ctx.infoPlistEntries.filter(([, t]) => DEBUG_PLIST_RE.test(t)).map(([p]) => p);
	const DEBUG_SOURCE_RE = /#if\s+DEBUG\s*$|DEBUG\s*=\s*true|isDebugBuild\s*=\s*true/m;
	const debugSourceFiles = filesWithMatch(ctx.allNativeSources, DEBUG_SOURCE_RE);
	const allFiles = [...new Set([...debugPlistFiles, ...debugSourceFiles])];
	if (allFiles.length === 0) return null;
	return {
		id: "IOS_DEBUG_FLAG_PRODUCTION",
		title: "DEBUG build configuration or flag detected in production plist or source",
		severity: "CRITICAL",
		files: allFiles.slice(0, 10),
		requiredActions: [
			"Ensure DEBUG preprocessor flags are never compiled into release/production builds.",
			"Remove or guard all #if DEBUG blocks that bypass authentication, disable pinning, or log sensitive data.",
			"Validate that release scheme targets use Release configuration, not Debug.",
			"MASVS-CODE-2 / CWE-11: debug builds often disable security controls and expose internal state."
		]
	};
}

/** CHECK 18: Core Data persistent store without NSPersistentStoreFileProtectionKey. MASVS-STORAGE-1 / CWE-312 */
function checkCoreDataUnencrypted(ctx: ScanContext): Finding | null {
	const CORE_DATA_RE = /NSPersistentStoreCoordinator|NSPersistentContainer/;
	const coreDataFiles = filesWithMatch(ctx.allNativeSources, CORE_DATA_RE);
	if (coreDataFiles.length === 0) return null;
	const PROTECTION_RE = /NSPersistentStoreFileProtectionKey|NSFileProtectionComplete|NSFileProtectionCompleteUnlessOpen/;
	if (filesWithMatch(ctx.allNativeSources, PROTECTION_RE).length > 0) return null;
	return {
		id: "IOS_CORE_DATA_UNENCRYPTED",
		title: "Core Data persistent store used without NSPersistentStoreFileProtectionKey — database unencrypted at rest when device is locked",
		severity: "HIGH",
		files: coreDataFiles.slice(0, 10),
		requiredActions: [
			"Add NSPersistentStoreFileProtectionKey: NSFileProtectionComplete to the persistent store options dictionary.",
			"options[NSPersistentStoreFileProtectionKey] = FileProtectionType.complete",
			"MASVS-STORAGE-1 / CWE-312: without Data Protection, the SQLite file is accessible to attackers with physical access to an unlocked device or via a jailbreak."
		]
	};
}

/** CHECK 19: Network debugging / proxy tool reference in production source. MASVS-CODE-2 / CWE-532 */
function checkNetworkLoggerProduction(ctx: ScanContext): Finding | null {
	const NETWORK_LOGGER_RE = /(?:Charles|Proxyman|Paw|Rocketim|Netfox|GDNetwork|NetworkActivityLogger|ResponseSniffer|Wormholy)/i;
	const files = filesWithMatch(ctx.allNativeSources, NETWORK_LOGGER_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_NETWORK_LOGGER_PRODUCTION",
		title: "Network debugging / proxy tool reference found in source — must be stripped from production builds",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, NETWORK_LOGGER_RE),
		requiredActions: [
			"Wrap all network debugging integrations (Wormholy, Netfox, Charles proxy config) in #if DEBUG guards.",
			"Ensure no debug proxy certificate or trust-all-certs workaround reaches the release binary.",
			"MASVS-CODE-2 / CWE-532: network loggers in production expose all API traffic and can bypass certificate pinning."
		]
	};
}

/** CHECK 20: Sensitive data written to NSTemporaryDirectory. MASVS-STORAGE-1 */
function checkNsTempDirSensitive(ctx: ScanContext): Finding | null {
	const TEMP_DIR_RE = /NSTemporaryDirectory\(\)|FileManager\.default\.temporaryDirectory/;
	const SENSITIVE_RE = /(?:token|password|secret|credential|auth|key)/i;
	const files = filesWithMatch(ctx.allNativeSources, TEMP_DIR_RE).filter(
		(f) => SENSITIVE_RE.test(ctx.allNativeSources.get(f) ?? "")
	);
	if (files.length === 0) return null;
	return {
		id: "IOS_TEMP_DIR_SENSITIVE",
		title: "iOS sensitive data written to NSTemporaryDirectory — not guaranteed cleanup, accessible on jailbroken devices (MASVS-STORAGE-1)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, TEMP_DIR_RE),
		requiredActions: [
			"Do not write credential-class data (tokens, passwords, secrets) to NSTemporaryDirectory — the OS does not guarantee timely cleanup.",
			"Use the iOS Keychain for credentials. If temporary scratch files are needed, write to a sub-directory of the app's Documents folder with NSURLIsExcludedFromBackupKey and NSFileProtectionComplete.",
			"MASVS-STORAGE-1: temp files are accessible on jailbroken devices and can survive across app restarts."
		]
	};
}

/** CHECK 21: NSFileProtectionNone set on file — readable when device is locked. MASVS-STORAGE-1 */
function checkNsFileProtectionNone(ctx: ScanContext): Finding | null {
	const PROTECTION_NONE_RE = /NSFileProtectionNone|\.noProtection|FileProtectionType\.none/;
	const files = filesWithMatch(ctx.allNativeSources, PROTECTION_NONE_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_FILE_PROTECTION_NONE",
		title: "NSFileProtectionNone set on file — readable when device is locked or powered off (MASVS-STORAGE-1)",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, PROTECTION_NONE_RE),
		requiredActions: [
			"Replace NSFileProtectionNone with NSFileProtectionComplete for all sensitive files.",
			"Use NSFileProtectionCompleteUnlessOpen only when the file must be accessible while the device is locked for a specific background task.",
			"MASVS-STORAGE-1 / CWE-311: NSFileProtectionNone means the file is readable in any device state, including when locked or seized."
		]
	};
}

/** CHECK 22: @AppStorage used for sensitive data — backed by UserDefaults. MASVS-STORAGE-1 */
function checkAppStorageSensitive(ctx: ScanContext): Finding | null {
	const APPSTORAGE_RE = /@AppStorage\s*\([^)]*(?:token|password|secret|credential|auth|key)/i;
	const files = filesWithMatch(ctx.allNativeSources, APPSTORAGE_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_APPSTORAGE_SENSITIVE",
		title: "@AppStorage used for sensitive data — backed by UserDefaults, unencrypted, included in iTunes backups (MASVS-STORAGE-1)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, APPSTORAGE_RE),
		requiredActions: [
			"Replace @AppStorage for credential-class keys with a Keychain wrapper property wrapper.",
			"@AppStorage is syntactic sugar over UserDefaults — it is unencrypted and included in iCloud/iTunes backups by default.",
			"MASVS-STORAGE-1 / CWE-312: tokens and passwords in UserDefaults are trivially readable on jailbroken devices."
		]
	};
}

/** CHECK 23: iOS SQLite database without SQLCipher encryption. MASVS-STORAGE-1 */
function checkSqliteUnencrypted(ctx: ScanContext): Finding | null {
	const SQLITE_RE = /import FMDB|import SQLite|FMDatabase\s*\(|Connection\s*\([^)]*\.db/;
	const CIPHER_RE = /SQLCipher|sqlite3_key|PRAGMA key/;
	const files = filesWithMatch(ctx.allNativeSources, SQLITE_RE).filter(
		(f) => !CIPHER_RE.test(ctx.allNativeSources.get(f) ?? "")
	);
	if (files.length === 0) return null;
	return {
		id: "IOS_SQLITE_UNENCRYPTED",
		title: "iOS SQLite database without SQLCipher encryption — readable on jailbroken devices (MASVS-STORAGE-1)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, SQLITE_RE),
		requiredActions: [
			"Replace FMDB/SQLite.swift with a SQLCipher-backed variant and set a strong database key via sqlite3_key.",
			"Derive the database key from the user's passphrase + device-bound secret using PBKDF2 or Argon2 — do not hardcode it.",
			"MASVS-STORAGE-1: plaintext SQLite files are trivially copied and opened on jailbroken devices or via physical acquisition."
		]
	};
}

/** CHECK 24: WKWebView loading http:// URLs with JavaScript enabled. MASVS-NETWORK-1 */
function checkWkWebviewHttpLoad(ctx: ScanContext): Finding | null {
	const WEBVIEW_RE = /WKWebView/;
	const HTTP_LOAD_RE = /loadRequest.*http:|load.*URLRequest.*http:/i;
	const JS_BRIDGE_RE = /javaScriptEnabled\s*=\s*true/;
	const files = filesWithMatch(ctx.allNativeSources, WEBVIEW_RE).filter((f) => {
		const content = ctx.allNativeSources.get(f) ?? "";
		return (HTTP_LOAD_RE.test(content) || JS_BRIDGE_RE.test(content)) && /http:\/\//.test(content);
	});
	if (files.length === 0) return null;
	return {
		id: "IOS_WEBVIEW_HTTP_LOAD",
		title: "WKWebView with JavaScript enabled loading http:// — full MITM enables JS bridge injection (MASVS-NETWORK-1)",
		severity: "CRITICAL",
		files: files.slice(0, 10),
		evidence: evidenceLines(ctx.allNativeSources, HTTP_LOAD_RE),
		requiredActions: [
			"Always load WKWebView content over https:// — enforce this in ATS and in the URL construction logic.",
			"If http:// is required for a legacy endpoint, disable JavaScript (config.preferences.javaScriptEnabled = false) and remove all WKScriptMessageHandler registrations.",
			"MASVS-NETWORK-1 / CWE-319: a MITM attacker on http:// can inject arbitrary JavaScript that communicates with any registered native bridge handler."
		]
	};
}

/** CHECK 25: Universal Links configured — verify AASA served over HTTPS. MASVS-PLATFORM-3 */
function checkUniversalLinkConfig(ctx: ScanContext): Finding | null {
	const APPLINKS_RE = /applinks:|webcredentials:|NSUserActivityTypes/;
	const allSources = new Map<string, string>([
		...ctx.allNativeSources,
		...new Map(ctx.infoPlistEntries)
	]);
	const files = filesWithMatch(allSources, APPLINKS_RE);
	if (files.length === 0) return null;
	return {
		id: "IOS_UNIVERSAL_LINK_CONFIG",
		title: "Universal Links configured — verify AASA served over HTTPS with restrictive path patterns (MASVS-PLATFORM-3)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(allSources, APPLINKS_RE),
		requiredActions: [
			"Ensure the apple-app-site-association (AASA) file is served over HTTPS with no redirects and a valid TLS certificate.",
			"Restrict path patterns in the AASA file — avoid catch-all paths like \"/*\"; use the most specific paths possible.",
			"Validate all incoming NSUserActivity URLs in application(_:continue:restorationHandler:) before acting on parameters.",
			"MASVS-PLATFORM-3 / CWE-939: over-broad AASA paths allow attackers to hijack deep links by serving a malicious AASA from a sibling domain."
		]
	};
}

/** CHECK 26: React Native AsyncStorage used for sensitive data. MASVS-STORAGE-1 */
async function checkRnAsyncStorageSensitive(): Promise<Finding | null> {
	const JS_EXTENSIONS = ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"];
	const jsIgnore = ["**/node_modules/**", "**/.git/**"];
	const jsSources = await readFileMap(JS_EXTENSIONS, jsIgnore);
	const ASYNC_STORAGE_RE = /AsyncStorage\.setItem\s*\([^,]*(?:token|password|secret|auth|key)/i;
	const files = filesWithMatch(jsSources, ASYNC_STORAGE_RE);
	if (files.length === 0) return null;
	return {
		id: "RN_ASYNC_STORAGE_SENSITIVE",
		title: "React Native AsyncStorage used for sensitive data — unencrypted, readable on rooted devices (MASVS-STORAGE-1)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(jsSources, ASYNC_STORAGE_RE),
		requiredActions: [
			"Replace AsyncStorage with react-native-keychain or @react-native-community/encrypted-storage for credential-class data.",
			"AsyncStorage is backed by unencrypted SQLite on Android and unencrypted files on iOS — readable on rooted/jailbroken devices.",
			"MASVS-STORAGE-1: tokens, passwords, and secrets must be stored in the platform keystore (iOS Keychain / Android Keystore)."
		]
	};
}

/** CHECK 27: React Native CodePush OTA without bundle signing. MASVS-RESILIENCE-3 */
async function checkCodePushIntegrity(): Promise<Finding | null> {
	const JS_EXTENSIONS = ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"];
	const jsIgnore = ["**/node_modules/**", "**/.git/**"];
	const jsSources = await readFileMap(JS_EXTENSIONS, jsIgnore);
	const CODEPUSH_RE = /CodePush\.sync|codePush\.sync|import.*code-push/i;
	const INTEGRITY_RE = /publicKey|mandatory.*true|rollbackRetryOptions/;
	const files = filesWithMatch(jsSources, CODEPUSH_RE).filter(
		(f) => !INTEGRITY_RE.test(jsSources.get(f) ?? "")
	);
	if (files.length === 0) return null;
	return {
		id: "RN_CODEPUSH_NO_INTEGRITY",
		title: "React Native CodePush OTA without bundle signing — compromised CDN deploys malicious JS (MASVS-RESILIENCE-3)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(jsSources, CODEPUSH_RE),
		requiredActions: [
			"Enable CodePush bundle signing: generate an RSA key pair and pass the public key via CodePushPublicKey in Info.plist.",
			"Set mandatory: true for critical security patches to prevent users from running outdated bundles.",
			"MASVS-RESILIENCE-3: without signing, a compromised or malicious CDN update can replace the entire JS bundle with attacker code."
		]
	};
}

/** CHECK 28: Expo AsyncStorage for credentials instead of SecureStore. MASVS-STORAGE-1 */
async function checkExpoAsyncStorage(): Promise<Finding | null> {
	const JS_EXTENSIONS = ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"];
	const jsIgnore = ["**/node_modules/**", "**/.git/**"];

	const pkgText = await readFileSafe("package.json").catch(() => "");
	if (!/"expo"/.test(pkgText)) return null;

	const jsSources = await readFileMap(JS_EXTENSIONS, jsIgnore);
	const ASYNC_SENSITIVE_RE = /AsyncStorage.*(?:token|secret|password|auth)/i;
	const SECURE_STORE_RE = /SecureStore\.setItemAsync/;
	const files = filesWithMatch(jsSources, ASYNC_SENSITIVE_RE).filter(
		(f) => !SECURE_STORE_RE.test(jsSources.get(f) ?? "")
	);
	if (files.length === 0) return null;
	return {
		id: "EXPO_ASYNC_STORAGE_SENSITIVE",
		title: "Expo AsyncStorage for credentials instead of SecureStore — not backed by iOS Keychain or Android Keystore (MASVS-STORAGE-1)",
		severity: "HIGH",
		files: files.slice(0, 10),
		evidence: evidenceLines(jsSources, ASYNC_SENSITIVE_RE),
		requiredActions: [
			"Replace AsyncStorage with expo-secure-store (SecureStore.setItemAsync) for all credential-class data.",
			"expo-secure-store uses iOS Keychain and Android Keystore under the hood — AsyncStorage uses unencrypted flat files.",
			"MASVS-STORAGE-1: secrets in AsyncStorage are trivially readable on jailbroken iOS or rooted Android devices."
		]
	};
}

/** CHECK 29: Certificate Transparency enforcement not configured. MASVS-NETWORK-2 */
function checkCertificateTransparency(ctx: ScanContext): Finding | null {
	const PINNING_RE = /didReceive.*challenge|TrustKit|ServerTrustManager|ServerTrustPolicy|pinnedCertificates|NSPinnedDomains/i;
	const hasPinning =
		filesWithMatch(ctx.allNativeSources, PINNING_RE).length > 0 ||
		ctx.infoPlistEntries.some(([, t]) => PINNING_RE.test(t));
	if (!hasPinning) return null;

	const CT_RE = /NSRequiresCertificateTransparency|certificateTransparencyEnabled|CTPolicy/;
	const hasCT =
		filesWithMatch(ctx.allNativeSources, CT_RE).length > 0 ||
		ctx.infoPlistEntries.some(([, t]) => CT_RE.test(t));
	if (hasCT) return null;
	return {
		id: "MOBILE_NO_CERT_TRANSPARENCY",
		title: "Certificate Transparency enforcement not configured — misissued CA certificates can MITM without appearing in CT logs (MASVS-NETWORK-2)",
		severity: "MEDIUM",
		requiredActions: [
			"Set NSRequiresCertificateTransparency to true in your ATS dictionary in Info.plist.",
			"When using TrustKit, set kTSKRequireCertificateTransparency: true in the TrustKit configuration.",
			"MASVS-NETWORK-2: without CT enforcement, a misissued certificate from any trusted CA can intercept TLS traffic without appearing in public CT logs."
		]
	};
}

// ── orchestrator ──────────────────────────────────────────────────────────────

export async function checkMobileIos(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const ctx = await loadContext();

		// Synchronous checks — push all ATS per-plist findings first
		findings.push(...checkAtsWeak(ctx));

		// Remaining checks return Finding | null
		const candidates: Array<Finding | null> = [
			checkBackupAllowed(ctx),
			checkKeychainWeakAccess(ctx),
			checkUserDefaultsSensitive(ctx),
			// checkLogSensitive is async — resolved separately below
			checkHardcodedSecret(ctx),
			checkBundleSecrets(ctx),
			checkWeakCrypto(ctx),
			checkArcDisabled(ctx),
			checkJailbreakDetectionMissing(ctx),
			checkCertPinningMissing(ctx),
			checkPasteboardSensitive(ctx),
			checkScreenshotUnprotected(ctx),
			checkWebviewJsBridge(ctx),
			checkUrlSchemeUnvalidated(ctx),
			checkBiometricWeak(ctx),
			checkBitcodeEnabled(ctx),
			checkDebugFlagProduction(ctx),
			checkCoreDataUnencrypted(ctx),
			checkNetworkLoggerProduction(ctx),
			checkNsTempDirSensitive(ctx),
			checkNsFileProtectionNone(ctx),
			checkAppStorageSensitive(ctx),
			checkSqliteUnencrypted(ctx),
			checkWkWebviewHttpLoad(ctx),
			checkUniversalLinkConfig(ctx),
			checkCertificateTransparency(ctx),
			await checkLogSensitive(ctx),
			await checkRnAsyncStorageSensitive(),
			await checkCodePushIntegrity(),
			await checkExpoAsyncStorage()
		];

		for (const c of candidates) {
			if (c !== null) findings.push(c);
		}
	} catch (err) {
		console.warn(
			"[checkMobileIos] Internal error:",
			sanitizeErrorMessage(err instanceof Error ? err.message : String(err))
		);
	}

	return findings;
}
