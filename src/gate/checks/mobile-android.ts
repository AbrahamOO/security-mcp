import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";
import { searchRepo } from "../../repo/search.js";

// ---------------------------------------------------------------------------
// File-discovery helpers
// ---------------------------------------------------------------------------

async function findManifests(): Promise<string[]> {
	return fg(["**/AndroidManifest.xml"], {
		dot: true,
		ignore: ["**/node_modules/**", "**/.git/**", "**/build/**", "**/dist/**"]
	});
}

async function findNetworkSecurityConfigs(): Promise<string[]> {
	return fg(["**/network_security_config.xml", "**/res/xml/network_security_config.xml"], {
		dot: true,
		ignore: ["**/node_modules/**", "**/.git/**", "**/build/**"]
	});
}

async function findSourceFiles(): Promise<string[]> {
	return fg(["**/*.kt", "**/*.java"], {
		dot: true,
		ignore: [
			"**/node_modules/**", "**/.git/**", "**/build/**",
			"**/dist/**", "**/test/**", "**/androidTest/**"
		]
	});
}

async function findGradleFiles(): Promise<string[]> {
	return fg(["**/build.gradle", "**/build.gradle.kts"], {
		dot: true,
		ignore: ["**/node_modules/**", "**/.git/**"]
	});
}

async function findStringResources(): Promise<string[]> {
	return fg(["**/res/values/strings.xml", "**/res/values*.xml"], {
		dot: true,
		ignore: ["**/node_modules/**", "**/.git/**", "**/build/**"]
	});
}

async function findProviderPathFiles(): Promise<string[]> {
	return fg(
		["**/res/xml/file_paths.xml", "**/res/xml/*_paths.xml", "**/res/xml/provider_paths.xml"],
		{ dot: true, ignore: ["**/node_modules/**", "**/.git/**", "**/build/**"] }
	);
}

// ---------------------------------------------------------------------------
// Text-search helpers
// ---------------------------------------------------------------------------

function grepLines(content: string, needle: string, limit = 10): string[] {
	const lower = needle.toLowerCase();
	return content
		.split("\n")
		.filter(l => l.toLowerCase().includes(lower))
		.slice(0, limit)
		.map(l => l.trim());
}

function grepLinesRe(content: string, re: RegExp, limit = 10): string[] {
	return content
		.split("\n")
		.filter(l => re.test(l))
		.slice(0, limit)
		.map(l => l.trim());
}

// ---------------------------------------------------------------------------
// Sub-checker: AndroidManifest.xml checks
// MASVS-RESILIENCE-2, MASVS-NETWORK-1, MASVS-STORAGE-2,
// MASVS-PLATFORM-1, MASVS-PLATFORM-3, MASVS-NETWORK-2
// ---------------------------------------------------------------------------

async function checkManifests(): Promise<Finding[]> {
	const findings: Finding[] = [];
	const manifests = await findManifests();

	for (const m of manifests) {
		const xml = await readFileSafe(m).catch(() => "");
		const lower = xml.toLowerCase();

		if (lower.includes('android:debuggable="true"')) {
			findings.push({
				id: "ANDROID_DEBUGGABLE",
				title: "Android app is debuggable in manifest",
				severity: "CRITICAL",
				files: [m],
				requiredActions: [
					'Remove android:debuggable="true" for release builds.',
					"Ensure signing configs and build variants enforce non-debuggable release artifacts."
				]
			});
		}

		if (lower.includes('android:usescleartexttraffic="true"')) {
			findings.push({
				id: "ANDROID_CLEARTEXT",
				title: "Android cleartext traffic allowed",
				severity: "CRITICAL",
				files: [m],
				requiredActions: [
					"Disable cleartext traffic. Enforce TLS 1.3.",
					"Use Network Security Config with strict domain allowlists if exceptions are required."
				]
			});
		}

		if (lower.includes('android:allowbackup="true"')) {
			findings.push({
				id: "ANDROID_BACKUP_ALLOWED",
				title: "Android allowBackup enabled — ADB backup can extract app data without root",
				severity: "HIGH",
				files: [m],
				evidence: grepLines(xml, 'allowBackup="true"'),
				requiredActions: [
					'Set android:allowBackup="false" in <application> unless full backup rules are defined.',
					"If selective backup is required, use android:fullBackupContent and exclude sensitive files.",
					"Review MASVS-STORAGE-2 for data backup guidance."
				]
			});
		}

		const exportedLines = collectExportedWithoutPermission(xml);
		if (exportedLines.length > 0) {
			findings.push({
				id: "ANDROID_EXPORTED_NO_PERMISSION",
				title: "Exported component(s) have no android:permission — unauthorized invocation possible",
				severity: "HIGH",
				files: [m],
				evidence: exportedLines.slice(0, 5),
				requiredActions: [
					"Add android:permission to every exported Activity, Service, Receiver, and Provider.",
					'Use a signature-level permission (android:protectionLevel="signature") for internal IPC.',
					"Audit all exported components against MASVS-PLATFORM-1 and OWASP M1."
				]
			});
		}

		const deepLinkEvidence = collectUnverifiedDeepLinks(xml);
		if (deepLinkEvidence.length > 0) {
			findings.push({
				id: "ANDROID_DEEPLINK_NO_VERIFY",
				title: 'Deep link intent-filter missing android:autoVerify="true" — App Links unverified',
				severity: "HIGH",
				files: [m],
				evidence: deepLinkEvidence.slice(0, 3),
				requiredActions: [
					'Add android:autoVerify="true" to all https-scheme intent-filters.',
					"Host a valid .well-known/assetlinks.json on the linked domain.",
					"Test verification with: adb shell pm get-app-links --user 0 <package>"
				]
			});
		}

		if (!/android:networkSecurityConfig\s*=/.test(xml)) {
			findings.push({
				id: "ANDROID_NSC_MISSING",
				title: "No networkSecurityConfig referenced in AndroidManifest — relying on platform defaults",
				severity: "HIGH",
				files: [m],
				requiredActions: [
					"Create res/xml/network_security_config.xml and reference it in <application> via android:networkSecurityConfig.",
					"Define base-config with cleartextTrafficPermitted=false and restrict trust anchors to the system store.",
					"See MASVS-NETWORK-2 for a compliant template."
				]
			});
		}
	}

	return findings;
}

function collectExportedWithoutPermission(xml: string): string[] {
	const re = /<(activity|service|receiver|provider)[^>]*android:exported\s*=\s*"true"[^>]*>/gi;
	const results: string[] = [];
	let m: RegExpExecArray | null;
	while ((m = re.exec(xml)) !== null) {
		if (!/android:permission\s*=/.test(m[0])) {
			results.push(m[0].slice(0, 200).trim());
		}
	}
	return results;
}

function collectUnverifiedDeepLinks(xml: string): string[] {
	const re = /<intent-filter[^>]*>[\s\S]*?<data[^>]*android:scheme\s*=\s*"https?"[^>]*>[\s\S]*?<\/intent-filter>/gi;
	const results: string[] = [];
	let m: RegExpExecArray | null;
	while ((m = re.exec(xml)) !== null) {
		if (!/android:autoVerify\s*=\s*"true"/i.test(m[0])) {
			results.push(m[0].slice(0, 200).trim());
		}
	}
	return results;
}

// ---------------------------------------------------------------------------
// Sub-checker: Network Security Config checks
// MASVS-NETWORK-2
// ---------------------------------------------------------------------------

/** Build NSC_WEAK evidence lines from an NSC XML string. Returns null if no weakness found. */
function nscWeakEvidence(xml: string): string[] | null {
	const hasCleartextDomain = /cleartexttrafficpermitted\s*=\s*"true"/i.test(xml);
	const hasUserCerts = /<certificates\s+src\s*=\s*"user"/i.test(xml);
	const hasSystemOnly = /<certificates\s+src\s*=\s*"system"\s*\/>/i.test(xml);
	const hasBroadTrust = /<trust-anchors>/i.test(xml) && !hasSystemOnly;

	if (!hasCleartextDomain && !hasUserCerts && !hasBroadTrust) return null;

	const evidence: string[] = [];
	if (hasCleartextDomain) evidence.push('cleartextTrafficPermitted="true" found in domain config');
	if (hasUserCerts) evidence.push('<certificates src="user"> trust anchor allows user-installed CAs');
	if (hasBroadTrust) evidence.push(...grepLines(xml, "<trust-anchors>", 3));
	return evidence;
}

/** Returns a CERT_PINNING_MISSING finding for `nsc` if no pinning is detected anywhere. */
async function checkNscPinning(nsc: string, xml: string): Promise<Finding | null> {
	if (xml.toLowerCase().includes("<pin-set")) return null;

	const [okHttp, trustKit] = await Promise.all([
		searchRepo({ query: "CertificatePinner", isRegex: false, maxMatches: 3 }),
		searchRepo({ query: "TrustKit", isRegex: false, maxMatches: 3 })
	]);
	if (okHttp.length > 0 || trustKit.length > 0) return null;

	return {
		id: "ANDROID_CERT_PINNING_MISSING",
		title: "No certificate pinning found in NSC or OkHttp/TrustKit",
		severity: "HIGH",
		files: [nsc],
		requiredActions: [
			"Add a <pin-set> to network_security_config.xml for production domains, or",
			"Configure OkHttp CertificatePinner / TrustKit for high-risk API endpoints.",
			"Include backup pins and a rotation plan. See MASVS-NETWORK-2."
		]
	};
}

async function checkNetworkSecurityConfig(): Promise<Finding[]> {
	const findings: Finding[] = [];

	for (const nsc of await findNetworkSecurityConfigs()) {
		const xml = await readFileSafe(nsc).catch(() => "");
		if (!xml) continue;

		const weakEvidence = nscWeakEvidence(xml);
		if (weakEvidence !== null) {
			findings.push({
				id: "ANDROID_NSC_WEAK",
				title: "Network Security Config has weakened trust settings (user CAs or domain cleartext)",
				severity: "CRITICAL",
				files: [nsc],
				evidence: weakEvidence,
				requiredActions: [
					'Remove <certificates src="user"> trust anchors — they allow MITM by any user-installed CA.',
					'Remove domain-level cleartextTrafficPermitted="true" entries.',
					"Restrict <base-config> to system CAs only and enforce TLS globally.",
					"Reference MASVS-NETWORK-2 and OWASP M3."
				]
			});
		}

		const pinFinding = await checkNscPinning(nsc, xml);
		if (pinFinding !== null) findings.push(pinFinding);
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Source-file scan helpers — each returns { files, evidence } for one check
// ---------------------------------------------------------------------------

type SourceAccumulator = { files: string[]; evidence: string[] };

function newAccumulator(): SourceAccumulator {
	return { files: [], evidence: [] };
}

function recordHit(acc: SourceAccumulator, src: string, lines: string[]): void {
	acc.files.push(src);
	acc.evidence.push(...lines.map(l => `${src}: ${l}`));
}

function scanWebviewJsi(code: string, src: string, acc: SourceAccumulator): void {
	if (!code.includes("addJavascriptInterface")) return;
	recordHit(acc, src, grepLines(code, "addJavascriptInterface", 5));
}

function scanWebviewJs(code: string, src: string, acc: SourceAccumulator): void {
	if (!code.includes("setJavaScriptEnabled(true)")) return;
	if (code.includes("setSaveFormData(false)") && code.includes("setSavePassword(false)")) return;
	recordHit(acc, src, grepLines(code, "setJavaScriptEnabled", 3));
}

function scanSharedPrefs(code: string, src: string, acc: SourceAccumulator, sensitiveNeedles: string[]): void {
	if (!code.includes("getSharedPreferences") && !code.includes("defaultSharedPreferences")) return;
	if (code.includes("EncryptedSharedPreferences")) return;

	const spLines = grepLinesRe(code, /getSharedPreferences|defaultSharedPreferences/i, 20);
	const sensitiveLinesNear = spLines.some(l => sensitiveNeedles.some(n => l.toLowerCase().includes(n)));

	const codeLower = code.toLowerCase();
	const idx = codeLower.indexOf("getsharedpreferences");
	const windowText = idx === -1 ? "" : codeLower.slice(Math.max(0, idx - 300), idx + 300);
	const hasSensitiveNearby = sensitiveNeedles.some(n => windowText.includes(n));

	if (sensitiveLinesNear || hasSensitiveNearby) {
		recordHit(acc, src, grepLines(code, "getSharedPreferences", 3));
	}
}

function scanLogcat(code: string, src: string, acc: SourceAccumulator, sensitiveNeedles: string[]): void {
	const logRe = /Log\s*\.\s*[diwve]\s*\(.*?(password|token|secret|apikey|credential)/i;
	if (!logRe.test(code)) return;
	const lines = grepLinesRe(code, /Log\s*\.\s*[diwve]/i, 5)
		.filter(l => sensitiveNeedles.some(n => l.toLowerCase().includes(n)));
	if (lines.length > 0) recordHit(acc, src, lines);
}

function scanHardcodedSecret(code: string, src: string, acc: SourceAccumulator): void {
	const re = /(apiKey|api_key|secret|password|token)\s*[=:]\s*["'][^"']{8,}/i;
	if (!re.test(code)) return;
	const lines = grepLinesRe(code, re, 5);
	if (lines.length > 0) recordHit(acc, src, lines);
}

function scanRawQuery(code: string, src: string, acc: SourceAccumulator): void {
	if (!/rawQuery|execSQL/.test(code)) return;
	if (!/rawQuery.*\+|execSQL.*\+/.test(code)) return;
	recordHit(acc, src, grepLinesRe(code, /rawQuery.*\+|execSQL.*\+/, 5));
}

function scanImplicitIntent(code: string, src: string, acc: SourceAccumulator): void {
	const re = /new\s+Intent\s*\(\s*["'][^"']+["']\s*\)/i;
	if (!re.test(code)) return;
	recordHit(acc, src, grepLinesRe(code, re, 5));
}

function scanPendingIntentMutable(code: string, src: string, acc: SourceAccumulator): void {
	if (!code.includes("FLAG_MUTABLE")) return;
	recordHit(acc, src, grepLines(code, "FLAG_MUTABLE", 5));
}

function scanExternalStorage(code: string, src: string, acc: SourceAccumulator): void {
	if (!/getExternalStorageDirectory|getExternalFilesDir/.test(code)) return;
	recordHit(acc, src, grepLinesRe(code, /getExternalStorageDirectory|getExternalFilesDir/, 5));
}

function scanBiometricWeak(code: string, src: string, acc: SourceAccumulator): void {
	if (!code.includes("BiometricPrompt")) return;
	if (code.includes("CryptoObject")) return;
	recordHit(acc, src, grepLines(code, "BiometricPrompt", 3));
}

// ---------------------------------------------------------------------------
// Sub-checker: Kotlin/Java source checks
// ---------------------------------------------------------------------------

type SourceAccumulators = {
	jsi: SourceAccumulator;
	jsEnabled: SourceAccumulator;
	sharedPrefs: SourceAccumulator;
	logcat: SourceAccumulator;
	hardcoded: SourceAccumulator;
	rawQuery: SourceAccumulator;
	implicitIntent: SourceAccumulator;
	pendingIntent: SourceAccumulator;
	externalStorage: SourceAccumulator;
	biometric: SourceAccumulator;
	billingFiles: string[];
};

function emitSourceFindings(accs: SourceAccumulators): Finding[] {
	const { jsi, jsEnabled, sharedPrefs, logcat, hardcoded, rawQuery, implicitIntent, pendingIntent, externalStorage, biometric } = accs;
	const findings: Finding[] = [];

	const push = (f: Finding) => findings.push(f);
	const files = (acc: SourceAccumulator) => [...new Set(acc.files)];
	const ev = (acc: SourceAccumulator) => acc.evidence.slice(0, 8);

	if (jsi.files.length > 0) push({ id: "ANDROID_WEBVIEW_JS_INTERFACE", title: "addJavascriptInterface exposes Java methods to WebView JavaScript", severity: "CRITICAL", files: files(jsi), evidence: ev(jsi), requiredActions: ["Remove addJavascriptInterface unless the WebView loads only trusted, local content.", "If required, annotate only the specific methods with @JavascriptInterface and validate all inputs.", "Ensure minSdkVersion >= 17 where the annotation is the attack-surface gate.", "See MASVS-PLATFORM-7 and OWASP M1."] });
	if (jsEnabled.files.length > 0) push({ id: "ANDROID_WEBVIEW_JS_ENABLED", title: "WebView has JavaScript enabled without full hardening (setSaveFormData/setSavePassword false)", severity: "HIGH", files: files(jsEnabled), evidence: ev(jsEnabled), requiredActions: ["Call setSaveFormData(false) and setSavePassword(false) wherever setJavaScriptEnabled(true) is called.", "Also set setAllowFileAccessFromFileURLs(false) and setAllowUniversalAccessFromFileURLs(false).", "Load only HTTPS content and validate URLs before loading. See MASVS-PLATFORM-7."] });
	if (sharedPrefs.files.length > 0) push({ id: "ANDROID_SHARED_PREFS_SENSITIVE", title: "Sensitive data (password/token/secret) stored in unencrypted SharedPreferences", severity: "HIGH", files: files(sharedPrefs), evidence: ev(sharedPrefs), requiredActions: ["Replace SharedPreferences with EncryptedSharedPreferences (Jetpack Security) for all secrets.", "Never store passwords, tokens, or private keys in plaintext on-device.", "See MASVS-STORAGE-1 and OWASP M2."] });
	if (logcat.files.length > 0) push({ id: "ANDROID_LOGCAT_SENSITIVE", title: "Sensitive data (password/token/secret) logged via Logcat", severity: "HIGH", files: files(logcat), evidence: ev(logcat), requiredActions: ["Remove all Log.d/i/w/e/v calls that include passwords, tokens, or secrets.", "In ProGuard/R8 rules, strip all Log calls for release builds as a safety net.", "See MASVS-RESILIENCE-3 and OWASP M2."] });
	if (hardcoded.files.length > 0) push({ id: "ANDROID_HARDCODED_SECRET", title: "Hardcoded API key / secret / password found in Kotlin/Java source", severity: "CRITICAL", files: files(hardcoded), evidence: ev(hardcoded), requiredActions: ["Remove hardcoded credentials immediately. Rotate any exposed keys.", "Load secrets at runtime from a secure backend or Android Keystore.", "For CI, inject secrets via environment variables — never commit them to source control.", "See MASVS-STORAGE-14 and OWASP M9."] });
	if (rawQuery.files.length > 0) push({ id: "ANDROID_SQL_RAW_QUERY", title: "rawQuery / execSQL called with string concatenation — potential SQLite injection", severity: "HIGH", files: files(rawQuery), evidence: ev(rawQuery), requiredActions: ["Replace string-concatenated queries with parameterized placeholders (rawQuery(sql, selectionArgs)).", "Prefer Room DAO @Query methods which enforce parameterization by default.", "See MASVS-CODE-4 and CWE-89."] });
	if (implicitIntent.files.length > 0) push({ id: "ANDROID_INTENT_IMPLICIT", title: "Implicit Intent detected — may be intercepted by a malicious app", severity: "HIGH", files: files(implicitIntent), evidence: ev(implicitIntent), requiredActions: ["Use explicit intents (specifying target class or ComponentName) for intra-app communication.", "If broadcasting, use LocalBroadcastManager or sendBroadcast with permissions.", "See MASVS-PLATFORM-2 and OWASP M1."] });
	if (pendingIntent.files.length > 0) push({ id: "ANDROID_PENDING_INTENT_MUTABLE", title: "PendingIntent.FLAG_MUTABLE used — wrapped Intent can be modified by third-party apps", severity: "HIGH", files: files(pendingIntent), evidence: ev(pendingIntent), requiredActions: ["Prefer FLAG_IMMUTABLE for PendingIntents unless the wrapped Intent must be filled in by another app.", "If FLAG_MUTABLE is truly required, use explicit Intents inside the PendingIntent and validate all Intent fields on receipt.", "See Android documentation on PendingIntent mutability and MASVS-PLATFORM-2."] });
	if (externalStorage.files.length > 0) push({ id: "ANDROID_EXTERNAL_STORAGE", title: "Sensitive data potentially written to world-readable external storage", severity: "HIGH", files: files(externalStorage), evidence: ev(externalStorage), requiredActions: ["Write sensitive data only to internal storage (filesDir, cacheDir) or Android Keystore-backed encrypted files.", "If external storage is necessary, encrypt the data before writing using Jetpack Security.", "See MASVS-STORAGE-2 and OWASP M2."] });
	if (biometric.files.length > 0) push({ id: "ANDROID_BIOMETRIC_WEAK", title: "BiometricPrompt used without CryptoObject — authentication result not bound to a key", severity: "MEDIUM", files: files(biometric), evidence: ev(biometric), requiredActions: ["Pass a CryptoObject backed by an Android Keystore key (KeyPermanentlyInvalidatedException aware) to BiometricPrompt.authenticate().", "This ensures the cryptographic operation only succeeds on genuine biometric confirmation.", "See MASVS-AUTH-2 and Android BiometricPrompt best practices."] });

	return findings;
}

async function checkBillingClientOnly(billingFiles: string[]): Promise<Finding | null> {
	if (billingFiles.length === 0) return null;
	const matches = await searchRepo({ query: "purchaseToken", isRegex: false, maxMatches: 5 });
	const hasServerEndpoint = matches.some(r =>
		/retrofit|okhttp|httpurlconnection|volley|ktor|api|endpoint|server/i.test(r.preview)
	);
	if (hasServerEndpoint) return null;
	return {
		id: "ANDROID_IN_APP_PURCHASE_CLIENT_ONLY",
		title: "BillingClient detected but no server-side purchase validation found",
		severity: "HIGH",
		files: billingFiles,
		requiredActions: [
			"Validate every purchase server-side using the Google Play Developer API (/purchases/products or /purchases/subscriptions).",
			"Pass the purchaseToken and productId to your backend — never trust client-only verification.",
			"See MASVS-RESILIENCE-3 and Google Play billing best practices."
		]
	};
}

async function checkSourceFiles(): Promise<Finding[]> {
	const sensitiveNeedles = ["password", "token", "secret", "apikey", "api_key", "credential", "auth_token"];

	const accs: SourceAccumulators = {
		jsi: newAccumulator(),
		jsEnabled: newAccumulator(),
		sharedPrefs: newAccumulator(),
		logcat: newAccumulator(),
		hardcoded: newAccumulator(),
		rawQuery: newAccumulator(),
		implicitIntent: newAccumulator(),
		pendingIntent: newAccumulator(),
		externalStorage: newAccumulator(),
		biometric: newAccumulator(),
		billingFiles: []
	};

	for (const src of await findSourceFiles()) {
		const code = await readFileSafe(src).catch(() => "");
		if (!code) continue;

		scanWebviewJsi(code, src, accs.jsi);
		scanWebviewJs(code, src, accs.jsEnabled);
		scanSharedPrefs(code, src, accs.sharedPrefs, sensitiveNeedles);
		scanLogcat(code, src, accs.logcat, sensitiveNeedles);
		scanHardcodedSecret(code, src, accs.hardcoded);
		scanRawQuery(code, src, accs.rawQuery);
		scanImplicitIntent(code, src, accs.implicitIntent);
		scanPendingIntentMutable(code, src, accs.pendingIntent);
		scanExternalStorage(code, src, accs.externalStorage);
		scanBiometricWeak(code, src, accs.biometric);
		if (code.includes("BillingClient")) accs.billingFiles.push(src);
	}

	const findings = emitSourceFindings(accs);
	const billingFinding = await checkBillingClientOnly(accs.billingFiles);
	if (billingFinding !== null) findings.push(billingFinding);
	return findings;
}

// ---------------------------------------------------------------------------
// Sub-checker: Android string resource checks
// MASVS-STORAGE-14
// ---------------------------------------------------------------------------

async function checkStringResources(existingFindings: Finding[]): Promise<Finding[]> {
	const findings: Finding[] = [];
	const resFiles: string[] = [];
	const resEvidence: string[] = [];
	const secretResRe = /name\s*=\s*["'](apiKey|api_key|secret|password|token|auth_token|client_secret)['"]/i;

	for (const res of await findStringResources()) {
		const xml = await readFileSafe(res).catch(() => "");
		if (!xml || !secretResRe.test(xml)) continue;
		resFiles.push(res);
		resEvidence.push(...grepLinesRe(xml, secretResRe, 5).map(l => `${res}: ${l}`));
	}

	if (resFiles.length === 0) return findings;

	const existing = existingFindings.find(f => f.id === "ANDROID_HARDCODED_SECRET");
	if (existing) {
		existing.files = [...new Set([...(existing.files ?? []), ...resFiles])];
		existing.evidence = [...(existing.evidence ?? []), ...resEvidence.slice(0, 4)];
	} else {
		findings.push({
			id: "ANDROID_HARDCODED_SECRET",
			title: "Hardcoded API key / secret / password found in Android string resources",
			severity: "CRITICAL",
			files: resFiles,
			evidence: resEvidence.slice(0, 8),
			requiredActions: [
				"Remove secret values from strings.xml and all resource files.",
				"Inject secrets at runtime from a secure backend — never bundle them in the APK.",
				"Rotate any credentials that may have been committed. See MASVS-STORAGE-14."
			]
		});
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Sub-checker: FileProvider path checks + tapjacking
// MASVS-PLATFORM-1, MASVS-PLATFORM-4
// ---------------------------------------------------------------------------

async function checkProviderPathsAndTapjacking(hasManifests: boolean): Promise<Finding[]> {
	const findings: Finding[] = [];

	for (const pp of await findProviderPathFiles()) {
		const xml = await readFileSafe(pp).catch(() => "");
		if (!xml) continue;

		const hasRootPath = /<root-path/i.test(xml);
		const hasOverbroad =
			/<external-path[^>]*path\s*=\s*["']\.?["']/i.test(xml) ||
			/<files-path[^>]*path\s*=\s*["']\.?["']/i.test(xml);

		if (!hasRootPath && !hasOverbroad) continue;

		const evidence: string[] = [];
		if (hasRootPath) evidence.push(...grepLines(xml, "<root-path", 3));
		if (hasOverbroad) evidence.push(...grepLinesRe(xml, /<external-path|<files-path/, 3));

		findings.push({
			id: "ANDROID_CONTENT_PROVIDER_PATHS",
			title: 'FileProvider path config uses <root-path> or overly broad path — filesystem over-exposure',
			severity: "HIGH",
			files: [pp],
			evidence,
			requiredActions: [
				"Replace <root-path> with the narrowest applicable path element (<files-path>, <cache-path>, etc.).",
				'Set path to a specific subdirectory, not "." or empty.',
				"Review every <external-path> declaration and limit scope to the minimum required directory.",
				"See FileProvider documentation and MASVS-PLATFORM-1."
			]
		});
	}

	if (hasManifests) {
		const tapjacking = await searchRepo({ query: "filterTouchesWhenObscured", isRegex: false, maxMatches: 5 });
		if (tapjacking.length === 0) {
			findings.push({
				id: "ANDROID_TAPJACKING",
				title: "No filterTouchesWhenObscured protection found — sensitive views may be vulnerable to tapjacking",
				severity: "MEDIUM",
				requiredActions: [
					'Set filterTouchesWhenObscured="true" on sensitive Views (password fields, payment screens, permission dialogs).',
					"Call setFilterTouchesWhenObscured(true) programmatically for dynamically inflated views.",
					"See Android View security documentation and MASVS-PLATFORM-4."
				]
			});
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Sub-checker: Gradle SDK version checks
// MASVS-RESILIENCE-1
// ---------------------------------------------------------------------------

async function checkGradleSdkVersions(): Promise<Finding[]> {
	const findings: Finding[] = [];

	for (const gradle of await findGradleFiles()) {
		const text = await readFileSafe(gradle).catch(() => "");
		if (!text) continue;

		const minSdkMatch = /minSdkVersion\s*[=:]\s*(\d+)/i.exec(text);
		if (minSdkMatch) {
			const minSdk = Number.parseInt(minSdkMatch[1], 10);
			if (minSdk < 21) {
				findings.push({
					id: "ANDROID_MIN_SDK_LOW",
					title: `minSdkVersion ${minSdk} is critically low — missing FBE, modern TLS, and Keystore features`,
					severity: "HIGH",
					files: [gradle],
					evidence: [`minSdkVersion = ${minSdk}`],
					requiredActions: [
						"Raise minSdkVersion to at least 24 (Android 7.0) to gain per-file encryption and TLS 1.3.",
						"Target 28+ for all cleartext-traffic restrictions to apply by default.",
						"Check Google Play distribution data — very few active devices run below API 21."
					]
				});
			} else if (minSdk < 24) {
				findings.push({
					id: "ANDROID_MIN_SDK_LOW",
					title: `minSdkVersion ${minSdk} is below 24 — app runs on devices missing key security features`,
					severity: "MEDIUM",
					files: [gradle],
					evidence: [`minSdkVersion = ${minSdk}`],
					requiredActions: [
						"Consider raising minSdkVersion to 24 (Android 7.0) for TLS 1.3 and improved Keystore guarantees.",
						"At minimum ensure your network_security_config.xml enforces TLS regardless of platform defaults.",
						"See MASVS-RESILIENCE-1 for minimum SDK guidance."
					]
				});
			}
		}

		const targetSdkMatch = /targetSdkVersion\s*[=:]\s*(\d+)/i.exec(text);
		if (targetSdkMatch) {
			const targetSdk = Number.parseInt(targetSdkMatch[1], 10);
			if (targetSdk < 33) {
				findings.push({
					id: "ANDROID_TARGET_SDK_OLD",
					title: `targetSdkVersion ${targetSdk} is below 33 — modern permission model and scoped storage not enforced`,
					severity: "HIGH",
					files: [gradle],
					evidence: [`targetSdkVersion = ${targetSdk}`],
					requiredActions: [
						"Raise targetSdkVersion to 34 (Android 14) or the current Google Play requirement.",
						"Review and adapt code for scoped storage, exact alarm permissions, and foreground service types.",
						"Google Play requires targetSdkVersion >= 33 for new app submissions as of 2023.",
						"See MASVS-RESILIENCE-1 and Android target API level requirements."
					]
				});
			}
		}
	}

	return findings;
}

// ---------------------------------------------------------------------------
// Orchestrator — runs all sub-checkers and merges results
// ---------------------------------------------------------------------------

export async function checkMobileAndroid(_: { changedFiles: string[] }): Promise<Finding[]> {
	const [manifestFindings, nscFindings, sourceFindings, providerFindings, gradleFindings] =
		await Promise.all([
			checkManifests(),
			checkNetworkSecurityConfig(),
			checkSourceFiles(),
			checkProviderPathsAndTapjacking(true),
			checkGradleSdkVersions()
		]);

	const findings = [...manifestFindings, ...nscFindings, ...sourceFindings, ...providerFindings, ...gradleFindings];

	// String resource check may augment the ANDROID_HARDCODED_SECRET finding already in the list
	const resFindings = await checkStringResources(findings);
	findings.push(...resFindings);

	return findings;
}
