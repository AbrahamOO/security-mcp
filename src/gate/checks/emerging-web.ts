/**
 * Emerging web / API framework vulnerability detections (2025 wave).
 *
 * This module encodes signatures for a set of recently-disclosed, high-impact
 * web-framework CVEs and one long-standing web class (JWT key-URL SSRF). Each
 * rule is self-contained and defensive: a malformed manifest, lockfile, or
 * source file must never throw or abort the whole gate run, so every rule body
 * is wrapped in try/catch and every parse is guarded.
 *
 * Two detection strategies are combined:
 *   1. Pattern matching over source via searchRepo (tight regexes, low FP).
 *   2. Dependency version gating: we read the ecosystem manifest
 *      (package.json / requirements*.txt / pyproject.toml / *.csproj) with
 *      fast-glob + readFileSafe and compare the declared version against the
 *      known-patched version using a small, dependency-free semver comparator.
 *
 * Version-gating principle (to avoid false CRITICALs): if we CANNOT resolve a
 * concrete version (range specifier we can't pin, missing file, unparseable
 * value), we DOWNGRADE to a MEDIUM "review" finding rather than assert a
 * CRITICAL. A confident CRITICAL is only emitted when a concrete, parseable
 * version is provably below the patched threshold.
 *
 * Rule IDs implemented:
 *   - WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS   (CVE-2025-29927, CWE-285)
 *   - WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED (companion, CWE-285)
 *   - WEB_RSC_FLIGHT_DESERIALIZATION_RCE  (CVE-2025-55182, CWE-502)
 *   - WEB_DJANGO_ORM_CONNECTOR_SQLI       (CVE-2025-64459, CWE-89)
 *   - WEB_KESTREL_CHUNKED_SMUGGLING       (CVE-2025-55315, CWE-444)
 *   - WEB_JWT_JKU_X5U_SSRF                 (CWE-918)
 *   - WEB_PATH_TO_REGEXP_REDOS            (CWE-1333)
 *
 * CWE references per the MITRE CWE catalog.
 */
import { Finding, sanitizeErrorMessage } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

type Hit = { file: string; line: number; preview: string };

function toEvidence(hits: Hit[]): string[] {
	return hits.slice(0, 10).map((m) => `${m.file}:${m.line}:${m.preview}`);
}
function toFiles(hits: Hit[]): string[] {
	return [...new Set(hits.slice(0, 10).map((m) => m.file))];
}

// ---------------------------------------------------------------------------
// Dependency-free semver comparison helper.
//
// We deliberately avoid pulling in the `semver` package: the scanner must be
// able to reason about versions without adding a runtime dependency (and
// without expanding its own supply-chain surface). This comparator handles the
// subset of semver we actually need: dotted numeric releases with an optional
// pre-release tag. Build metadata and complex pre-release ordering are not
// required for the "is this below the patched release" question we ask here.
// ---------------------------------------------------------------------------

/**
 * Extract a concrete, comparable version string from a manifest value.
 *
 * Manifest values are messy: "^14.2.0", "~5.2.0", ">=4.2,<5.0", "19.0.0-rc.1",
 * "next" (a dist-tag), "*", "workspace:*". We can only make a confident
 * below-threshold assertion when a single concrete version is present. This
 * strips a SINGLE leading range operator (^ ~ >= <= > < =) and returns the
 * pinned version; if the spec is a wildcard, dist-tag, URL, or a compound range
 * we cannot collapse to one number, we return null so the caller downgrades to
 * a MEDIUM review finding instead of a false CRITICAL.
 */
function resolveConcreteVersion(spec: string): string | null {
	if (typeof spec !== "string") return null;
	const trimmed = spec.trim();
	if (!trimmed) return null;

	// Reject anything that is clearly not a single pinned semver: wildcards,
	// dist-tags (latest/next/canary), git/file/URL specs, or compound ranges
	// (containing a comma, "||", or a whitespace-separated second constraint).
	if (/^[*x]$/i.test(trimmed)) return null;
	if (/(?:git\+|file:|https?:|workspace:|link:|npm:)/i.test(trimmed)) return null;
	if (/[,|]|\s/.test(trimmed)) return null;
	if (/^(?:latest|next|canary|beta|alpha|rc|nightly)$/i.test(trimmed)) return null;

	// Strip a single leading range operator, then require a numeric release.
	const stripped = trimmed.replace(/^(?:\^|~|>=|<=|>|<|=|v)/, "");
	const m = /^(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|\d+\.\d+|\d+)$/.exec(stripped);
	return m ? m[1] : null;
}

/**
 * Split a version into numeric release components plus an optional pre-release
 * tag. "19.0.0-rc.1" -> { nums: [19,0,0], pre: "rc.1" }. Missing components
 * default to 0 so "14.2" compares as "14.2.0".
 */
function parseVersion(v: string): { nums: number[]; pre: string | null } | null {
	const clean = v.trim().replace(/^v/i, "");
	const [core, pre] = clean.split(/[-+]/, 2);
	const parts = core.split(".");
	if (parts.length === 0) return null;
	const nums: number[] = [];
	for (let i = 0; i < 3; i++) {
		const n = Number.parseInt(parts[i] ?? "0", 10);
		if (Number.isNaN(n)) return null;
		nums.push(n);
	}
	return { nums, pre: pre ?? null };
}

/**
 * Compare two versions. Returns <0 if a<b, 0 if equal, >0 if a>b, or null if
 * either is unparseable (caller treats null as "cannot resolve" and downgrades).
 * A version WITH a pre-release tag sorts BELOW the same version without one
 * (e.g. 19.0.0-rc.1 < 19.0.0), matching semver precedence.
 */
function compareVersions(a: string, b: string): number | null {
	const pa = parseVersion(a);
	const pb = parseVersion(b);
	if (!pa || !pb) return null;
	for (let i = 0; i < 3; i++) {
		if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] - pb.nums[i];
	}
	// Equal numeric core: a pre-release is lower than a release.
	if (pa.pre && !pb.pre) return -1;
	if (!pa.pre && pb.pre) return 1;
	if (pa.pre && pb.pre) return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
	return 0;
}

/** Strict "is `version` older than `patched`" that returns false when unknown. */
function isBelow(version: string, patched: string): boolean {
	const c = compareVersions(version, patched);
	return c !== null && c < 0;
}

/**
 * A package can be vulnerable if it is below the patch on its OWN major line.
 * Frameworks like Next.js backport a fix to several supported majors, so a repo
 * on 13.x is safe at 13.5.9 but a repo on 14.x needs 14.2.25. We pick the
 * patched threshold whose major matches the installed major; if the installed
 * major is newer than every listed threshold it is considered patched, and if
 * older than every listed major it is considered vulnerable.
 */
function isBelowMajorAwareThresholds(version: string, patchedByMajor: string[]): boolean {
	const parsed = parseVersion(version);
	if (!parsed) return false;
	const installedMajor = parsed.nums[0];

	let bestSameMajor: string | null = null;
	let maxListedMajor = -1;
	for (const p of patchedByMajor) {
		const pp = parseVersion(p);
		if (!pp) continue;
		maxListedMajor = Math.max(maxListedMajor, pp.nums[0]);
		if (pp.nums[0] === installedMajor) bestSameMajor = p;
	}

	if (bestSameMajor) return isBelow(version, bestSameMajor);
	// No threshold for this major: if newer than everything listed → patched;
	// if older than everything listed → vulnerable.
	return installedMajor < maxListedMajor;
}

// ---------------------------------------------------------------------------
// Manifest readers (defensive — return {} / [] on any failure).
// ---------------------------------------------------------------------------

/** Read the first package.json and return the merged dependency map. */
async function readPackageJsonDeps(): Promise<{
	deps: Record<string, string>;
	file: string | null;
}> {
	try {
		const files = await fg(["package.json", "**/package.json"], { dot: true });
		if (files.length === 0) return { deps: {}, file: null };
		const raw = await readFileSafe(files[0]);
		const pkg = JSON.parse(raw) as {
			dependencies?: Record<string, string>;
			devDependencies?: Record<string, string>;
		};
		return {
			deps: { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) },
			file: files[0]
		};
	} catch {
		return { deps: {}, file: null };
	}
}

// ---------------------------------------------------------------------------
// 1. WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS — CVE-2025-29927, CWE-285.
//
// What it is (plain language): Next.js decided whether a request had already
// been processed by middleware by trusting an internal HTTP header,
// `x-middleware-subrequest`. Because that header is attacker-controllable from
// outside, an attacker can add it to a request and Next.js SKIPS the middleware
// entirely — including any authentication/authorization performed there. If
// your login/redirect logic lives in `middleware.ts`, an attacker walks past it.
//
// Why the pattern matches: we require BOTH a vulnerable `next` version in the
// manifest AND a middleware file that actually performs auth (redirect / rewrite
// / NextResponse / session), because the bypass only matters when middleware is
// the auth gate. Patched releases: 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.
// ---------------------------------------------------------------------------
async function checkNextjsMiddlewareAuthBypass(
	nextSpec: string | undefined,
	pkgFile: string | null
): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		if (nextSpec === undefined) return findings;

		// Does a middleware file exist that performs auth?
		const middlewareFiles = await fg(
			["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js", "**/middleware.{ts,js}"],
			{ dot: true }
		);
		if (middlewareFiles.length === 0) return findings;

		// Confirm the middleware actually gates requests (auth-shaped behaviour).
		const authInMiddleware = await searchRepo({
			query: String.raw`NextResponse\.(?:redirect|rewrite)|\breturn\s+NextResponse\b|getToken\(|getServerSession\(|\bsession\b|\bauth(?:orize|enticate)?\b|requireAuth|isAuthenticated`,
			isRegex: true,
			maxMatches: 200
		});
		const authHits = authInMiddleware.filter((h) => /middleware\.(?:ts|js)$/.test(h.file));
		if (authHits.length === 0) return findings;

		const PATCHED = ["12.3.5", "13.5.9", "14.2.25", "15.2.3"];
		const concrete = resolveConcreteVersion(nextSpec);

		if (concrete === null) {
			// Version could not be pinned (range/dist-tag) — downgrade to review.
			findings.push({
				id: "WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS",
				title: "Next.js middleware performs auth but the `next` version cannot be confirmed patched for CVE-2025-29927 (middleware auth bypass) — review",
				severity: "MEDIUM",
				evidence: [`${pkgFile ?? "package.json"}: next -> "${nextSpec}" (unresolvable)`, ...toEvidence(authHits)],
				files: [...(pkgFile ? [pkgFile] : []), ...toFiles(authHits)],
				requiredActions: [
					"Pin `next` to a concrete version and confirm it is >= 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 for your major line (CVE-2025-29927).",
					"Do not rely on middleware alone for authorization — enforce authz in the route/handler as well, so a skipped middleware cannot expose data.",
					"At the edge/proxy, strip the `x-middleware-subrequest` request header from all inbound traffic."
				]
			});
			return findings;
		}

		if (isBelowMajorAwareThresholds(concrete, PATCHED)) {
			findings.push({
				id: "WEB_NEXTJS_MIDDLEWARE_AUTH_BYPASS",
				title: "Vulnerable Next.js version with auth in middleware — CVE-2025-29927 middleware authorization bypass via x-middleware-subrequest (CWE-285)",
				severity: "CRITICAL",
				sla: "24h",
				evidence: [`${pkgFile ?? "package.json"}: next -> "${nextSpec}" (concrete ${concrete}, below patched line)`, ...toEvidence(authHits)],
				files: [...(pkgFile ? [pkgFile] : []), ...toFiles(authHits)],
				requiredActions: [
					"Upgrade `next` immediately to a patched release: >= 12.3.5, 13.5.9, 14.2.25, or 15.2.3 for your major line (CVE-2025-29927).",
					"An attacker can send the internal `x-middleware-subrequest` header to make Next.js skip middleware entirely, bypassing any auth performed there (CWE-285).",
					"Defence in depth: also enforce authorization inside route handlers/server actions, and strip `x-middleware-subrequest` at the reverse proxy."
				]
			});
		}
	} catch (err) {
		console.warn("[checkNextjsMiddlewareAuthBypass] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

// ---------------------------------------------------------------------------
// 1b. Companion: reverse-proxy configs that do NOT strip x-middleware-subrequest.
//
// Even with a patched framework, a hardened edge that strips the internal
// `x-middleware-subrequest` header is the recommended belt-and-braces control.
// We flag nginx / *.conf proxy files that proxy upstream but never clear the
// header. LOW severity because it is a hardening gap, not a live exploit on its own.
// ---------------------------------------------------------------------------
async function checkProxyDoesNotStripMiddlewareHeader(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const proxyFiles = await fg(
			["**/*.conf", "**/nginx.conf", "**/nginx/**/*.conf", "**/default.conf"],
			{ dot: true }
		);
		if (proxyFiles.length === 0) return findings;

		// A proxy config is relevant only if it actually forwards requests upstream.
		const flagged: string[] = [];
		for (const file of proxyFiles) {
			let content = "";
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			const isProxy = /proxy_pass\s|proxy_set_header/i.test(content);
			if (!isProxy) continue;
			// Header is considered stripped if the config clears it (empty value)
			// or explicitly rewrites it. Matching is case-insensitive since header
			// names are case-insensitive.
			const strips = /(?:proxy_set_header|more_clear_input_headers|proxy_hide_header)[^\n;]*x-middleware-subrequest/i.test(content);
			if (!strips) flagged.push(file);
		}

		if (flagged.length > 0) {
			findings.push({
				id: "WEB_PROXY_MIDDLEWARE_HEADER_UNSTRIPPED",
				title: "Reverse-proxy config forwards upstream without stripping the internal `x-middleware-subrequest` header (CVE-2025-29927 hardening gap, CWE-285)",
				severity: "LOW",
				evidence: flagged.slice(0, 10),
				files: flagged.slice(0, 10),
				requiredActions: [
					"Strip the internal `x-middleware-subrequest` header from all inbound requests at the edge: `proxy_set_header x-middleware-subrequest \"\";`",
					"This prevents an external attacker from forging the header to make Next.js skip middleware (CVE-2025-29927), independent of the framework version.",
					"Audit all edge proxies (nginx, Envoy, CDN rules) for the same stripping rule."
				]
			});
		}
	} catch (err) {
		console.warn("[checkProxyDoesNotStripMiddlewareHeader] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

// ---------------------------------------------------------------------------
// 2. WEB_RSC_FLIGHT_DESERIALIZATION_RCE — "React2Shell", CVE-2025-55182, CWE-502.
//
// What it is (plain language): React Server Components serialize data to the
// client (and accept it back) using the "Flight" wire format. Affected React 19
// builds deserialize attacker-influenced Flight payloads / server-action
// arguments in a way that lets a crafted payload reach dangerous constructors —
// an insecure-deserialization path (CWE-502) that can lead to remote code
// execution on the server.
//
// Why the pattern matches: we gate on a concrete `react` version in the
// 19.0.0–19.2.0 window (inclusive of the pre-releases below 19.0.0 final is out
// of scope). If the version can't be resolved we downgrade to MEDIUM review.
// ---------------------------------------------------------------------------
async function checkRscFlightDeserializationRce(
	reactSpec: string | undefined,
	pkgFile: string | null
): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		if (reactSpec === undefined) return findings;

		const LOWER = "19.0.0"; // first affected
		const UPPER = "19.2.0"; // last affected (patched above this)
		const concrete = resolveConcreteVersion(reactSpec);

		if (concrete === null) {
			// Only raise a review if the spec at least targets the react 19 line,
			// to avoid noise on unrelated majors expressed as ranges.
			if (/(?:^|[^\d])19\b/.test(reactSpec)) {
				findings.push({
					id: "WEB_RSC_FLIGHT_DESERIALIZATION_RCE",
					title: "`react` targets the 19.x line but the exact version cannot be confirmed patched for React2Shell (CVE-2025-55182) — review",
					severity: "MEDIUM",
					evidence: [`${pkgFile ?? "package.json"}: react -> "${reactSpec}" (unresolvable)`],
					files: pkgFile ? [pkgFile] : [],
					requiredActions: [
						"Pin `react` to a concrete version and confirm it is above 19.2.0 (React2Shell / CVE-2025-55182).",
						"React 19.0.0–19.2.0 deserialize RSC Flight / server-action payloads unsafely (CWE-502), reachable via crafted server-action arguments.",
						"Upgrade to a patched React 19 release and audit any custom server-action argument handling."
					]
				});
			}
			return findings;
		}

		const inWindow =
			compareVersions(concrete, LOWER) !== null &&
			(compareVersions(concrete, LOWER) as number) >= 0 &&
			(compareVersions(concrete, UPPER) as number) <= 0;

		if (inWindow) {
			findings.push({
				id: "WEB_RSC_FLIGHT_DESERIALIZATION_RCE",
				title: "Vulnerable React 19 version — React2Shell RSC Flight insecure deserialization (CVE-2025-55182, CWE-502) enabling RCE",
				severity: "CRITICAL",
				sla: "24h",
				evidence: [`${pkgFile ?? "package.json"}: react -> "${reactSpec}" (concrete ${concrete}, in affected 19.0.0–19.2.0 window)`],
				files: pkgFile ? [pkgFile] : [],
				requiredActions: [
					"Upgrade `react` (and `react-dom` / the paired `next` server-actions runtime) past 19.2.0 immediately (CVE-2025-55182 'React2Shell').",
					"Affected builds deserialize the RSC 'Flight' wire format / server-action arguments unsafely (CWE-502), which can be driven to remote code execution.",
					"Until patched, treat all server-action inputs as untrusted and consider disabling server actions on internet-facing surfaces."
				]
			});
		}
	} catch (err) {
		console.warn("[checkRscFlightDeserializationRce] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

// ---------------------------------------------------------------------------
// 3. WEB_DJANGO_ORM_CONNECTOR_SQLI — CVE-2025-64459, CWE-89.
//
// What it is (plain language): Django's ORM lets you build queries with keyword
// arguments, e.g. `Model.objects.filter(name="x")`. When code unpacks an
// attacker-controlled dict into those keyword args — `filter(**request.GET)` —
// a crafted key (using the special `_connector` / Q-object handling) can alter
// the generated SQL, i.e. SQL injection through the ORM connector (CWE-89).
//
// Why the pattern matches: we look for `.filter/.exclude/.get(**...` or
// `Q(**...` AND, nearby, a reference to `request.GET/POST/data`, so we only fire
// when the unpacked dict plausibly derives from user input. We also gate on a
// vulnerable Django version in requirements*.txt / pyproject.toml. Either the
// source pattern OR a vulnerable version can produce a finding; both together is
// the confident CRITICAL.
// Patched: 4.2.26 / 5.1.14 / 5.2.8.
// ---------------------------------------------------------------------------
async function checkDjangoOrmConnectorSqli(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		// Source pattern: dict-unpack into a filtering call.
		const unpackHits = (
			await searchRepo({
				query: String.raw`\.(?:filter|exclude|get)\(\s*\*\*|(?:^|[^.\w])Q\(\s*\*\*`,
				isRegex: true,
				maxMatches: 200
			})
		).filter((h) => /\.py$/.test(h.file));

		// Correlate with user-input sources anywhere in the same files.
		let userInputFiles = new Set<string>();
		if (unpackHits.length > 0) {
			const reqHits = await searchRepo({
				query: String.raw`request\.(?:GET|POST|data|query_params)\b`,
				isRegex: true,
				maxMatches: 200
			});
			userInputFiles = new Set(reqHits.map((h) => h.file));
		}
		const correlatedHits = unpackHits.filter((h) => userInputFiles.has(h.file));

		// Version gate on Django.
		const djangoVuln = await isVulnerableDjango();

		// Confident CRITICAL: user-input-correlated ORM unpack in source.
		if (correlatedHits.length > 0) {
			findings.push({
				id: "WEB_DJANGO_ORM_CONNECTOR_SQLI",
				title: "Attacker-controlled dict unpacked into a Django ORM filter/exclude/get/Q call — ORM connector SQL injection (CVE-2025-64459, CWE-89)",
				severity: "CRITICAL",
				sla: "24h",
				evidence: toEvidence(correlatedHits),
				files: toFiles(correlatedHits),
				requiredActions: [
					"Never unpack a request dict directly into ORM query kwargs (`filter(**request.GET)`); build the kwargs from an explicit allowlist of field names.",
					"A crafted key abusing the ORM `_connector`/Q handling rewrites the generated SQL (CVE-2025-64459 / CWE-89).",
					"Upgrade Django to a patched release: >= 4.2.26, 5.1.14, or 5.2.8 for your major line."
				]
			});
		} else if (djangoVuln.vulnerable) {
			// No source pattern found, but the installed Django is provably below
			// the patched line — flag the framework itself as needing the upgrade.
			findings.push({
				id: "WEB_DJANGO_ORM_CONNECTOR_SQLI",
				title: "Vulnerable Django version — ORM connector SQL injection fix missing (CVE-2025-64459, CWE-89)",
				severity: "CRITICAL",
				sla: "24h",
				evidence: djangoVuln.evidence,
				files: djangoVuln.files,
				requiredActions: [
					"Upgrade Django to >= 4.2.26, 5.1.14, or 5.2.8 for your major line (CVE-2025-64459).",
					"Audit all `.filter/.exclude/.get(**...)` and `Q(**...)` call sites for dicts derived from `request.GET/POST/data`.",
					"Build ORM query kwargs from an allowlist of permitted field names rather than unpacking user input."
				]
			});
		} else if (unpackHits.length > 0 && djangoVuln.unresolved) {
			// ORM unpack present, Django version unconfirmable → MEDIUM review.
			findings.push({
				id: "WEB_DJANGO_ORM_CONNECTOR_SQLI",
				title: "Django ORM dict-unpack pattern present and Django version cannot be confirmed patched for CVE-2025-64459 — review",
				severity: "MEDIUM",
				evidence: [...toEvidence(unpackHits), ...djangoVuln.evidence],
				files: [...toFiles(unpackHits), ...djangoVuln.files],
				requiredActions: [
					"Confirm whether the unpacked dict in `filter/exclude/get/Q(**...)` derives from user input; if so, treat as CVE-2025-64459.",
					"Pin and confirm Django is >= 4.2.26 / 5.1.14 / 5.2.8 for your major line.",
					"Rebuild ORM kwargs from an allowlist of field names."
				]
			});
		}
	} catch (err) {
		console.warn("[checkDjangoOrmConnectorSqli] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

/**
 * Resolve the declared Django version from requirements*.txt / pyproject.toml
 * and decide whether it is below the patched line (4.2.26 / 5.1.14 / 5.2.8).
 * Returns discriminated result so the caller can distinguish "vulnerable",
 * "not present / patched", and "present but unresolvable" (review).
 */
async function isVulnerableDjango(): Promise<{
	vulnerable: boolean;
	unresolved: boolean;
	evidence: string[];
	files: string[];
}> {
	const PATCHED = ["4.2.26", "5.1.14", "5.2.8"];
	try {
		const files = await fg(
			["requirements*.txt", "**/requirements*.txt", "pyproject.toml", "**/pyproject.toml"],
			{ dot: true }
		);
		for (const file of files) {
			let content = "";
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			// Match a Django pin in either format:
			//   Django==5.1.2   django>=5.1,<5.2   "django==5.1.2"   django = "5.1.2"
			const m = /(?:^|[\s"'])[Dd]jango\s*(==|>=|~=|<=|>|<|=)?\s*["']?(\d+\.\d+(?:\.\d+)?)/m.exec(content);
			if (!m) continue;
			const op = m[1] ?? "==";
			const ver = m[2];

			// Only "==" / bare / "~=" collapse to a single confident version. A
			// lower-bound-only range (>= / >) does not prove the installed version,
			// so we treat it as unresolved (review) rather than assert vulnerable.
			if (op === "==" || op === "~=" || op === "=" ) {
				const concrete = resolveConcreteVersion(ver);
				if (concrete === null) {
					return { vulnerable: false, unresolved: true, evidence: [`${file}: Django ${op} ${ver}`], files: [file] };
				}
				if (isBelowMajorAwareThresholds(concrete, PATCHED)) {
					return { vulnerable: true, unresolved: false, evidence: [`${file}: Django ${op} ${ver} (below patched line)`], files: [file] };
				}
				return { vulnerable: false, unresolved: false, evidence: [], files: [] };
			}
			// Range specifier — cannot pin exact version.
			return { vulnerable: false, unresolved: true, evidence: [`${file}: Django ${op} ${ver} (range — version unresolved)`], files: [file] };
		}
	} catch {
		// fall through to "not present"
	}
	return { vulnerable: false, unresolved: false, evidence: [], files: [] };
}

// ---------------------------------------------------------------------------
// 4. WEB_KESTREL_CHUNKED_SMUGGLING — CVE-2025-55315, CWE-444.
//
// What it is (plain language): Kestrel (the ASP.NET Core HTTP server) mis-parsed
// HTTP/1.1 chunked transfer-encoding in a way that lets an attacker "smuggle" a
// second request inside the body of the first (HTTP request smuggling, CWE-444).
// Front-end and back-end disagree on where one request ends and the next begins,
// enabling auth bypass, cache poisoning, and request hijacking.
//
// Why the pattern matches: we flag either (a) a Microsoft.AspNetCore package
// reference in a .csproj/packages file below the patched version, or (b) the
// `InsecureChunkedParsing` compatibility switch explicitly set to true, which
// re-enables the vulnerable behaviour. HIGH.
// ---------------------------------------------------------------------------
async function checkKestrelChunkedSmuggling(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		// (b) Compat flag re-enabling the vulnerable parser — always a finding.
		const compatHits = await searchRepo({
			query: String.raw`InsecureChunkedParsing["'\s]*(?:[:=,>]|value=["'])\s*["']?true`,
			isRegex: true,
			maxMatches: 200
		});
		if (compatHits.length > 0) {
			findings.push({
				id: "WEB_KESTREL_CHUNKED_SMUGGLING",
				title: "ASP.NET Core `InsecureChunkedParsing` compat switch set to true — re-enables chunked request smuggling (CVE-2025-55315, CWE-444)",
				severity: "HIGH",
				sla: "7d",
				evidence: toEvidence(compatHits),
				files: toFiles(compatHits),
				requiredActions: [
					"Remove the `InsecureChunkedParsing` compatibility switch (or set it to false) — it re-enables the vulnerable chunked parser (CVE-2025-55315).",
					"Kestrel mis-parsing chunked transfer-encoding permits HTTP request smuggling (CWE-444): auth bypass, cache poisoning, and request hijacking.",
					"Ensure the runtime/patch that fixed CVE-2025-55315 is deployed before removing the switch."
				]
			});
		}

		// (a) Vulnerable Microsoft.AspNetCore package pin in .csproj / packages.config.
		const projFiles = await fg(
			["**/*.csproj", "**/packages.config", "**/Directory.Packages.props", "**/*.props"],
			{ dot: true }
		);
		// Patched runtime lines (representative): 8.0.x and 9.0.x received servicing
		// updates; we flag confident concrete versions below these servicing lines.
		const PATCHED = ["8.0.11", "9.0.0"];
		for (const file of projFiles) {
			let content = "";
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			// PackageReference / PackageVersion Include="Microsoft.AspNetCore..." Version="x.y.z"
			const re = /Microsoft\.AspNetCore[\w.]*"[^>]*?[Vv]ersion="([^"]+)"/g;
			let m: RegExpExecArray | null;
			const flaggedVersions: string[] = [];
			let sawUnresolved = false;
			while ((m = re.exec(content)) !== null) {
				const concrete = resolveConcreteVersion(m[1]);
				if (concrete === null) {
					sawUnresolved = true;
					continue;
				}
				if (isBelowMajorAwareThresholds(concrete, PATCHED)) {
					flaggedVersions.push(`${file}: Microsoft.AspNetCore ${m[1]} (below patched line)`);
				}
			}
			if (flaggedVersions.length > 0) {
				findings.push({
					id: "WEB_KESTREL_CHUNKED_SMUGGLING",
					title: "Vulnerable Microsoft.AspNetCore version — Kestrel chunked request smuggling (CVE-2025-55315, CWE-444)",
					severity: "HIGH",
					sla: "7d",
					evidence: flaggedVersions.slice(0, 10),
					files: [file],
					requiredActions: [
						"Upgrade Microsoft.AspNetCore / the ASP.NET Core runtime to a version containing the CVE-2025-55315 fix (8.0.11+ / 9.0.0+ servicing line).",
						"Kestrel's chunked transfer-encoding parsing flaw enables HTTP request smuggling (CWE-444).",
						"After upgrading, verify no `InsecureChunkedParsing` compat switch re-enables the old behaviour."
					]
				});
			} else if (sawUnresolved && /Microsoft\.AspNetCore/.test(content)) {
				findings.push({
					id: "WEB_KESTREL_CHUNKED_SMUGGLING",
					title: "Microsoft.AspNetCore referenced but the version cannot be confirmed patched for CVE-2025-55315 — review",
					severity: "MEDIUM",
					evidence: [`${file}: Microsoft.AspNetCore version unresolvable`],
					files: [file],
					requiredActions: [
						"Pin Microsoft.AspNetCore / the runtime to a concrete version and confirm it contains the CVE-2025-55315 chunked-parsing fix.",
						"Kestrel chunked transfer-encoding mis-parsing enables HTTP request smuggling (CWE-444).",
						"Ensure no `InsecureChunkedParsing` compat switch is set to true."
					]
				});
			}
		}
	} catch (err) {
		console.warn("[checkKestrelChunkedSmuggling] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

// ---------------------------------------------------------------------------
// 5. WEB_JWT_JKU_X5U_SSRF — CWE-918.
//
// What it is (plain language): A JWT's header can carry `jku` (JWK Set URL) or
// `x5u` (X.509 cert URL) pointing to where the verifier should fetch the signing
// key. If a verifier blindly fetches that attacker-supplied URL, an attacker can
// (1) point it at an internal service to perform Server-Side Request Forgery
// (CWE-918), and (2) host their own key to forge valid-looking tokens.
//
// Why the pattern matches: we look for the decoded JWT header's `jku`/`x5u`
// field flowing into an HTTP fetch (fetch/axios/http(s).get/got/request) with no
// host allowlist present in the codebase. Tight enough to avoid firing on any
// mention of `jku` in comments or config. HIGH.
// ---------------------------------------------------------------------------
async function checkJwtJkuX5uSsrf(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		// header.jku / header.x5u / decoded.header.jku reaching an HTTP client.
		const fetchFromHeader = await searchRepo({
			query: String.raw`(?:fetch|axios(?:\.get)?|got|request|https?\.get|superagent(?:\.get)?)\s*\(\s*[^)]*\b(?:header|decoded|payload)?\.?(?:jku|x5u)\b`,
			isRegex: true,
			maxMatches: 200
		});
		// Also catch a two-step: `const url = header.jku` then fetched — flag the
		// assignment when a jku/x5u value is pulled out of a decoded header.
		const headerAssign = await searchRepo({
			query: String.raw`(?:const|let|var)\s+\w+\s*=\s*[^;\n]*\b(?:decoded|header|token)\b[^;\n]*\.(?:jku|x5u)\b`,
			isRegex: true,
			maxMatches: 200
		});

		const codeExt = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|java|rb)$/;
		const combined = [...fetchFromHeader, ...headerAssign].filter((h) => codeExt.test(h.file));
		const uniqueHits = combined.filter(
			(hit, idx, arr) => arr.findIndex((h) => h.file === hit.file && h.line === hit.line) === idx
		);
		if (uniqueHits.length === 0) return findings;

		// A host allowlist anywhere in the codebase mitigates the SSRF — if present
		// we still report but note it; absence makes it a clean HIGH.
		const allowlistHits = await searchRepo({
			query: String.raw`jku[A-Za-z]*[Aa]llow|allowedJku|allowedHosts?|jwksAllowlist|trustedIssuers?|allowedKeyHosts?|ALLOWED_(?:JKU|KEY)_HOSTS`,
			isRegex: true,
			maxMatches: 200
		});

		findings.push({
			id: "WEB_JWT_JKU_X5U_SSRF",
			title: "JWT verifier fetches signing keys from a token-header `jku`/`x5u` URL without a host allowlist — SSRF and token forgery (CWE-918)",
			severity: allowlistHits.length > 0 ? "MEDIUM" : "HIGH",
			sla: "7d",
			evidence: [
				...toEvidence(uniqueHits),
				...(allowlistHits.length > 0 ? [`(allowlist-like symbol present — verify it actually constrains jku/x5u hosts: ${allowlistHits[0].file}:${allowlistHits[0].line})`] : [])
			],
			files: toFiles(uniqueHits),
			requiredActions: [
				"Never fetch signing keys from an attacker-controlled `jku`/`x5u` URL in the JWT header — pin the JWKS/key endpoint in server config, ignoring header-supplied URLs.",
				"If dynamic fetch is unavoidable, enforce a strict host allowlist and block internal/link-local/metadata addresses (CWE-918 SSRF).",
				"Bind accepted keys to the expected issuer so an attacker-hosted key cannot forge valid tokens."
			]
		});
	} catch (err) {
		console.warn("[checkJwtJkuX5uSsrf] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

// ---------------------------------------------------------------------------
// 6. WEB_PATH_TO_REGEXP_REDOS — CWE-1333.
//
// What it is (plain language): `path-to-regexp` (used by Express and many
// routers to turn route strings like `/user/:id` into regexes) had versions that
// generate a regex vulnerable to catastrophic backtracking. A crafted URL can
// hang the event loop — a Regular-Expression Denial of Service (ReDoS, CWE-1333).
//
// Why the pattern matches: we read the installed version from the lockfile
// (package-lock.json / yarn.lock — the resolved, transitive-inclusive version is
// what actually runs) and flag versions in the known-vulnerable ranges. Fixed
// lines: 0.1.12 / 1.9.0 / 3.3.0 / 8.0.0 (the 0.1.x / 1.x–3.x / <8 pre-fix
// releases are affected). MEDIUM. When no concrete version resolves, downgrade.
// ---------------------------------------------------------------------------
async function checkPathToRegexpRedos(): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const lockFiles = await fg(
			["package-lock.json", "**/package-lock.json", "yarn.lock", "**/yarn.lock"],
			{ dot: true }
		);
		if (lockFiles.length === 0) return findings;

		// Fixed thresholds per major line. A version below the fix for its own
		// major is vulnerable.
		const PATCHED = ["0.1.12", "1.9.0", "3.3.0", "8.0.0"];
		const vulnerable: string[] = [];
		let sawUnresolved = false;
		const seen = new Set<string>();

		for (const file of lockFiles) {
			let content = "";
			try {
				content = await readFileSafe(file);
			} catch {
				continue;
			}
			for (const ver of extractPathToRegexpVersions(content)) {
				const key = `${file}::${ver}`;
				if (seen.has(key)) continue;
				seen.add(key);
				const concrete = resolveConcreteVersion(ver);
				if (concrete === null) {
					sawUnresolved = true;
					continue;
				}
				if (isBelowMajorAwareThresholds(concrete, PATCHED)) {
					vulnerable.push(`${file}: path-to-regexp ${ver} (below patched line for its major)`);
				}
			}
		}

		if (vulnerable.length > 0) {
			findings.push({
				id: "WEB_PATH_TO_REGEXP_REDOS",
				title: "Vulnerable `path-to-regexp` version in lockfile — route-parser ReDoS (CWE-1333)",
				severity: "MEDIUM",
				sla: "30d",
				evidence: vulnerable.slice(0, 10),
				files: [...new Set(vulnerable.map((v) => v.split(":")[0]))].slice(0, 10),
				requiredActions: [
					"Upgrade `path-to-regexp` to a fixed release for its major line: >= 0.1.12, 1.9.0, 3.3.0, or 8.0.0.",
					"Affected versions compile route patterns into a regex prone to catastrophic backtracking — a crafted URL hangs the event loop (ReDoS, CWE-1333).",
					"Because this is usually a transitive dependency (Express), pin it via `overrides`/`resolutions` and run `npm audit` to confirm the fix."
				]
			});
		} else if (sawUnresolved) {
			findings.push({
				id: "WEB_PATH_TO_REGEXP_REDOS",
				title: "`path-to-regexp` present but its version could not be confirmed patched for the ReDoS fix (CWE-1333) — review",
				severity: "MEDIUM",
				evidence: ["path-to-regexp version unresolvable from lockfile"],
				requiredActions: [
					"Confirm the resolved `path-to-regexp` version is >= 0.1.12 / 1.9.0 / 3.3.0 / 8.0.0 for its major line.",
					"Vulnerable versions allow a route-parser ReDoS (CWE-1333).",
					"Pin via `overrides`/`resolutions` and re-run `npm audit`."
				]
			});
		}
	} catch (err) {
		console.warn("[checkPathToRegexpRedos] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}
	return findings;
}

/**
 * Pull path-to-regexp versions out of a lockfile. Handles both
 * package-lock.json (JSON, `"node_modules/path-to-regexp": { "version": "x" }`)
 * and yarn.lock (`path-to-regexp@...:` stanza followed by `version "x"`). Purely
 * textual/regex so it never throws on an unexpected lockfile shape.
 */
function extractPathToRegexpVersions(content: string): string[] {
	const versions: string[] = [];

	// package-lock.json style: an entry key mentioning path-to-regexp with a
	// nearby "version": "x.y.z". We scan for the key then the next version field.
	const jsonRe = /path-to-regexp[^\n]*\n(?:[^\n]*\n){0,3}?[^\n]*"version"\s*:\s*"([^"]+)"/g;
	let jm: RegExpExecArray | null;
	while ((jm = jsonRe.exec(content)) !== null) {
		versions.push(jm[1]);
	}

	// yarn.lock style: `path-to-regexp@<range>:` header then `  version "x.y.z"`.
	const yarnRe = /path-to-regexp@[^\n]*\n(?:[^\n]*\n){0,4}?\s*version\s+"([^"]+)"/g;
	let ym: RegExpExecArray | null;
	while ((ym = yarnRe.exec(content)) !== null) {
		versions.push(ym[1]);
	}

	return [...new Set(versions)];
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------
export async function checkEmergingWeb(_: { changedFiles: string[] }): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const { deps, file: pkgFile } = await readPackageJsonDeps();

		findings.push(...(await checkNextjsMiddlewareAuthBypass(deps["next"], pkgFile)));
		findings.push(...(await checkProxyDoesNotStripMiddlewareHeader()));
		findings.push(...(await checkRscFlightDeserializationRce(deps["react"], pkgFile)));
		findings.push(...(await checkDjangoOrmConnectorSqli()));
		findings.push(...(await checkKestrelChunkedSmuggling()));
		findings.push(...(await checkJwtJkuX5uSsrf()));
		findings.push(...(await checkPathToRegexpRedos()));
	} catch (err) {
		console.warn("[checkEmergingWeb] Internal error:", sanitizeErrorMessage(err instanceof Error ? err.message : String(err)));
	}

	return findings;
}
