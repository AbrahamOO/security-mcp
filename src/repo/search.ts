import fg from "fast-glob";
import { readFileSafe } from "./fs.js";

export type RepoMatch = { file: string; line: number; preview: string };

type SearchOptions = {
	query: string;
	isRegex: boolean;
	maxMatches: number;
};

// Maximum allowed regex pattern length. Longer patterns significantly raise
// the risk of catastrophic backtracking (ReDoS). CWE-1333.
const MAX_REGEX_LEN = 500;

/**
 * Detects regex patterns that risk catastrophic backtracking (ReDoS).
 * Covers nested quantifiers, ambiguous alternation with outer quantifiers,
 * counted repetition inside groups, and overlapping wildcard groups.
 * CWE-1333 / MITRE ATT&CK T1499.
 */
function isCatastrophicRegex(pattern: string): boolean {
	// Original: nested quantifiers like (a+)+, (a*)*, (\w+)+
	if (/\([^)]*[+*][^)]*\)[+*?{]/.test(pattern)) return true;

	// Ambiguous alternation with outer quantifier: (a|aa)+ or (a|b)+
	if (/\([^)]*\|[^)]*\)[+*]/.test(pattern)) return true;

	// Counted repetition with nested group: (a{2,})+ or (a{1,3})+
	if (/\([^)]*\{[^)]*\}[^)]*\)[+*]/.test(pattern)) return true;

	// Overlapping alternatives: (.+)+ or (\w+)+
	if (/\(\.[+*][^)]*\)[+*]/.test(pattern)) return true;
	if (/\(\\[wWdDsS][+*][^)]*\)[+*]/.test(pattern)) return true;

	return false;
}

/**
 * Validates and compiles a user-supplied regex string.
 * Throws if the pattern is dangerously long, contains known ReDoS signatures,
 * or is syntactically invalid. Returns the compiled RegExp on success.
 * CWE-1333 / MITRE ATT&CK T1499 (resource exhaustion via ReDoS).
 */
function compileUserRegex(pattern: string): RegExp {
	if (pattern.length > MAX_REGEX_LEN) {
		throw new Error(`Regex pattern too long (max ${MAX_REGEX_LEN} chars)`);
	}
	if (isCatastrophicRegex(pattern)) {
		throw new Error("Regex pattern contains nested quantifiers that risk catastrophic backtracking (ReDoS)");
	}
	return new RegExp(pattern, "i"); // throws SyntaxError on invalid patterns
}

const MAX_PREVIEW_LEN = 240;

const SECRET_REDACT_RE = /\b(?:AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,}){2})\b/g;

function redactSecrets(s: string): string {
	return s.replace(SECRET_REDACT_RE, "[REDACTED]");
}

function isHit(line: string, query: string, re: RegExp | null): boolean {
	return re ? re.test(line) : line.includes(query);
}

function scanLines(
	file: string,
	lines: string[],
	opts: SearchOptions,
	re: RegExp | null,
	matches: RepoMatch[]
): void {
	for (let i = 0; i < lines.length; i++) {
		if (matches.length >= opts.maxMatches) return;

		const line = lines[i];
		if (!isHit(line, opts.query, re)) continue;

		matches.push({
			file,
			line: i + 1,
			preview: redactSecrets(line.slice(0, MAX_PREVIEW_LEN))
		});
	}
}

export async function searchRepo(opts: SearchOptions): Promise<RepoMatch[]> {
	const files = await fg(["**/*.*"], {
		dot: true,
		followSymbolicLinks: false,  // Prevent glob-based symlink traversal outside workspace root.
		ignore: [
			"**/node_modules/**",
			"**/.git/**",
			"**/dist/**",
			"**/.claude/**",
			// Exclude detection-engine source — these files define the regex patterns that
			// the checks search for, so they would trigger their own scanners. When deployed
			// as an npm package the compiled dist/ is what runs; src/ lives in node_modules
			// which is excluded above. This ignore only affects the tool's self-scan.
			"src/gate/**"
		]
	});

	const re = opts.isRegex ? compileUserRegex(opts.query) : null;
	const matches: RepoMatch[] = [];

	for (const file of files) {
		if (matches.length >= opts.maxMatches) break;

		let text = "";
		try {
			text = await readFileSafe(file);
		} catch {
			continue;
		}

		scanLines(file, text.split("\n"), opts, re, matches);
	}

	return matches;
}
