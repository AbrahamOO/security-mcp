import fg from "fast-glob";
import { readFileSafe } from "./fs.js";
import { scanIgnoreGlobs } from "../gate/scan-scope.js";
import { getWorkspaceRoot } from "./workspace.js";

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

/**
 * Truncation ledger.
 *
 * Every query stops at `maxMatches`. Nothing recorded that it had stopped, so a rule
 * that filters its hits — "keep the ones whose line does not also contain a
 * sanitizer" — could have its unsafe match sitting at position 201 and report
 * nothing, and a rule that intersects two searches by filename could miss the file
 * entirely. The gate reported that as a clean result, because a capped search and an
 * exhausted search return the same shape.
 *
 * Queries that only ask whether ANY match exists use small caps (5) and are not
 * truncation-sensitive: they got their answer. Only evidence-collecting queries,
 * which ask for 50 or more, are recorded.
 */
export type SearchTruncation = { query: string; maxMatches: number };

const EVIDENCE_CAP_THRESHOLD = 50;
const truncations: SearchTruncation[] = [];
/** Cap on remembered entries — the ledger must not grow without bound on a huge repo. */
const MAX_REMEMBERED_TRUNCATIONS = 200;

function recordTruncation(query: string, maxMatches: number): void {
	if (truncations.length >= MAX_REMEMBERED_TRUNCATIONS) return;
	if (truncations.some((t) => t.query === query)) return;
	truncations.push({ query: query.slice(0, 120), maxMatches });
}

/** Returns every truncation recorded since the last call, and clears the ledger. */
export function consumeSearchTruncations(): SearchTruncation[] {
	return truncations.splice(0, truncations.length);
}

export async function searchRepo(opts: SearchOptions): Promise<RepoMatch[]> {
	// "**/*" (not "**/*.*") — the dotted form silently excludes every
	// extensionless file (Dockerfile, Makefile, Jenkinsfile, Procfile, ...),
	// which are exactly the filenames several checks (docker-deep's
	// isDockerfile()) search for.
	const files = await fg(["**/*"], {
		dot: true,
		// Discover files under the active workspace root, not the process directory,
		// so discovery and readFileSafe() resolve against the same tree under withWorkspace().
		cwd: getWorkspaceRoot(),
		followSymbolicLinks: false,  // Prevent glob-based symlink traversal outside workspace root.
		// Only the always-ignore set (node_modules, .git, dist, .mcp) plus the
		// operator's SECURITY_GATE_IGNORE paths.
		//
		// This deliberately carries NO path exclusions of its own. It previously
		// skipped "src/gate/**" and "**/.claude/**" so the tool's own self-scan would
		// not flag its detection patterns and agent-instruction files. Those globs
		// applied to EVERY workspace, so any reviewed project with a src/gate/
		// directory (an API gateway, a feature-gate module) or a .claude/ directory
		// (every repo that uses Claude Code) had those trees silently excluded from
		// every query-based check: SQL injection, crypto, secrets, web hardening.
		// Absence of findings there read as clean.
		//
		// Excluding the tool's own source is an operator decision about one specific
		// repository, so it belongs in SECURITY_GATE_IGNORE (environment, set by the
		// operator) and not in the shipped product (repository content, set by whoever
		// wrote the repo under review).
		ignore: scanIgnoreGlobs()
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

	if (matches.length >= opts.maxMatches && opts.maxMatches >= EVIDENCE_CAP_THRESHOLD) {
		recordTruncation(opts.query, opts.maxMatches);
	}

	return matches;
}
