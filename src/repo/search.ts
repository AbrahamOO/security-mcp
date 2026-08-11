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
 * Upper bound on unbounded quantifiers in one pattern.
 *
 * Backtracking cost grows with the number of quantified atoms that can match the same
 * input, and a sequence of them is as expensive as nesting them. Legitimate search
 * patterns are well under this; the bound is what makes the cost of a rejected pattern
 * a refusal rather than a stalled process.
 */
const MAX_QUANTIFIERS = 4;

/**
 * Rejects regex patterns whose backtracking cost is superlinear. CWE-1333.
 *
 * The group-shape tests below are necessary but not sufficient on their own: they all
 * require a parenthesised group, so a flat sequence of quantified atoms is equally
 * expensive and matches none of them. The quantifier budget and the adjacency test are
 * what make the guard hold for patterns that use no groups at all. Matching is
 * additionally bounded at runtime by REGEX_TIME_BUDGET_MS and MAX_SCANNED_LINE_LEN, so
 * a pattern this function does not anticipate still cannot run without limit.
 */
function isCatastrophicRegex(pattern: string): boolean {
	// Nested quantifiers like (a+)+, (a*)*, (\w+)+
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
 * Additional pattern rules applied only to caller-supplied regexes.
 *
 * The shape tests above all require a parenthesised group, so a flat sequence of
 * quantified atoms is equally expensive and matches none of them. That gap is only
 * reachable from a caller that chooses its own pattern, which today means the
 * `repo.search` MCP tool. That tool is child-safe, so a prompt-injected agent can reach
 * it and stall the parent process.
 *
 * These rules are deliberately not applied to the engine's own detection patterns. Those
 * are authored in this repository, reviewed, and corpus-tested, and several legitimately
 * use more quantifiers than a caller ever should. Their cost is bounded instead by
 * REGEX_TIME_BUDGET_MS and MAX_SCANNED_LINE_LEN, which apply to every search.
 */
export function assertSafeCallerRegex(pattern: string): void {
	if (pattern.length > MAX_REGEX_LEN) {
		throw new Error(`Regex pattern too long (max ${MAX_REGEX_LEN} chars)`);
	}
	if (isCatastrophicRegex(pattern)) {
		throw new Error("Regex pattern contains nested quantifiers that risk catastrophic backtracking (ReDoS)");
	}

	// Collapse escapes and character classes to a single placeholder atom, so the tests
	// below compare atoms rather than re-parsing syntax. Both replacements are linear,
	// which matters: a guard that is itself superlinear is not a guard. Input is already
	// bounded to MAX_REGEX_LEN above.
	const flattened = pattern.replace(/\\./g, "a").replace(/\[[^\]]*\]/g, "a");

	// The same atom quantified twice in sequence: x+x+, .*.*, [a-z]+[a-z]*. Ambiguous in
	// exactly the way a nested quantifier is, and it needs no group to be expensive.
	if (/(.)[+*]\1[+*]/.test(flattened)) {
		throw new Error("Regex pattern repeats a quantified atom, which risks catastrophic backtracking (ReDoS)");
	}

	// Budget on unbounded quantifiers, counting + * and open-ended {n,}.
	const quantifiers = flattened.match(/[+*]|\{\d+,\}/g);
	if (quantifiers && quantifiers.length > MAX_QUANTIFIERS) {
		throw new Error(
			`Regex pattern uses more than ${MAX_QUANTIFIERS} unbounded quantifiers, which risks catastrophic backtracking (ReDoS)`
		);
	}
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

/**
 * Ceiling on the input length a single regex is applied to.
 *
 * Backtracking cost is a function of input length as well as pattern shape, and a
 * minified bundle or a generated file can put a whole program on one line. Bounding the
 * input bounds the cost of any single match attempt.
 */
const MAX_SCANNED_LINE_LEN = 8192;

/**
 * Scanning-time ceiling for one search.
 *
 * The pattern guard rejects the shapes it knows. This bounds the ones it does not, so an
 * unanticipated pattern costs a truncated search rather than a process that never
 * returns. It is checked between lines, which is where a search can be interrupted.
 *
 * This budget counts time spent inside scanLines, not elapsed wall clock. The gate issues
 * its ~495 searches in concurrent Promise.all batches, so a wall-clock deadline taken at
 * call time is shared by every search in flight: once the batch as a whole ran longer than
 * the budget, all of them tripped at the same instant and reported a timeout, having each
 * done almost no work. That produced 200 spurious SEARCH_TIME_BUDGET_EXCEEDED reports in a
 * CI job that finished in 14 seconds, which is the opposite of what the finding is for —
 * it is supposed to mark a genuinely incomplete scan.
 */
const REGEX_TIME_BUDGET_MS = 5000;

function isHit(line: string, query: string, re: RegExp | null): boolean {
	return re ? re.test(line) : line.includes(query);
}

function scanLines(
	file: string,
	lines: string[],
	opts: SearchOptions,
	re: RegExp | null,
	matches: RepoMatch[],
	budget: { remainingMs: number }
): boolean {
	const started = Date.now();
	const spend = (): void => {
		const now = Date.now();
		budget.remainingMs -= now - started;
	};

	for (let i = 0; i < lines.length; i++) {
		if (matches.length >= opts.maxMatches) {
			spend();
			return true;
		}
		// Charge only this search's own scanning against the budget, so a concurrent
		// batch cannot bill one query for another's time.
		if (Date.now() - started >= budget.remainingMs) {
			spend();
			return false;
		}

		const raw = lines[i];
		const line = raw.length > MAX_SCANNED_LINE_LEN ? raw.slice(0, MAX_SCANNED_LINE_LEN) : raw;
		if (!isHit(line, opts.query, re)) continue;

		matches.push({
			file,
			line: i + 1,
			preview: redactSecrets(line.slice(0, MAX_PREVIEW_LEN))
		});
	}
	spend();
	return true;
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

/**
 * Skip ledger.
 *
 * A file the scanner could not read contributes no matches, which is the same output as
 * a file that was read and contained nothing. Every such file was previously discarded
 * by a bare `catch { continue; }`, so an oversized, unreadable, or non-regular file was
 * reported as clean while `scope.changedFiles` still asserted it had been scanned.
 *
 * The reasons a read fails are ordinary: over the size cap, a symlink leaving the
 * workspace, a socket or device node, a permission error, a file deleted mid-scan. None
 * of them mean the file is safe. They mean it is unknown, and unknown is recorded.
 */
export type SearchSkip = { file: string; reason: string };

const skips: SearchSkip[] = [];
/** Cap on remembered entries — the ledger must not grow without bound on a huge repo. */
const MAX_REMEMBERED_SKIPS = 500;

function recordSkip(file: string, err: unknown): void {
	if (skips.length >= MAX_REMEMBERED_SKIPS) return;
	if (skips.some((s) => s.file === file)) return;
	const raw = err instanceof Error ? err.message : String(err);
	skips.push({ file: file.slice(0, 300), reason: raw.slice(0, 200) });
}

/** Returns every skip recorded since the last call, and clears the ledger. */
export function consumeSearchSkips(): SearchSkip[] {
	return skips.splice(0, skips.length);
}

/** Wall-clock budget exhaustion, recorded so a cut-short search cannot read as complete. */
let timedOutQueries: string[] = [];

function recordSearchTimeout(query: string): void {
	if (timedOutQueries.length >= MAX_REMEMBERED_TRUNCATIONS) return;
	if (timedOutQueries.includes(query)) return;
	timedOutQueries.push(query.slice(0, 120));
}

/** Returns every timed-out query since the last call, and clears the ledger. */
export function consumeSearchTimeouts(): string[] {
	const out = timedOutQueries;
	timedOutQueries = [];
	return out;
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
	const budget = { remainingMs: REGEX_TIME_BUDGET_MS };

	for (const file of files) {
		if (matches.length >= opts.maxMatches) break;

		let text = "";
		try {
			text = await readFileSafe(file);
		} catch (err) {
			// Not skipped silently: an unread file is unknown, not clean.
			recordSkip(file, err);
			continue;
		}

		if (!scanLines(file, text.split("\n"), opts, re, matches, budget)) {
			recordSearchTimeout(opts.query);
			break;
		}
	}

	if (matches.length >= opts.maxMatches && opts.maxMatches >= EVIDENCE_CAP_THRESHOLD) {
		recordTruncation(opts.query, opts.maxMatches);
	}

	return matches;
}
