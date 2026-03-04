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
const MAX_REGEX_LEN = 256;

// Detects nested quantifiers — the most common ReDoS trigger — without being
// overly complex itself. Matches patterns like (a+)+, (a*)*, (\w+)+.
const NESTED_QUANTIFIER_RE = /\([^)]*[+*][^)]*\)[+*?{]/;

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
	if (NESTED_QUANTIFIER_RE.test(pattern)) {
		throw new Error("Regex pattern contains nested quantifiers that risk catastrophic backtracking (ReDoS)");
	}
	return new RegExp(pattern, "i"); // throws SyntaxError on invalid patterns
}

const MAX_PREVIEW_LEN = 240;

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
			preview: line.slice(0, MAX_PREVIEW_LEN)
		});
	}
}

export async function searchRepo(opts: SearchOptions): Promise<RepoMatch[]> {
	const files = await fg(["**/*.*"], {
		dot: true,
		ignore: ["**/node_modules/**", "**/.git/**", "**/dist/**"]
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
