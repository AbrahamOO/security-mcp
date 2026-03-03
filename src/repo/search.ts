import fg from "fast-glob";
import { readFileSafe } from "./fs.js";

export type RepoMatch = { file: string; line: number; preview: string };

type SearchOptions = {
	query: string;
	isRegex: boolean;
	maxMatches: number;
};

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

	const re = opts.isRegex ? new RegExp(opts.query, "i") : null;
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
