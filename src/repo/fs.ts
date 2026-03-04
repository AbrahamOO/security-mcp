import { readFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();
// ROOT_PREFIX ensures /home/u/project-adjacent doesn't pass a startsWith check for /home/u/project
const ROOT_PREFIX = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;

export async function readFileSafe(relPath: string): Promise<string> {
	const p = path.resolve(ROOT, relPath);
	// Allow exact match to ROOT itself or any path strictly under it.
	// Using ROOT_PREFIX prevents the classic prefix-collision bypass
	// (e.g. /app-sibling matching /app as a prefix). CWE-22.
	if (p !== ROOT && !p.startsWith(ROOT_PREFIX)) {
		throw new Error("Path traversal blocked");
	}
	return await readFile(p, "utf8");
}
