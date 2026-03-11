import { readFile } from "node:fs/promises";
import path from "node:path";

function getWorkspaceRoot(): string {
	return process.cwd();
}

function getWorkspacePrefix(root: string): string {
	return root.endsWith(path.sep) ? root : root + path.sep;
}

export async function readFileSafe(relPath: string): Promise<string> {
	const root = getWorkspaceRoot();
	const rootPrefix = getWorkspacePrefix(root);
	const p = path.resolve(root, relPath);
	// Allow exact match to ROOT itself or any path strictly under it.
	// Using ROOT_PREFIX prevents the classic prefix-collision bypass
	// (e.g. /app-sibling matching /app as a prefix). CWE-22.
	if (p !== root && !p.startsWith(rootPrefix)) {
		throw new Error("Path traversal blocked");
	}
	return await readFile(p, "utf8");
}
