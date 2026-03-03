import { readFile } from "node:fs/promises";
import path from "node:path";

const ROOT = process.cwd();

export async function readFileSafe(relPath: string): Promise<string> {
	const p = path.resolve(ROOT, relPath);
	if (!p.startsWith(ROOT)) throw new Error("Path traversal blocked");
	return await readFile(p, "utf8");
}
