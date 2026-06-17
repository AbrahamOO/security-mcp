import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

// Upper bound on the size of any single file the gate will read into memory.
// A malicious target repo can otherwise ship multi-GB files (or one huge
// contiguous token) to exhaust memory, or trigger V8 RangeError in the
// secret-scanner's global-regex passes. 10 MB comfortably covers real source,
// lockfiles, and minified bundles while bounding blast radius. CWE-400 / CWE-789.
const MAX_FILE_BYTES = 10 * 1024 * 1024;

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

	// Resolve symlinks and verify the real path is also within the workspace.
	// This prevents symlink traversal attacks where a symlink inside the workspace
	// points to a file outside it. CWE-61 / CAPEC-132.
	try {
		const realResolved = await realpath(p);
		const realRoot = await realpath(root);
		const realRootPrefix = realRoot + path.sep;
		if (realResolved !== realRoot && !realResolved.startsWith(realRootPrefix)) {
			throw new Error(`Symlink traversal detected: ${relPath} -> ${realResolved}`);
		}
	} catch (e: any) {
		if (e.code === "ENOENT") {
			throw new Error(`File not found: ${relPath}`);
		}
		if (e.message.includes("Symlink traversal")) throw e;
		// SECURITY: Any other realpath error (EACCES, ELOOP, etc.) means we could not
		// verify the real path is within the workspace. Deny rather than fall through,
		// because readFile() would follow symlinks using the unverified lexical path,
		// enabling traversal to out-of-workspace targets. CWE-61 / CAPEC-132.
		throw new Error(`Cannot verify path safety for ${relPath}: ${(e as Error).message}`);
	}

	// CWE-400/CWE-789: refuse oversized files so a hostile repo cannot exhaust
	// memory or feed a multi-MB contiguous token into a global regex (RangeError).
	// Loop-callers (secret/cloud-controls/search scanners) catch this and skip the file.
	const { size } = await stat(p);
	if (size > MAX_FILE_BYTES) {
		throw new Error(`File too large to scan safely: ${relPath} (${size} bytes > ${MAX_FILE_BYTES})`);
	}

	return await readFile(p, "utf8");
}
