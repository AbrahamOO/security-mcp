import { AsyncLocalStorage } from "node:async_hooks";
import path from "node:path";

/**
 * Workspace-root resolution for the whole gate.
 *
 * Historically every scanner resolved paths against `process.cwd()`, which made
 * the process's current directory the one and only workspace and forced tests to
 * `process.chdir()` (serial-only, non-reentrant). This module replaces that with
 * an AsyncLocalStorage-scoped root: code under a `withWorkspace(root, fn)` boundary
 * resolves against `root`; everything else falls back to `process.cwd()`, so the
 * default single-workspace stdio behavior is unchanged.
 *
 * This is the seam that lets tests run a check against a temp fixture directory
 * concurrently (no chdir) and is the prerequisite for any future multi-workspace mode.
 */
const workspaceStore = new AsyncLocalStorage<{ root: string }>();

/** Current workspace root: the ALS-scoped root if set, else process.cwd(). */
export function getWorkspaceRoot(): string {
  return workspaceStore.getStore()?.root ?? process.cwd();
}

/**
 * Run `fn` with `root` as the workspace root for the duration of the async call
 * tree. Nested calls override. The root is resolved to an absolute path once.
 */
export function withWorkspace<T>(root: string, fn: () => T | Promise<T>): Promise<T> {
  return Promise.resolve(workspaceStore.run({ root: path.resolve(root) }, fn));
}
