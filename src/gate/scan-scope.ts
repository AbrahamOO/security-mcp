import fg from "fast-glob";

/**
 * Centralised scan-scoping for every gate check.
 *
 * Historically each check module called fast-glob directly with its own
 * hand-maintained `ignore` array, so exclusions drifted: some checks skipped
 * `.mcp/`, most did not, and only a couple skipped a project's test fixtures.
 * The result was that the gate, run against its own repository, flagged its
 * generated state files and intentional vulnerable fixtures as findings.
 *
 * Check modules now import `scopedFg as fg` from this module, so a single
 * source of truth governs what every check is allowed to see.
 */

/**
 * Globs that must NEVER be scanned by any check, in any project: VCS internals,
 * installed dependencies, build output, and the gate's own state directory.
 * `.mcp/` holds gate-generated baselines, reviews, reports, attestations, and
 * audit logs — scanning it makes the gate flag its own serialized output as new
 * findings, which is never correct.
 */
export const ALWAYS_IGNORE_GLOBS: readonly string[] = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/.mcp/**",
];

/**
 * Extra ignore globs configured per-project via the `SECURITY_GATE_IGNORE`
 * environment variable (comma-separated). A bare directory name such as
 * `fixtures` is expanded to `** /fixtures/** `; a value already containing `*`
 * is used verbatim.
 *
 * This is how a project excludes intentional test-vulnerability fixtures (or any
 * other path it does not ship) from its own gate run WITHOUT weakening detection
 * for real code, and without baking a project-specific assumption into the
 * shipped product. When the variable is unset (e.g. during the unit tests, which
 * deliberately scan fixtures) no extra paths are excluded.
 */
export function configuredIgnoreGlobs(): string[] {
  const raw = process.env.SECURITY_GATE_IGNORE;
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      if (entry.includes("*")) return entry; // already a glob — use verbatim
      const p = entry.replace(/^\.?\/+/, "").replace(/\/+$/, "");
      const lastSegment = p.split("/").pop() ?? p;
      const looksLikeFile = lastSegment.includes(".");
      if (p.includes("/")) return looksLikeFile ? p : `${p}/**`;
      return looksLikeFile ? `**/${p}` : `**/${p}/**`;
    });
}

/** Merge a caller's own ignore list with the always-ignore and configured sets. */
export function scanIgnoreGlobs(callerIgnore: readonly string[] = []): string[] {
  return [...new Set([...callerIgnore, ...ALWAYS_IGNORE_GLOBS, ...configuredIgnoreGlobs()])];
}

/**
 * Drop-in replacement for fast-glob's default export. Behaves identically except
 * that the global and project-configured ignore globs are always merged into the
 * caller's options. Check modules import this as `fg`, so existing `fg(...)`
 * call sites are unchanged.
 */
export function scopedFg(
  patterns: string | string[],
  options: fg.Options = {}
): Promise<string[]> {
  return fg(patterns, { ...options, ignore: scanIgnoreGlobs(options.ignore ?? []) });
}
