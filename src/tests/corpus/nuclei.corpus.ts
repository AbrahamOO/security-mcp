import type { RuleCase } from "./types.js";

/**
 * "nuclei" (src/gate/checks/nuclei.ts) is a DAST integration, not a static
 * analyzer — it has no file-based Finding-emitting code path to corpus-test.
 *
 * runNucleiChecks(opts: { changedFiles: string[] }) never reads `changedFiles`.
 * Every Finding it can produce is gated behind, in order:
 *   1. process.env.SECURITY_STAGING_URL being set (else returns [] immediately);
 *   2. that URL parsing as http(s) and not resolving to a private/metadata
 *      host (else returns [], no Finding either way — this is an SSRF guard,
 *      not a detection rule with a Finding.id);
 *   3. the external `nuclei` binary being present on PATH (else returns []
 *      silently, again with no Finding);
 *   4. actually shelling out to `nuclei -u <targetUrl> ...` and parsing its
 *      NDJSON stdout from a real scan of a live HTTP target.
 *
 * A RuleCase proves a rule fires on a positive file sample and not on a
 * negative file sample, via the corpus runner's mkdtemp single-file,
 * network-less workspace (stagingUrl forced to `undefined` in
 * runner.ts's baseCtx). There is no file content — vulnerable or safe —
 * that can make this module emit a NUCLEI_* finding under those conditions:
 * doing so would require a real network round trip to an attacker-reachable
 * HTTP endpoint plus the nuclei binary, neither of which the corpus harness
 * provides or should provide. The module's only "static" logic (the env-var
 * gate and the SSRF host guard) never itself produces a Finding, so there is
 * nothing to assert a ruleId against.
 *
 * Correct outcome: no RuleCase entries.
 */
export const cases: RuleCase[] = [];
