/**
 * Corpus for the "scanners-run" CHECKS entry (runScanners in src/gate/checks/scanners.ts).
 *
 * No cases are authored here. Every finding id `runScanners` can emit —
 * POSSIBLE_SECRET (gitleaks), SEMGREP_* (semgrep), SCANNER_CRITICAL_CVE /
 * SCANNER_HIGH_CVE (trivy, osv-scanner), CHECKOV_* (checkov), and
 * SCANNER_EXECUTION_ERROR — is produced by parsing the JSON output of an
 * external scanner binary, not by security-mcp's own regex/heuristic engine
 * matching file content directly.
 *
 * Two properties make this untestable via a static single-file corpus sample:
 *  1. Each scanner task is only queued if `commandExists(command)` resolves
 *     true first (see runScanners in scanners.ts). In a test environment
 *     without gitleaks/semgrep/trivy/checkov/osv-scanner installed, the task
 *     list is empty and runScanners always returns [] regardless of what the
 *     sample file contains — a corpus "positive" case would never fire for a
 *     reason unrelated to detection quality.
 *  2. Even with the binary installed, the finding content depends on that
 *     external tool's own detection logic and JSON schema for the installed
 *     version, not on any pattern this module tests. That's integration
 *     testing a third-party tool, not corpus-testing a security-mcp rule.
 *
 * This is the "genuinely not testable this way" outcome anticipated by the
 * corpus contract: no RuleCase entries are authored for "scanners-run".
 */
import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [];
