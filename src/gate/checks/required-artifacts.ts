import fg from "fast-glob";
import picomatch from "picomatch";
import { Finding } from "../result.js";
import { Policy } from "../policy.js";

export async function checkRequiredArtifacts(opts: {
  policy: Policy;
  changedFiles: string[];
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const req of opts.policy.artifacts_required ?? []) {
    const matchers = req.on_changes.map((pattern) => picomatch(pattern, { dot: true }));
    const touched = opts.changedFiles.some((file) => matchers.some((match) => match(file)));

    if (!touched) continue;

    const matches = await fg(req.pattern, { dot: true });
    if (matches.length === 0) {
      findings.push({
        id: "ARTIFACTS_MISSING",
        title: `Missing required artifact(s) for changes affecting: ${req.on_changes.join(", ")}`,
        severity: "HIGH",
        evidence: [`Expected at least one file matching: ${req.pattern}`],
        requiredActions: [
          `Add required artifact(s) matching "${req.pattern}" (e.g., threat model for the changed flow).`,
          `Include STRIDE + OWASP mapping + MITRE mapping + required logging and tests.`
        ]
      });
    }
  }

  return findings;
}