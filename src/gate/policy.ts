import { z } from "zod";
import { GateResult, Finding } from "./result.js";
import { getChangedFiles } from "./diff.js";
import { detectSurfaces } from "./findings.js";
import { checkRequiredArtifacts } from "./checks/required-artifacts.js";
import { checkSecrets } from "./checks/secrets.js";
import { checkDependencies } from "./checks/dependencies.js";
import { checkWebNextjs } from "./checks/web-nextjs.js";
import { checkApi } from "./checks/api.js";
import { checkInfra } from "./checks/infra.js";
import { checkMobileIos } from "./checks/mobile-ios.js";
import { checkMobileAndroid } from "./checks/mobile-android.js";
import { checkAi } from "./checks/ai.js";
import { readFileSafe } from "../repo/fs.js";

const PolicySchema = z.object({
  name: z.string(),
  version: z.string(),
  artifacts_required: z
    .array(
      z.object({
        pattern: z.string(),
        on_changes: z.array(z.string())
      })
    )
    .default([]),
  required_checks: z.record(z.any()).default({}),
  requirements: z
    .array(
      z.object({
        id: z.string(),
        type: z.enum(["gate", "control"]).default("gate"),
        evidence: z.array(z.string()).default([])
      })
    )
    .default([])
});

export type Policy = z.infer<typeof PolicySchema>;

export async function loadPolicy(policyPath: string): Promise<Policy> {
  const raw = await readFileSafe(policyPath);
  const parsed = JSON.parse(raw);
  return PolicySchema.parse(parsed);
}

export async function runPrGate(opts: {
  baseRef?: string;
  headRef?: string;
  policyPath: string;
}): Promise<GateResult> {
  const policy = await loadPolicy(opts.policyPath);

  const changedFiles = await getChangedFiles({
    baseRef: opts.baseRef ?? "origin/main",
    headRef: opts.headRef ?? "HEAD"
  });

  const surfaces = detectSurfaces(changedFiles);

  const findings: Finding[] = [
    // Required artifacts first: threat models/checklists.
    ...(await checkRequiredArtifacts({ policy, changedFiles })),
    // Baseline scans / checks
    ...(await checkSecrets({ changedFiles })),
    ...(await checkDependencies({ changedFiles })),
    // Surface-specific checks (only run if that surface is impacted or exists)
    ...(surfaces.web ? await checkWebNextjs({ changedFiles }) : []),
    ...(surfaces.api ? await checkApi({ changedFiles }) : []),
    ...(surfaces.infra ? await checkInfra({ changedFiles }) : []),
    ...(surfaces.mobileIos ? await checkMobileIos({ changedFiles }) : []),
    ...(surfaces.mobileAndroid ? await checkMobileAndroid({ changedFiles }) : []),
    ...(surfaces.ai ? await checkAi({ changedFiles }) : [])
  ];

  const status = findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL")
    ? "FAIL"
    : "PASS";

  return {
    status,
    policyVersion: policy.version,
    evaluatedAt: new Date().toISOString(),
    scope: { changedFiles, surfaces },
    findings
  };
}