import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { runPrGate } from "../gate/policy.js";
import { createReviewAttestation, createReviewRun, readReviewRun, updateReviewStep } from "../review/store.js";

function repoPath(...parts: string[]): string {
  return path.join(process.cwd(), ...parts);
}

function cleanupFixtureReviewArtifacts(fixtureName: string): void {
  const fixtureRoot = repoPath("fixtures", fixtureName, ".mcp");
  rmSync(path.join(fixtureRoot, "reports"), { recursive: true, force: true });
  rmSync(path.join(fixtureRoot, "reviews"), { recursive: true, force: true });
}

async function withFixture<T>(fixtureName: string, fn: () => Promise<T>): Promise<T> {
  const previous = process.cwd();
  process.chdir(repoPath("fixtures", fixtureName));
  try {
    return await fn();
  } finally {
    process.chdir(previous);
  }
}

async function runPromptConformanceTests(): Promise<void> {
  const prompt = readFileSync(repoPath("prompts", "SECURITY_PROMPT.md"), "utf-8");
  const skill = readFileSync(repoPath("skills", "senior-security-engineer", "SKILL.md"), "utf-8");
  const readme = readFileSync(repoPath("README.md"), "utf-8");
  const serverSource = readFileSync(repoPath("src", "mcp", "server.ts"), "utf-8");

  assert.match(prompt, /security\.start_review/);
  assert.match(prompt, /security\.attest_review/);
  assert.match(prompt, /Human approval is mandatory/i);
  assert.match(skill, /90% fixing/);
  assert.match(skill, /security\.self_heal_loop/);
  assert.match(readme, /security\.start_review/);
  assert.match(readme, /security\.attest_review/);
  assert.match(serverSource, /"security\.start_review"/);
  assert.match(serverSource, /"security\.attest_review"/);
}

async function runFixtureGateTests(): Promise<void> {
  await withFixture("web-insecure", async () => {
    const result = await runPrGate({
      mode: "folder_by_folder",
      targets: ["src"],
      policyPath: ".mcp/policies/security-policy.json"
    });
    const ids = result.findings.map((finding) => finding.id);
    assert.ok(ids.includes("WEB_HEADERS_MISSING"));
    assert.ok(ids.includes("DANGEROUSLY_SET_INNER_HTML"));
    assert.ok(ids.includes("SSRF_GUARD_REQUIRED"));
    assert.ok(result.confidence);
  });

  await withFixture("infra-insecure", async () => {
    const result = await runPrGate({
      mode: "folder_by_folder",
      targets: ["terraform"],
      policyPath: ".mcp/policies/security-policy.json"
    });
    const ids = result.findings.map((finding) => finding.id);
    assert.ok(ids.includes("PUBLIC_EXPOSURE_RISK"));
    assert.ok(ids.includes("CONTROL_EVIDENCE_MISSING"));
  });

  await withFixture("ai-insecure", async () => {
    const result = await runPrGate({
      mode: "folder_by_folder",
      targets: ["ai"],
      policyPath: ".mcp/policies/security-policy.json"
    });
    const ids = result.findings.map((finding) => finding.id);
    assert.ok(ids.includes("AI_OUTPUT_BOUNDS_MISSING"));
  });
}

async function runReviewWorkflowTests(): Promise<void> {
  cleanupFixtureReviewArtifacts("web-insecure");

  await withFixture("web-insecure", async () => {
    const run = await createReviewRun({
      mode: "folder_by_folder",
      targets: ["src"]
    });
    await updateReviewStep(run.id, "scan_strategy", "completed", { mode: "folder_by_folder", targets: ["src"] });
    await updateReviewStep(run.id, "threat_model", "completed", { feature: "fixture web flow" });
    await updateReviewStep(run.id, "checklist", "completed", { surface: "web" });
    await updateReviewStep(run.id, "run_pr_gate", "completed", { status: "FAIL", confidence: { score: 20 } });

    const saved = await readReviewRun(run.id);
    assert.equal(saved.steps["run_pr_gate"]?.status, "completed");

    const attestation = await createReviewAttestation(run.id, {
      runId: run.id,
      steps: saved.steps
    });
    assert.ok(existsSync(attestation.path));
    assert.match(attestation.sha256, /^[a-f0-9]{64}$/);
  });

  cleanupFixtureReviewArtifacts("web-insecure");
}

async function main(): Promise<void> {
  await runPromptConformanceTests();
  await runFixtureGateTests();
  await runReviewWorkflowTests();
  console.log("security-mcp tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
