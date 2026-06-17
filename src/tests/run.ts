import assert from "node:assert/strict";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { runPrGate } from "../gate/policy.js";
import { autoHardenTree } from "../gate/cloud-controls/apply.js";
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
    assert.ok(ids.includes("AI_BIAS_TESTING_ABSENT"));
  });

  await withFixture("agentic-malicious", async () => {
    const result = await runPrGate({
      mode: "folder_by_folder",
      targets: ["."],
      policyPath: ".mcp/policies/security-policy.json"
    });
    const ids = result.findings.map((finding) => finding.id);
    assert.ok(ids.includes("AGENT_INSTRUCTION_OVERRIDE"));
    assert.ok(ids.includes("AGENT_INSTRUCTION_EXFIL"));
    assert.ok(ids.includes("AGENT_PERSISTENCE_DIRECTIVE"));
    assert.ok(ids.includes("AGENT_TOOL_POISONING"));
    assert.ok(ids.includes("AGENT_CREDENTIAL_HARVEST"));
    assert.ok(ids.includes("AGENT_MEMORY_POISONING"));
    assert.ok(ids.includes("AGENT_HIDDEN_INSTRUCTION"));
    assert.ok(ids.includes("AGENT_REMOTE_INSTRUCTION_LOAD"));
    assert.ok(ids.includes("AGENT_PERMISSION_ESCALATION"));
    assert.ok(ids.includes("AGENT_BACKDOOR_INSERT"));
    assert.ok(ids.includes("AGENT_PROMPT_LEAK"));
  });

  await withFixture("aws-insecure", async () => {
    const result = await runPrGate({
      mode: "folder_by_folder",
      targets: ["terraform"],
      policyPath: ".mcp/policies/security-policy.json"
    });
    const ids = result.findings.map((finding) => finding.id);
    assert.ok(ids.includes("AWS_EC2_IMDSV2_REQUIRED"));
    assert.ok(ids.includes("AWS_RDS_NOT_PUBLIC"));
    assert.ok(ids.includes("AWS_S3_BUCKET_NO_PUBLIC_ACL"));
    assert.ok(ids.includes("AWS_S3_BLOCK_PUBLIC_ACCESS"));
    assert.ok(ids.includes("AWS_LAMBDA_URL_AUTH_REQUIRED"));
  });
}

async function runCloudControlRemediationTests(): Promise<void> {
  const tmp = mkdtempSync(path.join(tmpdir(), "aws-harden-"));
  const previous = process.cwd();
  try {
    cpSync(repoPath("fixtures", "aws-insecure", "terraform"), path.join(tmp, "terraform"), {
      recursive: true
    });
    process.chdir(tmp);

    const first = await autoHardenTree({ write: true });
    const appliedIds = new Set(first.applied.map((fix) => fix.ruleId));
    assert.ok(appliedIds.has("AWS_EC2_IMDSV2_REQUIRED"));
    assert.ok(appliedIds.has("AWS_RDS_NOT_PUBLIC"));
    assert.ok(appliedIds.has("AWS_S3_BUCKET_NO_PUBLIC_ACL"));
    assert.ok(appliedIds.has("AWS_S3_BLOCK_PUBLIC_ACCESS"));
    assert.ok(appliedIds.has("AWS_KMS_KEY_ROTATION"));
    assert.ok(appliedIds.has("AWS_LAMBDA_URL_AUTH_REQUIRED"));

    const hardened = readFileSync(path.join(tmp, "terraform", "main.tf"), "utf-8");
    assert.match(hardened, /http_tokens\s*=\s*"required"/);
    assert.match(hardened, /publicly_accessible\s*=\s*false/);
    assert.match(hardened, /acl\s*=\s*"private"/);
    assert.match(hardened, /enable_key_rotation\s*=\s*true/);
    assert.match(hardened, /authorization_type\s*=\s*"AWS_IAM"/);
    assert.match(hardened, /aws_s3_bucket_public_access_block/);

    // Idempotent: a second pass over the now-hardened tree applies nothing.
    const second = await autoHardenTree({ write: true });
    assert.equal(second.applied.length, 0);
    assert.equal(second.filesChanged.length, 0);
  } finally {
    process.chdir(previous);
    rmSync(tmp, { recursive: true, force: true });
  }
}

async function runNestedRemediationTests(): Promise<void> {
  const tmp = mkdtempSync(path.join(tmpdir(), "cloud-harden-"));
  const previous = process.cwd();
  try {
    cpSync(repoPath("fixtures", "gcp-insecure", "terraform"), path.join(tmp, "gcp"), {
      recursive: true
    });
    cpSync(repoPath("fixtures", "azure-insecure", "terraform"), path.join(tmp, "azure"), {
      recursive: true
    });
    process.chdir(tmp);

    const report = await autoHardenTree({ write: true });
    const appliedIds = new Set(report.applied.map((fix) => fix.ruleId));
    // GCP: depth-3 nested replace + insert into existing settings/ip_configuration blocks.
    assert.ok(appliedIds.has("GCP_SQL_NO_PUBLIC_IP"));
    assert.ok(appliedIds.has("GCP_SQL_REQUIRE_SSL"));
    assert.ok(appliedIds.has("GCP_STORAGE_UNIFORM_ACCESS"));
    // Azure.
    assert.ok(appliedIds.has("AZURE_STORAGE_HTTPS_ONLY"));
    assert.ok(appliedIds.has("AZURE_KV_PURGE_PROTECTION"));

    const gcp = readFileSync(path.join(tmp, "gcp", "main.tf"), "utf-8");
    assert.match(gcp, /ipv4_enabled\s*=\s*false/);
    assert.match(gcp, /require_ssl\s*=\s*true/);
    const azure = readFileSync(path.join(tmp, "azure", "main.tf"), "utf-8");
    assert.match(azure, /enable_https_traffic_only\s*=\s*true/);
    assert.match(azure, /purge_protection_enabled\s*=\s*true/);

    // Idempotent across both providers.
    const second = await autoHardenTree({ write: true });
    assert.equal(second.applied.length, 0);
  } finally {
    process.chdir(previous);
    rmSync(tmp, { recursive: true, force: true });
  }
}

async function runReviewWorkflowTests(): Promise<void> {
  cleanupFixtureReviewArtifacts("web-insecure");

  await withFixture("web-insecure", async () => {
    const run = await createReviewRun({
      mode: "folder_by_folder",
      remediationMode: "auto_apply",
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
  await runCloudControlRemediationTests();
  await runNestedRemediationTests();
  await runReviewWorkflowTests();
  console.log("security-mcp tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
