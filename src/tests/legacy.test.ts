import assert from "node:assert/strict";
import test from "node:test";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadCorpusPolicy, runCase, summarize } from "./corpus/runner.js";
import type { RuleCase } from "./corpus/types.js";
import { runPrGate } from "../gate/policy.js";
import { autoHardenTree } from "../gate/cloud-controls/apply.js";
import { checkCloudControls } from "../gate/checks/cloud-controls.js";
import { createReviewAttestation, createReviewRun, readReviewRun, updateReviewStep } from "../review/store.js";
import { ensureSkill, readBundledSkillBody, listBundledSkills, buildInitialAgentNames } from "../mcp/orchestration.js";
import { writeJsonServers, writeCodexTomlConfig } from "../cli/install.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { selectFortifyAgents, resolveFortifyScope, extractSearchTerms, CORE_TARGETED_TEAM } from "../mcp/fortify.js";
import { withWorkspace } from "../repo/workspace.js";
import type { StackContext } from "../types/agent-run.js";
import type { RepoMatch } from "../repo/search.js";

const emptyStack: StackContext = {
  languages: [],
  frameworks: [],
  databases: [],
  cloudProvider: [],
  paymentProcessor: [],
  hasAI: false,
  hasMobile: false,
  hasPII: false,
  hasPayments: false,
  packageManagers: [],
  ciPlatform: []
};

function repoPath(...parts: string[]): string {
  return path.join(process.cwd(), ...parts);
}

function cleanupFixtureReviewArtifacts(fixtureName: string): void {
  const fixtureRoot = repoPath("fixtures", fixtureName, ".mcp");
  rmSync(path.join(fixtureRoot, "reports"), { recursive: true, force: true });
  rmSync(path.join(fixtureRoot, "reviews"), { recursive: true, force: true });
  rmSync(path.join(fixtureRoot, "audit"), { recursive: true, force: true });
}

// Scopes the workspace root via AsyncLocalStorage instead of process.chdir(), so
// fixture-backed tests no longer mutate global process state and can run concurrently.
async function withFixture<T>(fixtureName: string, fn: () => Promise<T>): Promise<T> {
  return withWorkspace(repoPath("fixtures", fixtureName), fn);
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
  // Portable agent delivery is registered.
  assert.match(serverSource, /HOST_ADAPTATION_PREAMBLE/);
  assert.match(serverSource, /skill:\/\/catalog/);
  assert.match(serverSource, /skill:\/\/\{name\}/);
  // One-shot fortify: tool + prompt registered, and trigger wording documented.
  assert.match(serverSource, /"security\.fortify"/);
  assert.match(serverSource, /server\.prompt\(\s*"fortify"/);
  assert.match(readme, /security\.fortify/);
  assert.match(skill, /security\.fortify/);
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
  try {
    cpSync(repoPath("fixtures", "aws-insecure", "terraform"), path.join(tmp, "terraform"), {
      recursive: true
    });

    await withWorkspace(tmp, async () => {
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
    });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

async function runNestedRemediationTests(): Promise<void> {
  const tmp = mkdtempSync(path.join(tmpdir(), "cloud-harden-"));
  try {
    cpSync(repoPath("fixtures", "gcp-insecure", "terraform"), path.join(tmp, "gcp"), {
      recursive: true
    });
    cpSync(repoPath("fixtures", "azure-insecure", "terraform"), path.join(tmp, "azure"), {
      recursive: true
    });

    await withWorkspace(tmp, async () => {
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
    });
  } finally {
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

async function runCfnBicepDetectionTests(): Promise<void> {
  await withFixture("cfn-insecure", async () => {
    const ids = new Set((await checkCloudControls({ changedFiles: [] })).map((f) => f.id));
    assert.ok(ids.has("CFN_S3_NO_PUBLIC_ACL"));
    assert.ok(ids.has("CFN_RDS_NOT_PUBLIC"));
    assert.ok(ids.has("CFN_RDS_STORAGE_ENCRYPTED"));
    assert.ok(ids.has("CFN_SG_OPEN_INGRESS"));
  });

  await withFixture("bicep-insecure", async () => {
    const ids = new Set((await checkCloudControls({ changedFiles: [] })).map((f) => f.id));
    assert.ok(ids.has("BICEP_STORAGE_HTTPS_ONLY"));
    assert.ok(ids.has("BICEP_STORAGE_MIN_TLS"));
    assert.ok(ids.has("BICEP_SQL_NO_PUBLIC"));
  });
}

// security.fortify's pure logic: agent selection must not depend on a fixed
// feature-name table (users name arbitrary surfaces), and scope resolution must
// generalize to any phrasing via generic word extraction, not a category lookup.
async function runFortifyLogicTests(): Promise<void> {
  // Arbitrary, non-overlapping targets all get the same generic core team.
  for (const target of ["lock down the forms", "secure our payment flow", "harden the admin panel"]) {
    const selection = selectFortifyAgents(target, emptyStack, buildInitialAgentNames);
    assert.equal(selection.wholeCodebase, false, `expected scoped selection for "${target}"`);
    for (const agent of CORE_TARGETED_TEAM) {
      assert.ok(selection.agents.includes(agent), `expected core team member "${agent}" for target "${target}"`);
    }
  }

  // Whole-codebase target falls back to the full auto-selected roster, unchanged.
  const wholeCodebase = selectFortifyAgents("the whole codebase", emptyStack, buildInitialAgentNames);
  assert.equal(wholeCodebase.wholeCodebase, true);
  assert.deepEqual(wholeCodebase.agents, buildInitialAgentNames(emptyStack));

  // Cloud domain signal layers cloud specialists on top of the core team, not instead of it.
  const cloudTarget = selectFortifyAgents("harden our AWS account", { ...emptyStack, cloudProvider: ["aws"] }, buildInitialAgentNames);
  assert.equal(cloudTarget.wholeCodebase, false);
  assert.ok(cloudTarget.agents.includes("cloud-infra-specialist"));
  assert.ok(cloudTarget.agents.includes("aws-penetration-tester"));
  for (const agent of CORE_TARGETED_TEAM) {
    assert.ok(cloudTarget.agents.includes(agent), `cloud target should still include core team member "${agent}"`);
  }

  // Generic word extraction, not a maintained category lookup.
  assert.deepEqual(extractSearchTerms("the payment flow"), ["payment", "flow"]);
  assert.deepEqual(extractSearchTerms("file uploads"), ["file", "uploads"]);
  assert.deepEqual(extractSearchTerms("lock down the forms"), ["forms"]);

  // Explicit scope override passes through verbatim; search is never consulted.
  let searchCalls = 0;
  const stubSearchNeverCalled = async (): Promise<RepoMatch[]> => { searchCalls++; return []; };
  const overrideScope = await resolveFortifyScope(
    "forms",
    { mode: "folder_by_folder", targets: ["src/forms"] },
    stubSearchNeverCalled
  );
  assert.equal(overrideScope.resolvedFrom, "override");
  assert.deepEqual(overrideScope.targets, ["src/forms"]);
  assert.equal(searchCalls, 0);

  // Narrow target, few matched files -> file_by_file.
  const fewFiles: RepoMatch[] = [
    { file: "src/forms/login.ts", line: 1, preview: "" },
    { file: "src/forms/signup.ts", line: 1, preview: "" }
  ];
  const fewScope = await resolveFortifyScope("forms", {}, async () => fewFiles);
  assert.equal(fewScope.mode, "file_by_file");
  assert.deepEqual(new Set(fewScope.targets), new Set(["src/forms/login.ts", "src/forms/signup.ts"]));

  // Narrow target, many matched files -> folder_by_folder grouped by dirname.
  const manyFiles: RepoMatch[] = Array.from({ length: 20 }, (_, i) => ({
    file: `src/forms/module${i}/handler.ts`,
    line: 1,
    preview: ""
  }));
  const manyScope = await resolveFortifyScope("forms", {}, async () => manyFiles);
  assert.equal(manyScope.mode, "folder_by_folder");
  assert.equal(manyScope.targets.length, 20);

  // No matches at all -> conservative fallback to recent_changes, not an empty scan.
  const emptyScope = await resolveFortifyScope("a nonexistent surface xyz", {}, async () => []);
  assert.equal(emptyScope.mode, "recent_changes");
  assert.equal(emptyScope.resolvedFrom, "search_empty_fallback");
  assert.ok(emptyScope.notes.length > 0);

  // Root-level file matches must not collapse into a "." folder (that would mean
  // "scan the entire repo root", defeating scope narrowing) when other real folders
  // matched too -- root files are noted instead, and real folders stay precise.
  const mixedFiles: RepoMatch[] = [
    { file: "README.md", line: 1, preview: "" },
    ...Array.from({ length: 13 }, (_, i) => ({ file: `src/forms/module${i}/handler.ts`, line: 1, preview: "" }))
  ];
  const mixedScope = await resolveFortifyScope("forms", {}, async () => mixedFiles);
  assert.equal(mixedScope.mode, "folder_by_folder");
  assert.ok(!mixedScope.targets.includes("."), "root-level match must not become a \".\" folder target");
  assert.ok(mixedScope.notes.some((n) => n.includes("README.md")), "root-level match should be called out in notes");

  // When EVERY match is root-level, fall back to file_by_file on those files directly.
  const onlyRootFiles: RepoMatch[] = [
    { file: "README.md", line: 1, preview: "" },
    { file: "package.json", line: 1, preview: "" }
  ];
  const onlyRootScope = await resolveFortifyScope("forms", {}, async () => onlyRootFiles);
  assert.equal(onlyRootScope.mode, "file_by_file");
  assert.deepEqual(new Set(onlyRootScope.targets), new Set(["README.md", "package.json"]));
}

// Every bundled agent must be serveable at full persona over MCP, so no agent is
// unrunnable on a non-Claude client. ensure_skill must return the full body even
// when ~/.claude is absent.
async function runAgentDeliveryTests(): Promise<void> {
  const skills = listBundledSkills();
  assert.ok(skills.length >= 90, `expected the full agent roster, got ${skills.length}`);
  for (const name of ["ciso-orchestrator", "senior-security-engineer", "agentic-instruction-auditor"]) {
    assert.ok(skills.includes(name), `catalog missing user-invocable agent: ${name}`);
  }
  for (const name of skills) {
    const body = readBundledSkillBody(name);
    assert.ok(body && body.length > 0, `empty persona body for agent: ${name}`);
  }
  // Persona fidelity: the orchestrator keeps its legitimate control-plane references
  // (would be stripped by the network-download sanitizer, must not be for bundled).
  const ciso = readBundledSkillBody("ciso-orchestrator");
  assert.ok(ciso);
  assert.match(ciso, /orchestration\.ensure_skill/);

  // ensure_skill returns the full body over MCP even with no ~/.claude layout.
  const prevHome = process.env["HOME"];
  const tmpHome = mkdtempSync(path.join(tmpdir(), "home-noclaude-"));
  try {
    process.env["HOME"] = tmpHome;
    const res = await ensureSkill({ skillName: "threat-modeler" });
    assert.ok(res.content && res.content.length > 0, "ensureSkill returned empty content");
  } finally {
    if (prevHome === undefined) delete process.env["HOME"]; else process.env["HOME"] = prevHome;
    rmSync(tmpHome, { recursive: true, force: true });
  }
}

// The installer must write the correct per-client shape: VS Code uses `servers`,
// Windsurf omits `type`, Codex TOML merges without clobbering and is idempotent.
async function runInstallerWriterTests(): Promise<void> {
  const tmp = mkdtempSync(path.join(tmpdir(), "mcp-writers-"));
  try {
    const vs = path.join(tmp, ".vscode", "mcp.json");
    writeJsonServers(vs, "servers", "with-type", false, false);
    const vsJson = JSON.parse(readFileSync(vs, "utf-8")) as Record<string, Record<string, { command?: string; args?: string[]; type?: string }>>;
    assert.ok(vsJson["servers"]?.["security-mcp"], "VS Code servers entry missing");
    assert.equal(vsJson["mcpServers"], undefined);
    assert.equal(vsJson["mcp.servers"], undefined);
    assert.equal(vsJson["servers"]["security-mcp"].command, "npx");
    assert.ok(vsJson["servers"]["security-mcp"].args?.includes("security-mcp@latest"));

    const ws = path.join(tmp, "windsurf.json");
    writeJsonServers(ws, "mcpServers", "no-type", false, false);
    const wsJson = JSON.parse(readFileSync(ws, "utf-8")) as Record<string, Record<string, { type?: string }>>;
    assert.equal(wsJson["mcpServers"]["security-mcp"].type, undefined, "Windsurf entry must omit type");

    const cx = path.join(tmp, "config.toml");
    writeFileSync(cx, '[mcp_servers.other]\ncommand = "x"\n# keep me\n', "utf-8");
    writeCodexTomlConfig(cx, false, false);
    let toml = readFileSync(cx, "utf-8");
    assert.match(toml, /\[mcp_servers\.security-mcp\]/);
    assert.match(toml, /security-mcp@latest/);
    assert.match(toml, /\[mcp_servers\.other\]/);
    assert.match(toml, /# keep me/);
    // Idempotent: second write does not duplicate the table.
    writeCodexTomlConfig(cx, false, false);
    toml = readFileSync(cx, "utf-8");
    assert.equal((toml.match(/\[mcp_servers\.security-mcp\]/g) ?? []).length, 1, "Codex table not idempotent");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

// End-to-end MCP protocol check: the server must expose the agent prompts and the
// skill:// resources so every client can discover and load the full roster.
async function runMcpSurfaceTests(): Promise<void> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [repoPath("dist", "mcp", "server.js")]
  });
  const client = new Client({ name: "security-mcp-tests", version: "0.0.0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    const promptNames = (await client.listPrompts()).prompts.map((p) => p.name);
    for (const n of ["ciso-orchestrator", "senior-security-engineer", "agentic-instruction-auditor", "fortify"]) {
      assert.ok(promptNames.includes(n), `MCP prompt missing: ${n}`);
    }
    const resourceUris = (await client.listResources()).resources.map((r) => r.uri);
    assert.ok(resourceUris.includes("skill://catalog"), "skill://catalog resource missing");
    assert.ok(resourceUris.length > 90, `expected full roster of resources, got ${resourceUris.length}`);

    const persona = await client.readResource({ uri: "skill://ciso-orchestrator" });
    const personaText = (persona.contents[0] as { text?: string }).text ?? "";
    assert.match(personaText, /CISO Orchestrator/);

    const gp = await client.getPrompt({ name: "ciso-orchestrator" });
    const body = (gp.messages[0]?.content as { text?: string }).text ?? "";
    assert.match(body, /Host adaptation/);
    assert.match(body, /CISO Orchestrator/);

    const fortifyPrompt = await client.getPrompt({ name: "fortify" });
    const fortifyBody = (fortifyPrompt.messages[0]?.content as { text?: string }).text ?? "";
    assert.match(fortifyBody, /Host adaptation/);
    assert.match(fortifyBody, /security\.fortify/);
  } finally {
    await client.close();
  }
}

// security.start_review must default to auto_apply (no required_user_decision question)
// when remediationMode is omitted, and still honor an explicit detection_only choice.
async function runStartReviewDefaultTests(): Promise<void> {
  cleanupFixtureReviewArtifacts("web-insecure");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [repoPath("dist", "mcp", "server.js")],
    cwd: repoPath("fixtures", "web-insecure")
  });
  const client = new Client({ name: "security-mcp-tests", version: "0.0.0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    const defaultResult = await client.callTool({
      name: "security.start_review",
      arguments: { mode: "folder_by_folder", targets: ["src"] }
    });
    const defaultText = (defaultResult.content as Array<{ text?: string }>)[0]?.text ?? "{}";
    const defaultParsed = JSON.parse(defaultText) as { required_user_decision?: boolean; remediationMode?: string };
    assert.equal(defaultParsed.required_user_decision, undefined, "start_review must not ask before proceeding");
    assert.equal(defaultParsed.remediationMode, "auto_apply", "start_review must default to auto_apply");

    const detectionResult = await client.callTool({
      name: "security.start_review",
      arguments: { mode: "folder_by_folder", targets: ["src"], remediationMode: "detection_only" }
    });
    const detectionText = (detectionResult.content as Array<{ text?: string }>)[0]?.text ?? "{}";
    const detectionParsed = JSON.parse(detectionText) as { remediationMode?: string };
    assert.equal(detectionParsed.remediationMode, "detection_only", "explicit detection_only must still be honored");
  } finally {
    await client.close();
    cleanupFixtureReviewArtifacts("web-insecure");
  }
}

// Compliance reports must NOT claim controls "satisfied" from the mere absence of a
// gate run. Regression for the prior satisfied-by-default logic that returned every
// control as satisfied when called with no run data.
async function runComplianceTruthTests(): Promise<void> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [repoPath("dist", "mcp", "server.js")]
  });
  const client = new Client({ name: "security-mcp-tests", version: "0.0.0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    const res = await client.callTool({
      name: "security.generate_compliance_report",
      arguments: { framework: "SOC2", outputFormat: "json" }
    });
    const parsed = JSON.parse((res.content as Array<{ text?: string }>)[0]?.text ?? "{}") as {
      summary?: { total: number; satisfied: number; unverified: number };
      caveat?: string;
    };
    assert.ok(parsed.summary, "compliance report must include a summary");
    assert.equal(parsed.summary!.satisfied, 0, "no gate run must yield ZERO satisfied controls (was satisfied-by-default)");
    assert.equal(parsed.summary!.unverified, parsed.summary!.total, "every control must be 'unverified' without a gate run");
    assert.ok(parsed.caveat && /not an audit/i.test(parsed.caveat), "report must carry the not-an-audit caveat");

    // Retracted frameworks must be rejected at input validation, not silently processed.
    const gdpr = await client.callTool({
      name: "security.generate_compliance_report",
      arguments: { framework: "GDPR", outputFormat: "json" }
    });
    const gdprText = (gdpr.content as Array<{ text?: string }>)[0]?.text ?? "";
    assert.match(gdprText, /validation error|Invalid/i, "GDPR framework must be rejected, not offered");
  } finally {
    await client.close();
  }
}

// Runs every per-rule TP/TN corpus case (src/tests/corpus/*.corpus.ts) against the
// real CHECKS registry, and writes the empirical result to
// .mcp/reports/rule-quality.json — the product's first-ever measured false-positive
// rate. A case fails the build if its rule does not fire on the positive sample or
// DOES fire on the negative sample: either signals a genuine problem (a broken rule,
// or a corpus case that doesn't actually discriminate).
async function runRuleCorpusTests(): Promise<void> {
  const corpusDir = repoPath("dist", "tests", "corpus");
  const files = existsSync(corpusDir)
    ? readdirSync(corpusDir).filter((f) => f.endsWith(".corpus.js"))
    : [];

  const allCases: RuleCase[] = [];
  for (const file of files) {
    const mod = (await import(path.join(corpusDir, file).replace(/\\/g, "/"))) as { cases?: RuleCase[] };
    if (mod.cases) allCases.push(...mod.cases);
  }

  if (allCases.length === 0) {
    console.log("[rule-corpus] no corpus cases found yet — skipping (bootstrap-safe).");
    return;
  }

  const policy = await loadCorpusPolicy();
  const results = [];
  for (const kase of allCases) {
    results.push(await runCase(policy, kase));
  }
  const report = summarize(results);

  const reportDir = repoPath(".mcp", "reports");
  mkdirSync(reportDir, { recursive: true });
  writeFileSync(path.join(reportDir, "rule-quality.json"), JSON.stringify(report, null, 2) + "\n", "utf-8");

  console.log(
    `[rule-corpus] ${report.totalCases} case(s) — tpRate=${report.tpRate.toFixed(2)} fpRate=${report.fpRate.toFixed(2)}`
  );
  if (report.failures.length > 0) {
    console.error("[rule-corpus] failures:", JSON.stringify(report.failures, null, 2));
  }
  assert.equal(report.failures.length, 0, `${report.failures.length} rule-corpus case(s) failed — see .mcp/reports/rule-quality.json`);
}

// Registered (and awaited, one at a time) in the same order the old hand-rolled
// main() called them in — several share fixture state (web-insecure's .mcp/
// artifacts) via cleanupFixtureReviewArtifacts() before/after, so this preserves
// the sequential guarantee that ordering depended on rather than assuming
// node:test's default scheduling would happen to match.
await test("agent delivery (bundled skills serveable over MCP)", runAgentDeliveryTests);
await test("installer writers (VS Code / Windsurf / Codex TOML)", runInstallerWriterTests);
await test("MCP surface (prompts + skill:// resources)", runMcpSurfaceTests);
await test("start_review defaults to auto_apply", runStartReviewDefaultTests);
await test("compliance report truth (no satisfied-by-default)", runComplianceTruthTests);
await test("prompt conformance (SECURITY_PROMPT/skills/README/server.ts)", runPromptConformanceTests);
await test("fixture gate findings (web/infra/ai/agentic/aws insecure)", runFixtureGateTests);
await test("cloud-control remediation (AWS autoharden, idempotent)", runCloudControlRemediationTests);
await test("nested cloud-control remediation (GCP + Azure)", runNestedRemediationTests);
await test("CFN/Bicep detection", runCfnBicepDetectionTests);
await test("review workflow (run -> attest)", runReviewWorkflowTests);
await test("fortify logic (agent selection + scope resolution)", runFortifyLogicTests);
await test("rule corpus (per-rule TP/TN, measures tpRate/fpRate)", runRuleCorpusTests);
