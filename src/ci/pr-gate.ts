import { runPrGate, type GateMode } from "../gate/policy.js";

// Allow safe git revision operators (~ and ^) plus ref/path characters. CWE-88.
const SAFE_REF_RE = /^[a-zA-Z0-9_./~^-]+$/;
// Allow relative file/folder paths for targets. CWE-88.
const SAFE_TARGET_RE = /^[a-zA-Z0-9_./ -]+$/;

function safeEnvRef(envVar: string, defaultValue: string): string {
  const val = process.env[envVar] || defaultValue;
  if (!SAFE_REF_RE.test(val)) {
    console.error(`Invalid value for ${envVar}: "${val}". Using default: "${defaultValue}".`);
    return defaultValue;
  }
  return val;
}

function safeEnvTargets(envVar: string): string[] | undefined {
  const raw = process.env[envVar];
  if (!raw) return undefined;
  const targets = raw.split(",").map((t) => t.trim()).filter(Boolean);
  return targets.filter((t) => {
    if (!SAFE_TARGET_RE.test(t) || t.includes("..")) {
      console.error(`Skipping unsafe target: "${t}"`);
      return false;
    }
    return true;
  });
}

async function main() {
  const baseRef = safeEnvRef("SECURITY_GATE_BASE_REF", "origin/main");
  const headRef = safeEnvRef("SECURITY_GATE_HEAD_REF", "HEAD");
  const policyPath = process.env.SECURITY_GATE_POLICY || ".mcp/policies/security-policy.json";
  const mode = (process.env.SECURITY_GATE_MODE ?? "recent_changes") as GateMode;
  const targets = safeEnvTargets("SECURITY_GATE_TARGETS");

  const result = await runPrGate({ baseRef, headRef, policyPath, mode, targets });

  // Print result for Actions logs
  console.log(JSON.stringify(result, null, 2));

  if (result.status !== "PASS") {
    process.exit(2);
  }
}

main().catch((err) => {
  console.error("security gate crashed:", err);
  process.exit(3);
});
