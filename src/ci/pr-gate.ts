import { runPrGate } from "../gate/policy.js";

// Allowlist refs to the same safe character set enforced in diff.ts. CWE-88.
const SAFE_REF_RE = /^[a-zA-Z0-9_.\-/]+$/;

function safeEnvRef(envVar: string, defaultValue: string): string {
  const val = process.env[envVar] || defaultValue;
  if (!SAFE_REF_RE.test(val)) {
    console.error(`Invalid value for ${envVar}: "${val}". Using default: "${defaultValue}".`);
    return defaultValue;
  }
  return val;
}

async function main() {
  const baseRef = safeEnvRef("SECURITY_GATE_BASE_REF", "origin/main");
  const headRef = safeEnvRef("SECURITY_GATE_HEAD_REF", "HEAD");
  const policyPath = process.env.SECURITY_GATE_POLICY || ".mcp/policies/security-policy.json";

  const result = await runPrGate({ baseRef, headRef, policyPath });

  // Print result for Actions logs
  console.log(JSON.stringify(result, null, 2));

  if (result.status !== "PASS") {
    process.exit(2);
  }
}

// eslint-disable-next-line unicorn/prefer-top-level-await
main().catch((err) => {
  console.error("security gate crashed:", err);
  process.exit(3);
});