import { runPrGate } from "../gate/policy.js";

async function main() {
  const baseRef = process.env.SECURITY_GATE_BASE_REF || "origin/main";
  const headRef = process.env.SECURITY_GATE_HEAD_REF || "HEAD";
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