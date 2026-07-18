/**
 * Frozen, parsed-once security configuration.
 *
 * Every permissive default in security-mcp is intentional for frictionless local
 * use (no MCP auth secret required, HMAC-signed policy/audit chains optional,
 * live network egress for threat intel allowed) — see README's "Is security-mcp
 * safe to use?" section for the full residual-risk accounting of each default.
 *
 * SECURITY_STRICT=1 flips every one of those defaults to its locked-down setting
 * and, since a "strict" mode that silently falls back to a permissive default
 * whenever a required key is missing wouldn't actually be strict, refuses to
 * start at all if the environment can't satisfy it. This module is the single
 * place that decision is made — importing it is what makes the check run, so
 * every entrypoint (the MCP server, the CI gate) must import it early.
 *
 * The two HMAC keys gate the gate engine itself (policy integrity, audit-chain
 * integrity) and are required in strict mode for BOTH entrypoints. The MCP
 * shared secret only means something for a live MCP server session — a CI gate
 * run has no persistent session to authenticate a caller against — so it's a
 * separate, MCP-server-only requirement, asserted explicitly by server.ts via
 * assertStrictMcpAuthRequirements() rather than folded into CONFIG's own
 * unconditional startup check.
 */

function envFlag(name: string): boolean {
  const v = process.env[name];
  return v === "1" || v === "true";
}

export type SecurityConfig = {
  /** SECURITY_STRICT=1 was set. Every other field here is derived from this. */
  readonly strict: boolean;
  /** Mirrors auth.ts's isAuthRequired() — true whenever SECURITY_MCP_SHARED_SECRET
   *  is set. Exposed here too so callers can assert it's true, not just possible. */
  readonly authRequired: boolean;
  /** True when live third-party network egress (CISA KEV/EPSS, OpenSSF Scorecard,
   *  npm registry audit calls) should be skipped. In strict mode this is forced
   *  on regardless of SECURITY_OFFLINE, since a locked-down environment is the
   *  one most likely to mandate no outbound calls; call sites should read
   *  CONFIG.offline instead of process.env["SECURITY_OFFLINE"] directly so the
   *  strict-mode override actually takes effect. */
  readonly offline: boolean;
};

const STRICT_REQUIRED_ENV_VARS = ["SECURITY_POLICY_HMAC_KEY", "SECURITY_AUDIT_HMAC_KEY"] as const;

function assertStrictRequirements(): void {
  const missing = STRICT_REQUIRED_ENV_VARS.filter((name) => !process.env[name]);
  if (missing.length === 0) return;
  throw new Error(
    `SECURITY_STRICT=1 requires ${missing.join(", ")} to be set, but ` +
    `${missing.length === 1 ? "it is" : "they are"} missing. Strict mode means no ` +
    "permissive default is active — configure every required key, or unset " +
    "SECURITY_STRICT to run with the (documented, but weaker) frictionless defaults."
  );
}

/**
 * MCP-server-only strict requirement: a shared secret must be configured, since
 * strict mode's "auth required" default only means something with a secret to
 * authenticate against. Call from an MCP-server entrypoint, not the CI gate.
 */
export function assertStrictMcpAuthRequirements(): void {
  if (!CONFIG.strict) return;
  if (!process.env["SECURITY_MCP_SHARED_SECRET"]) {
    throw new Error(
      "SECURITY_STRICT=1 requires SECURITY_MCP_SHARED_SECRET to be set for an MCP " +
      "server session — strict mode's mandatory-auth default has no secret to " +
      "authenticate against otherwise. Configure it, or unset SECURITY_STRICT."
    );
  }
}

function computeConfig(): SecurityConfig {
  const strict = envFlag("SECURITY_STRICT");
  if (strict) assertStrictRequirements();
  const secret = process.env["SECURITY_MCP_SHARED_SECRET"];
  return Object.freeze({
    strict,
    authRequired: strict || (typeof secret === "string" && secret.length > 0),
    offline: strict || envFlag("SECURITY_OFFLINE")
  });
}

/** Computed once at import time — see the module doc comment for why that matters. */
export const CONFIG: SecurityConfig = computeConfig();
