/**
 * MCP caller authentication for security-mcp.
 *
 * When SECURITY_MCP_SHARED_SECRET is set, every tool call is blocked until
 * security.authenticate is called with the matching token. This provides a
 * process-boundary guard against rogue processes that somehow obtain access
 * to the MCP stdio channel without being the intended AI coding agent.
 *
 * Design notes:
 * - One stdio session = one server process = one auth state (module singleton).
 * - Token comparison uses constant-time HMAC to eliminate length-based timing
 *   oracles (CWE-208). Both inputs are hashed to 32-byte digests before compare.
 * - After AUTH_MAX_ATTEMPTS failures the process exits to prevent brute-force.
 * - If SECURITY_MCP_SHARED_SECRET is absent, auth is disabled and all tools are
 *   immediately available (backwards-compatible default).
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Domain-separation constant for auth HMAC. Never changes. */
const HMAC_DOMAIN = "security-mcp-session-auth-v1";

/**
 * Minimum acceptable secret length (bytes).
 * OWASP ASVS L2 V2.9.1 requires 32 bytes (256 bits) for HMAC secrets.
 * NIST SP 800-107 §5.3.4 / SP 800-131A recommend ≥ 112-bit keys for HMAC-SHA256;
 * we enforce 32 bytes (256-bit) for full ASVS L2 compliance.
 */
const SECRET_MIN_BYTES = 32;

/** Maximum failed authentication attempts before the server process exits. */
const AUTH_MAX_ATTEMPTS = 3;

/** Unique ID for this server instance (for logging / correlation only). */
const SESSION_ID = randomBytes(16).toString("hex");

let _authenticated = false;
let _authenticatedAt: number | null = null;
let _attempts = 0;

/** Whether the caller must authenticate before using any other tool. */
export function isAuthRequired(): boolean {
  return typeof process.env["SECURITY_MCP_SHARED_SECRET"] === "string" &&
    process.env["SECURITY_MCP_SHARED_SECRET"].length > 0;
}

/**
 * Whether the current session is authenticated.
 * Always returns true when auth is disabled (no SECURITY_MCP_SHARED_SECRET).
 * Enforces session TTL: if the session has exceeded SECURITY_SESSION_TTL_MS
 * (default 8 hours), it is automatically invalidated and false is returned.
 */
export function isAuthenticated(): boolean {
  if (!isAuthRequired()) return true;
  if (_authenticated && _authenticatedAt) {
    // Guard against NaN/negative from malformed env var — attacker-set "" or "abc"
    // would produce NaN, making the comparison always false and bypassing TTL (CWE-1288).
    // Also cap the TTL at 24 hours (86400000 ms) to prevent an attacker who controls
    // the env from setting an arbitrarily large value that effectively disables TTL expiry.
    // OWASP ASVS V3.7.1: sessions must expire within a reasonable bound.
    const SESSION_TTL_MAX_MS = 86_400_000; // 24 hours absolute maximum
    const parsedTtl = Number.parseInt(process.env["SECURITY_SESSION_TTL_MS"] ?? "28800000", 10);
    const SESSION_TTL_MS = Number.isFinite(parsedTtl) && parsedTtl > 0
      ? Math.min(parsedTtl, SESSION_TTL_MAX_MS)
      : 28800000;
    if (Date.now() - _authenticatedAt > SESSION_TTL_MS) {
      _authenticated = false;
      _authenticatedAt = null;
      return false;
    }
  }
  return _authenticated;
}

/**
 * Explicitly log out the current session. Resets authentication state and
 * timestamp so the next tool call will require re-authentication.
 */
export function logout(): void {
  _authenticated = false;
  _authenticatedAt = null;
}

/**
 * Increment the failed-attempt counter regardless of whether the input is
 * structurally valid. Call this BEFORE Zod parsing in the authenticate handler
 * so that malformed requests still burn a lockout attempt (fixes CWE-307 bypass
 * via invalid-shape inputs that would otherwise never reach attemptAuth).
 */
export function recordAttempt(): void {
  if (isAuthRequired() && !_authenticated) {
    _attempts++;
  }
}

export function getSessionId(): string {
  return SESSION_ID;
}

/**
 * Attempt to authenticate the session with the provided token.
 *
 * Uses constant-time HMAC comparison to prevent timing oracles regardless of
 * token length. After AUTH_MAX_ATTEMPTS failures, terminates the process.
 */
export function attemptAuth(token: string): {
  success: boolean;
  sessionId?: string;
  attemptsRemaining?: number;
  reason?: string;
} {
  if (!isAuthRequired()) {
    return { success: true, sessionId: SESSION_ID };
  }

  if (_authenticated) {
    return { success: true, sessionId: SESSION_ID };
  }

  // NOTE: _attempts is incremented by recordAttempt() called BEFORE Zod parsing
  // in the server.ts handler. Do not increment here again to avoid double-counting.
  const remaining = AUTH_MAX_ATTEMPTS - _attempts;

  // Enforce lockout BEFORE any other check — including misconfiguration — so that
  // the short-secret path cannot bypass the three-strike limit (AUTH-001 / CWE-307).
  // Fix: use <= 0 (not < 0). With < 0, remaining==0 (i.e. _attempts==AUTH_MAX_ATTEMPTS)
  // would still reach the HMAC comparison — granting one extra attempt beyond policy.
  if (remaining <= 0) {
    setTimeout(() => process.exit(1), 200);
    return {
      success: false,
      reason: "Authentication failed."
    };
  }

  const secret = process.env["SECURITY_MCP_SHARED_SECRET"]!;

  if (Buffer.byteLength(secret, "utf-8") < SECRET_MIN_BYTES) {
    // Server misconfiguration — warn but do not leak the secret value or byte length.
    return {
      success: false,
      reason: "Authentication failed."
    };
  }

  // Hash both inputs to fixed-length 32-byte digests so timingSafeEqual always
  // receives same-length buffers (prevents length-based timing oracle, CWE-208).
  // Keys and messages are swapped relative to the original: the secret/token is
  // used as the HMAC key and HMAC_DOMAIN is the fixed message (AUTH-003 / CWE-327).
  const expected = createHmac("sha256", secret).update(HMAC_DOMAIN, "utf-8").digest();
  const provided = createHmac("sha256", token).update(HMAC_DOMAIN, "utf-8").digest();

  if (!timingSafeEqual(expected, provided)) {
    if (remaining <= 0) {
      // Schedule exit after a short delay so the error response can be sent.
      setTimeout(() => process.exit(1), 200);
      return {
        success: false,
        reason: "Authentication failed."
      };
    }
    return {
      success: false,
      // Do not expose attempt count to avoid targeted last-attempt attacks (AUTH-004 / CWE-204).
      reason: "Authentication failed."
    };
  }

  _authenticated = true;
  _authenticatedAt = Date.now();
  return { success: true, sessionId: SESSION_ID };
}

/**
 * Returns the preamble to prepend to the system prompt when authentication
 * is required but has not yet been completed.
 */
export function authSystemPromptPreamble(): string {
  if (!isAuthRequired()) return "";
  return [
    "## ⚠️ Authentication Required",
    "",
    "This security-mcp server requires authentication before any security tools can be used.",
    "**Call `security.authenticate` first** with the value of the `SECURITY_MCP_SHARED_SECRET`",
    "environment variable configured on this server.",
    "",
    "```",
    "security.authenticate({ token: \"<value of SECURITY_MCP_SHARED_SECRET>\" })",
    "```",
    "",
    "All other tool calls will be rejected with UNAUTHENTICATED until this step completes.",
    ""
  ].join("\n");
}
