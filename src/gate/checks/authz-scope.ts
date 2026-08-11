/**
 * Scoped authorization heuristics, shared by the two rules that ask "does this
 * publicly reachable handler verify its caller?" —
 * `WEB_SERVER_ACTION_NO_AUTHZ` (web-hardening.ts) and
 * `VIBE_API_ROUTE_NO_SERVER_AUTHZ` (vibe-coding.ts).
 *
 * Both rules used to answer that question by testing an "auth verifier" regex and
 * an "intentionally public" regex against the WHOLE FILE. Whole-file matching made
 * both rules suppressible by text that authorizes nothing:
 *
 *   'use server';
 *   // move this to the webhook handler later           <- the word "webhook"
 *   export async function deleteDoc(id: string) {          suppressed the finding
 *     await prisma.doc.delete({ where: { id } });
 *   }
 *
 *   'use server';
 *   const getToken = () => null;                        <- an identifier the auth
 *   export async function deleteDoc(id: string) {          regex recognised, never
 *     await prisma.doc.delete({ where: { id } });          called, returning null
 *   }
 *
 * Both files are unauthenticated public POST endpoints that delete rows, and both
 * passed the gate. The evasion needs no intent: a comment mentioning a webhook, an
 * import of a `getToken` helper used elsewhere, or a `currentUser` type name is
 * enough to silence the rule for the whole file.
 *
 * The functions here answer the same question per exported handler, over that
 * handler's own body, and require the verifier to appear in call position.
 */

/** One exported function found in a source file. */
export type ExportedHandler = {
  /** Declared name, or "default" / "(anonymous)" when there is none. */
  name: string;
  /** Source text from the `export` keyword to the end of the function body. */
  region: string;
  /** The function body including its braces. Empty when no body could be located. */
  body: string;
  /** Comment lines immediately above the export — where a `// PUBLIC` mark lives. */
  precedingComments: string;
};

const EXPORT_DECL_RE =
  /export\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*([A-Za-z0-9_$]+)?|(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=)/g;

/**
 * Walks `content` from `from`, skipping string literals, template literals, and
 * comments, and returns the [start, end] offsets of the first brace-balanced block
 * that begins the function body.
 *
 * Two constructs put braces before the body and must not be mistaken for it:
 * destructured parameters (`function f({ id }) {`), which sit at parenthesis depth
 * > 0, and generic return-type annotations (`: Promise<{ ok: boolean }>`), which
 * sit at angle-bracket depth > 0. Both are tracked. Returns null when no body is
 * found before the end of input.
 */
function findBody(content: string, from: number): { start: number; end: number } | null {
  let paren = 0;
  let angle = 0;
  let i = from;

  const skipQuoted = (quote: string): void => {
    i++; // opening quote
    while (i < content.length) {
      const ch = content[i];
      if (ch === "\\") { i += 2; continue; }
      if (ch === quote) { i++; return; }
      i++;
    }
  };

  const skipComment = (): boolean => {
    if (content[i] === "/" && content[i + 1] === "/") {
      while (i < content.length && content[i] !== "\n") i++;
      return true;
    }
    if (content[i] === "/" && content[i + 1] === "*") {
      i += 2;
      while (i < content.length && !(content[i] === "*" && content[i + 1] === "/")) i++;
      i += 2;
      return true;
    }
    return false;
  };

  while (i < content.length) {
    if (skipComment()) continue;
    const ch = content[i];
    if (ch === '"' || ch === "'" || ch === "`") { skipQuoted(ch); continue; }
    if (ch === "(") { paren++; i++; continue; }
    if (ch === ")") { paren = Math.max(0, paren - 1); i++; continue; }
    if (ch === "<") { angle++; i++; continue; }
    if (ch === ">") { angle = Math.max(0, angle - 1); i++; continue; }
    if (ch === ";") return null; // declaration ended without a body (e.g. an overload)
    if (ch === "{" && paren === 0 && angle === 0) break;
    i++;
  }
  if (i >= content.length) return null;

  const start = i;
  let depth = 0;
  while (i < content.length) {
    if (skipComment()) continue;
    const ch = content[i];
    if (ch === '"' || ch === "'" || ch === "`") { skipQuoted(ch); continue; }
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return { start, end: i + 1 };
    }
    i++;
  }
  return { start, end: content.length }; // unbalanced source — take the rest
}

/** Comment lines (`//` or `/* *\/`) immediately above `index`, nearest first. */
function commentsAbove(content: string, index: number): string {
  const before = content.slice(0, index).split("\n");
  const collected: string[] = [];
  for (let i = before.length - 1; i >= 0; i--) {
    const line = before[i].trim();
    if (line === "") continue;
    if (line.startsWith("//") || line.startsWith("*") || line.startsWith("/*") || line.endsWith("*/")) {
      collected.unshift(line);
      continue;
    }
    break;
  }
  return collected.join("\n");
}

/**
 * Every exported function in a source file, with its own body isolated.
 *
 * Returns an empty array for a file with no exported functions (a route file that
 * exports a plain object, a script with top-level work). Callers fall back to
 * whole-file matching in that case, so isolation never removes coverage.
 */
export function exportedHandlers(content: string): ExportedHandler[] {
  const handlers: ExportedHandler[] = [];
  EXPORT_DECL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = EXPORT_DECL_RE.exec(content)) !== null) {
    const body = findBody(content, m.index + m[0].length);
    if (!body) continue;
    handlers.push({
      name: m[1] ?? m[2] ?? (/default/.test(m[0]) ? "default" : "(anonymous)"),
      region: content.slice(m.index, body.end),
      body: content.slice(body.start, body.end),
      precedingComments: commentsAbove(content, m.index)
    });
    EXPORT_DECL_RE.lastIndex = body.end;
  }
  return handlers;
}

/**
 * A server-side identity check in CALL position.
 *
 * Every alternative ends in an opening parenthesis, so an import, a type name, or
 * an unused helper declaration does not satisfy it. The last alternative accepts
 * project-specific guards by naming convention (`requireUser()`, `assertSession()`,
 * `checkPermission()`), since a rule that only recognises named vendors would flag
 * every codebase that wrote its own middleware. That alternative requires an
 * imperative verb prefix, so an ordinary lookup like `getUserById()` is not read as
 * an authorization check.
 */
export const AUTH_CALL_RE =
  /\b(?:getServerSession|currentUser|clerkClient|verifyToken|getToken|requireAuth|getAuth|auth|authenticate|withApiAuth|getUser|getSession|useSession)\s*\(|\bjwt\s*\.\s*verify\s*\(|\bsupabase[\s\S]{0,80}auth\s*\.\s*getUser\s*\(|\b(?:require|assert|ensure|check|verify|validate)[A-Za-z0-9_$]*(?:Auth|Authz|Authorized|Session|Identity|Permission|Role|User|Admin|Login)[A-Za-z0-9_$]*\s*\(/;

/**
 * Provider-signature verification — the correct authorization for a webhook
 * receiver, which has no user session to check.
 *
 * This replaces the old "the file contains the word webhook" exemption. Naming a
 * handler after a webhook is a claim; verifying the signature is the control.
 */
export const WEBHOOK_SIGNATURE_RE =
  /constructEvent\s*\(|verifyWebhook|verify_signature|webhookSignature|X-Hub-Signature|x-hub-signature|Stripe-Signature|stripe-signature|createHmac\s*\(|timingSafeEqual\s*\(|\bsvix\b|Webhook\s*\(\s*(?:process\.env|secret)/i;

/**
 * An explicit, deliberate "this endpoint is public" annotation.
 *
 * Only a marker a developer had to write on purpose counts. The bare word
 * `webhook` used to count, so any comment or identifier containing it disabled the
 * rule for the whole file.
 */
export const PUBLIC_MARK_RE =
  /\/\/\s*PUBLIC(?:\s+(?:ACTION|ROUTE|ENDPOINT|API))?\b|@public\b|allowUnauthenticated|isPublic\s*[:=]\s*true|public\s*:\s*true/i;

/**
 * Does this handler verify its caller, or declare that it does not need to?
 *
 * `region` (declaration through end of body) is used for the auth call so a
 * wrapper such as `export const POST = withApiAuth(async (req) => { ... })`
 * still counts. The public mark is additionally accepted from the comment lines
 * directly above the export, where developers naturally write it.
 */
export function handlerIsAuthorized(handler: ExportedHandler): boolean {
  return (
    AUTH_CALL_RE.test(handler.region) ||
    WEBHOOK_SIGNATURE_RE.test(handler.region) ||
    PUBLIC_MARK_RE.test(handler.region) ||
    PUBLIC_MARK_RE.test(handler.precedingComments)
  );
}

/**
 * Whole-file fallback for files with no exported function to scope to. Uses the
 * same call-position regexes, so the loose identifier and bare-`webhook` matches
 * are gone here too.
 */
export function fileIsAuthorized(content: string): boolean {
  return AUTH_CALL_RE.test(content) || WEBHOOK_SIGNATURE_RE.test(content) || PUBLIC_MARK_RE.test(content);
}
