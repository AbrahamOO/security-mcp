// Lightweight, dependency-free HCL (Terraform) block utilities.
//
// These are intentionally heuristic — brace-balanced scanning, not a full HCL
// parser. They are robust enough to locate `resource "type" "name" { ... }`
// blocks and apply scoped attribute edits inside a single block, which is all
// the detect-and-remediate engine needs. Edge cases (heredocs, unusual
// formatting) may be missed; such rules degrade to "manual" remediation.

export type HclBlock = {
  type: string;
  name: string;
  start: number; // index of the leading "resource" keyword
  end: number; // index just past the matching closing "}"
  bodyStart: number; // index just past the opening "{"
  bodyEnd: number; // index of the closing "}"
};

const RESOURCE_HEADER = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;

/**
 * Find the index of the "}" matching the "{" at openIdx. Skips braces that
 * appear inside double-quoted strings and line comments (# and //).
 * Returns -1 if unbalanced.
 */
export function matchBrace(text: string, openIdx: number): number {
  let depth = 0;
  let inString = false;
  let inLineComment = false;
  for (let i = openIdx; i < text.length; i++) {
    const ch = text[i];
    if (inLineComment) {
      if (ch === "\n") inLineComment = false;
      continue;
    }
    if (inString) {
      if (ch === "\\") {
        i++; // skip escaped char
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "#") {
      inLineComment = true;
    } else if (ch === "/" && text[i + 1] === "/") {
      inLineComment = true;
      i++;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Parse all top-level `resource "type" "name"` blocks in a Terraform document. */
export function parseResourceBlocks(text: string): HclBlock[] {
  const blocks: HclBlock[] = [];
  RESOURCE_HEADER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RESOURCE_HEADER.exec(text)) !== null) {
    const openBrace = text.indexOf("{", m.index);
    if (openBrace < 0) continue;
    const close = matchBrace(text, openBrace);
    if (close < 0) continue;
    blocks.push({
      type: m[1],
      name: m[2],
      start: m.index,
      end: close + 1,
      bodyStart: openBrace + 1,
      bodyEnd: close
    });
    RESOURCE_HEADER.lastIndex = close + 1;
  }
  return blocks;
}

/**
 * Ensure `attr = value` exists inside an HCL body string for a single-segment
 * attribute. Replaces an existing assignment (even if the value differs) or
 * inserts a new one at the top of the body. Returns the new body string.
 */
function ensureLeafAttr(body: string, attr: string, value: string, indent: string): string {
  const escaped = attr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const assignRe = new RegExp(`^([ \\t]*)${escaped}(\\s*)=.*$`, "m");
  if (assignRe.test(body)) {
    return body.replace(assignRe, `$1${attr} = ${value}`);
  }
  const leading = body.startsWith("\n") ? "\n" : "";
  const rest = body.startsWith("\n") ? body.slice(1) : body;
  return `${leading}${indent}${attr} = ${value}\n${rest}`;
}

/** Build a fresh nested block chain `a { b { leaf = value } }` for a missing path. */
function buildNestedChain(segs: string[], value: string, indent: string): string {
  const [head, ...rest] = segs;
  if (rest.length === 0) {
    return `${indent}${head} = ${value}\n`;
  }
  const inner = buildNestedChain(rest, value, indent + "  ");
  return `${indent}${head} {\n${inner}${indent}}\n`;
}

/**
 * Ensure a nested-path attribute `a.b.c = value` inside an HCL body, creating
 * any missing intermediate `block { ... }` levels. Handles arbitrary depth.
 */
function ensurePath(body: string, segs: string[], value: string, indent: string): string {
  if (segs.length === 1) {
    return ensureLeafAttr(body, segs[0], value, indent);
  }
  const [parent, ...rest] = segs;
  const escaped = parent.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const headerRe = new RegExp(`(^|\\n)([ \\t]*)${escaped}\\s*\\{`);
  const match = headerRe.exec(body);
  if (match) {
    const openBrace = body.indexOf("{", match.index + match[1].length);
    const close = matchBrace(body, openBrace);
    if (openBrace >= 0 && close >= 0) {
      const innerBody = body.slice(openBrace + 1, close);
      const newInner = ensurePath(innerBody, rest, value, indent + "  ");
      return body.slice(0, openBrace + 1) + newInner + body.slice(close);
    }
  }
  const block = buildNestedChain(segs, value, indent);
  const leading = body.startsWith("\n") ? "\n" : "";
  const restBody = body.startsWith("\n") ? body.slice(1) : body;
  return `${leading}${block}${restBody}`;
}

/**
 * Apply a set of dotted-path attribute assignments to one resource block in
 * fullText, returning the rewritten document. Supports depth 1 (attr) and 2
 * (parent.child). Unknown depths are skipped.
 */
export function applyEnsures(
  fullText: string,
  block: HclBlock,
  ensure: Record<string, string>
): string {
  let body = fullText.slice(block.bodyStart, block.bodyEnd);
  for (const [path, value] of Object.entries(ensure)) {
    body = ensurePath(body, path.split("."), value, "  ");
  }
  return fullText.slice(0, block.bodyStart) + body + fullText.slice(block.bodyEnd);
}
