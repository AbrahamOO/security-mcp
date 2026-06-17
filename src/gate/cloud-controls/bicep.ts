// Bicep resource extraction. Block-structured like HCL, so we reuse the
// brace-balanced matcher to capture each `resource <name> '<type>@<ver>' = { ... }`
// body. Detect-only — no auto-fix is attempted for Bicep.
import { matchBrace } from "./hcl.js";

export type BicepResource = { type: string; name: string; body: string; line: number };

// resource <symbolicName> '<type>@<apiVersion>' = [if (...)] { ... }
const RESOURCE_HEADER = /resource\s+([A-Za-z_][A-Za-z0-9_]*)\s+'([^']+)'\s*=\s*(?:if\s*\([^)]*\)\s*)?\{/g;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/** Parse all Bicep `resource` declarations, stripping the `@apiVersion` suffix from the type. */
export function parseBicepResources(text: string): BicepResource[] {
  const out: BicepResource[] = [];
  RESOURCE_HEADER.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = RESOURCE_HEADER.exec(text)) !== null) {
    const open = text.indexOf("{", m.index);
    if (open < 0) continue;
    const close = matchBrace(text, open);
    if (close < 0) continue;
    out.push({
      type: m[2].split("@")[0],
      name: m[1],
      body: text.slice(open + 1, close),
      line: lineOf(text, m.index)
    });
    RESOURCE_HEADER.lastIndex = close + 1;
  }
  return out;
}
