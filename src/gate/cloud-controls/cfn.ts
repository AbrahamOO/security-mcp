// CloudFormation / SAM template resource extraction (JSON and YAML).
//
// Detect-only: we locate each `Resources` entry and capture its text so a rule's
// forbid/require regex can be scoped to one resource. Heuristic — YAML is parsed
// by indentation, not a full YAML engine, so unusual layouts may be missed. No
// auto-fix is attempted for CloudFormation (JSON re-serialize drops comments;
// YAML anchors are unsafe to rewrite), so detection accuracy is sufficient.

export type CfnResource = { type: string; name: string; body: string; line: number };

const CFN_TYPE = /Type\s*:\s*['"]?(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)/;

/** Cheap pre-filter so we don't JSON.parse / scan every json/yaml in the repo. */
export function looksLikeCfn(text: string): boolean {
  return (
    text.includes("AWSTemplateFormatVersion") ||
    text.includes("AWS::Serverless") ||
    /["']?Type["']?\s*:\s*["']?AWS::/.test(text)
  );
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function parseJsonCfn(text: string): CfnResource[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  const root = asRecord(doc);
  const resources = root && asRecord(root["Resources"]);
  if (!resources) return [];

  const out: CfnResource[] = [];
  for (const [name, resVal] of Object.entries(resources)) {
    const res = asRecord(resVal);
    const type = res?.["Type"];
    if (typeof type !== "string" || !type.startsWith("AWS::")) continue;
    const re = new RegExp(`"${escapeRegex(name)}"\\s*:`);
    const m = re.exec(text);
    out.push({ type, name, body: JSON.stringify(res), line: m ? lineOf(text, m.index) : 1 });
  }
  return out;
}

function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

function findResourcesIndent(lines: string[]): { start: number; indent: number } | null {
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)Resources\s*:\s*$/.exec(lines[i]);
    if (m) return { start: i, indent: m[1].length };
  }
  return null;
}

function parseYamlCfn(text: string): CfnResource[] {
  const lines = text.split("\n");
  const res = findResourcesIndent(lines);
  if (!res) return [];

  // First logical-id sits at the indent level directly under "Resources:".
  let childIndent = -1;
  for (let i = res.start + 1; i < lines.length; i++) {
    if (!lines[i].trim() || /^\s*#/.test(lines[i])) continue;
    const ind = indentOf(lines[i]);
    if (ind <= res.indent) return [];
    childIndent = ind;
    break;
  }
  if (childIndent < 0) return [];

  const out: CfnResource[] = [];
  let name = "";
  let start = -1;
  let body: string[] = [];
  const flush = (): void => {
    if (!name) return;
    const text2 = body.join("\n");
    const tm = CFN_TYPE.exec(text2);
    if (tm) out.push({ type: tm[1], name, body: text2, line: start + 1 });
    name = "";
    body = [];
  };

  for (let i = res.start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (!l.trim()) {
      if (name) body.push(l);
      continue;
    }
    const ind = indentOf(l);
    if (ind <= res.indent) {
      flush();
      break;
    }
    if (ind === childIndent) {
      const hm = /^\s*([A-Za-z0-9_]+)\s*:/.exec(l);
      flush();
      name = hm ? hm[1] : "";
      start = i;
      body = [l];
    } else if (name) {
      body.push(l);
    }
  }
  flush();
  return out;
}

/** Parse all CloudFormation resources from a JSON or YAML template. */
export function parseCfnResources(text: string): CfnResource[] {
  return text.trimStart().startsWith("{") ? parseJsonCfn(text) : parseYamlCfn(text);
}
