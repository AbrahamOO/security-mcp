import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

const SOURCE_FILE_RE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|json)$/i;
const SCHEMA_RE = /zod\.object\(|outputSchema|json_schema|JSON schema/i;
const TOOL_RE = /\bfunction_call\b|\btools?\b\s*[:=]/i;
const INJECTION_RE = /system prompt|developer message|ignore previous|prompt injection/i;

export async function checkAi(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await fg(["**/*.*"], {
    dot: true,
    onlyFiles: true,
    ignore: [
      "**/node_modules/**",
      "**/.git/**",
      "**/dist/**",
      "**/fixtures/**",
      "**/.mcp/**",
      "**/.mcp/reviews/**",
      "**/.mcp/reports/**"
    ]
  });

  let schemaDetected = false;
  const toolEvidence: string[] = [];
  const injectionEvidence: string[] = [];

  for (const file of files) {
    if (!SOURCE_FILE_RE.test(file)) continue;

    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }

    if (SCHEMA_RE.test(text)) {
      schemaDetected = true;
    }
    if (TOOL_RE.test(text)) {
      toolEvidence.push(file);
    }
    if (INJECTION_RE.test(text)) {
      injectionEvidence.push(file);
    }
  }

  if (toolEvidence.length > 0 && !schemaDetected) {
    findings.push({
      id: "AI_OUTPUT_BOUNDS_MISSING",
      title: "AI/tooling present but bounded output (schema validation) not detected",
      severity: "HIGH",
      evidence: toolEvidence,
      requiredActions: [
        "Enforce bounded outputs via JSON schema validation for every AI response used by code.",
        "Add prompt-injection defenses: input sanitization, tool allowlists, deny-by-default tool router, and sensitive data redaction."
      ]
    });
  }

  if (injectionEvidence.length > 0) {
    findings.push({
      id: "AI_INJECTION_CUES",
      title: "Potential prompt injection cues detected. Requires explicit mitigations and tests.",
      severity: "MEDIUM",
      evidence: injectionEvidence,
      requiredActions: [
        "Add multi-layer prompt-injection protection: instruction hierarchy enforcement, content isolation, tool gating, and output validation.",
        "Add a red-team test harness with injection payloads and exfil attempts."
      ]
    });
  }

  return findings;
}
