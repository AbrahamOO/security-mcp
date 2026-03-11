import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "private_key_pem", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: "aws_access_key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "google_api_key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { name: "slack_bot_token", regex: /\bxoxb-[0-9A-Za-z-]{20,}\b/ },
  { name: "llm_api_key", regex: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: "secret_key_assignment", regex: /\bSECRET_KEY\s*[:=]\s*["'][^"'\n]{8,}["']/ },
  { name: "private_key_assignment", regex: /\bPRIVATE_KEY\s*[:=]\s*["'][^"'\n]{16,}["']/ }
];

function previewLine(text: string, index: number): string {
  const lineStart = text.lastIndexOf("\n", index);
  const lineEnd = text.indexOf("\n", index);
  return text.slice(lineStart === -1 ? 0 : lineStart + 1, lineEnd === -1 ? undefined : lineEnd).trim();
}

export async function checkSecrets(_: { changedFiles: string[] }): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await fg(["**/*.*"], {
    dot: true,
    onlyFiles: true,
    ignore: [
      "**/node_modules/**",
      "**/.git/**",
      "**/dist/**",
      "**/fixtures/**",
      "**/.mcp/reviews/**",
      "**/.mcp/reports/**"
    ]
  });

  const evidence: string[] = [];
  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }

    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (!match || match.index === undefined) continue;
      evidence.push(`${file}:${pattern.name}:${previewLine(text, match.index)}`);
      if (evidence.length >= 25) break;
    }

    if (evidence.length >= 25) break;
  }

  if (evidence.length > 0) {
    findings.push({
      id: "POSSIBLE_SECRET",
      title: "Potential secret material detected by whole-repo heuristic scan",
      severity: "CRITICAL",
      evidence,
      requiredActions: [
        "Remove secrets from the affected files immediately.",
        "Rotate any exposed credentials.",
        "Store secrets only in a dedicated secret manager and keep them out of logs."
      ]
    });
  }

  return findings;
}
