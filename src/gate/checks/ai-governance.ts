import { Finding } from "../result.js";
import { scopedFg as fg } from "../scan-scope.js";
import { readFileSafe } from "../../repo/fs.js";

// ════════════════════════════════════════════════════════════════════════════
// AI governance / shadow-AI gap closers.
//
// Missing-control detection for AI threats that pure code-pattern matching can
// only partially see:
//   • AI_BIAS_TESTING_ABSENT          — ML decision systems without fairness tests
//   • AI_SHADOW_EXFIL_SECRET_TO_LLM   — secrets/PII flowing into an LLM payload
//   • AI_DEEPFAKE_VERIFICATION_ABSENT — high-value flows without out-of-band verify
//
// Maps to EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM06 (Sensitive Info
// Disclosure), CWE-200 / CWE-1395.
// ════════════════════════════════════════════════════════════════════════════

const SOURCE_FILE_RE = /\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|rb|json)$/i;

const GLOB_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/.mcp/**"
];

// ─── AI_BIAS_TESTING_ABSENT ──────────────────────────────────────────────────
// ML inference/decision code paired with a consequential domain, lacking any
// fairness-testing artifact anywhere in the repo.
const ML_PREDICT_RE = /\.(?:predict|predict_proba|classify|decision_function|score)\s*\(|model\.(?:predict|forward|infer)|\b(?:RandomForest|XGB|LogisticRegression|GradientBoosting|Sequential|sklearn|tensorflow|torch)\b/i;
const DECISION_DOMAIN_RE = /\b(?:hir(?:e|ing)|applicant|candidate|resume|loan|credit(?:[_-]?score|worthy)?|lending|underwrit\w+|insurance|eligib\w+|recidiv\w+|parole|admission|tenant\s+screen|risk[_-]?score)\b/i;
const FAIRNESS_ARTIFACT_RE = /\bfairlearn\b|\baif360\b|\baequitas\b|disparate[_-]?impact|equal(?:ized)?[_-]?odds|demographic[_-]?parity|\bfairness\b|bias[_-]?(?:test|audit|metric|check)|protected[_-]?attribute/i;

// ─── AI_SHADOW_EXFIL_SECRET_TO_LLM ───────────────────────────────────────────
const SECRET_ID_RE = /process\.env\.[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)|\b(?:apiKey|secretKey|accessToken|privateKey|clientSecret)\b|\bssn\b|cardNumber|\.env\b/i;
const LLM_PAYLOAD_RE = /(?:messages|prompt|systemPrompt|userMessage|content|input)\s*[:=]|\.(?:chat\.completions\.create|messages\.create|completions\.create|generateContent|invoke)\s*\(|\bopenai\.|\banthropic\.|\bllm\./i;

// ─── AI_DEEPFAKE_VERIFICATION_ABSENT ─────────────────────────────────────────
const HIGH_VALUE_FLOW_RE = /\b(?:wireTransfer|approveTransfer|sendMoney|transferFunds|resetPassword|changePassword|grantAccess|approvePayment|payout|disburse|releaseFunds|changeBankAccount)\b/i;
const OOB_VERIFY_RE = /out[_-]?of[_-]?band|callback\s+verif\w+|step[_-]?up\s+auth|\bMFA\b|\bOTP\b|verify\s+identity|liveness|deepfake|second\s+factor|known[_-]?good\s+number/i;

type Signals = {
  mlDecision: boolean;
  fairnessArtifact: boolean;
  shadowExfilFiles: string[];
  highValueFlow: boolean;
  oobVerify: boolean;
};

// Returns true if `targetRe` matches within `window` lines of any `anchorRe` line.
function windowMatch(lines: string[], anchorRe: RegExp, targetRe: RegExp, window: number): boolean {
  for (let i = 0; i < lines.length; i++) {
    if (!anchorRe.test(lines[i])) continue;
    const start = Math.max(0, i - window);
    const end = Math.min(lines.length - 1, i + window);
    for (let j = start; j <= end; j++) {
      if (targetRe.test(lines[j])) return true;
    }
  }
  return false;
}

function scanFile(file: string, text: string, sig: Signals): void {
  if (FAIRNESS_ARTIFACT_RE.test(text)) sig.fairnessArtifact = true;
  if (ML_PREDICT_RE.test(text) && DECISION_DOMAIN_RE.test(text)) sig.mlDecision = true;
  if (HIGH_VALUE_FLOW_RE.test(text)) sig.highValueFlow = true;
  if (OOB_VERIFY_RE.test(text)) sig.oobVerify = true;

  if (SECRET_ID_RE.test(text) && LLM_PAYLOAD_RE.test(text)) {
    const lines = text.split("\n");
    if (windowMatch(lines, SECRET_ID_RE, LLM_PAYLOAD_RE, 15)) {
      sig.shadowExfilFiles.push(file);
    }
  }
}

function buildFindings(sig: Signals): Finding[] {
  const findings: Finding[] = [];

  if (sig.mlDecision && !sig.fairnessArtifact) {
    findings.push({
      id: "AI_BIAS_TESTING_ABSENT",
      title: "ML decision system detected with no fairness / bias-testing artifact",
      severity: "MEDIUM",
      requiredActions: [
        "Add fairness evaluation (e.g. Fairlearn, AIF360, Aequitas) measuring disparate impact, equalized odds, and demographic parity across protected attributes for any model that affects people (EU AI Act high-risk obligations; NIST AI RMF MEASURE 2.11 / MANAGE).",
        "Document the training-data representativeness assessment and bias-mitigation steps as model-card evidence (ISO 42001).",
        "Gate model promotion on fairness thresholds in CI and re-evaluate on every retrain to catch drift-induced bias."
      ]
    });
  }

  if (sig.shadowExfilFiles.length > 0) {
    findings.push({
      id: "AI_SHADOW_EXFIL_SECRET_TO_LLM",
      title: "Secrets or PII interpolated into an LLM request payload — shadow-AI data leakage",
      severity: "HIGH",
      files: sig.shadowExfilFiles,
      evidence: sig.shadowExfilFiles,
      requiredActions: [
        "Never place secrets, API keys, or raw PII into prompt/messages content — they leave your trust boundary and may be retained or logged by the model provider (OWASP LLM06, CWE-200).",
        "Insert a redaction/tokenization step (e.g. Microsoft Presidio) at the prompt-construction boundary and pass only opaque references to the LLM.",
        "Add a DLP guard and CI check that fails when process.env secrets or PII identifiers reach an LLM SDK call site."
      ]
    });
  }

  if (sig.highValueFlow && !sig.oobVerify) {
    findings.push({
      id: "AI_DEEPFAKE_VERIFICATION_ABSENT",
      title: "High-value action flow without out-of-band identity verification — AI deepfake / vishing exposure",
      severity: "MEDIUM",
      requiredActions: [
        "Require out-of-band verification (callback to a known-good number, step-up MFA/OTP, or liveness check) before executing high-value actions — AI voice/video clones now routinely defeat single-channel approval (MITRE ATLAS AML.T0052 social engineering).",
        "Never treat a phone call, voicemail, or video request as sufficient authorization for fund transfers, account changes, or access grants.",
        "Add transaction anomaly checks and a mandatory second approver for irreversible high-value operations."
      ]
    });
  }

  return findings;
}

export async function checkAiGovernance(_: { changedFiles: string[] }): Promise<Finding[]> {
  const files = await fg(["**/*.*"], {
    dot: true,
    onlyFiles: true,
    ignore: GLOB_IGNORE
  });

  const sig: Signals = {
    mlDecision: false,
    fairnessArtifact: false,
    shadowExfilFiles: [],
    highValueFlow: false,
    oobVerify: false
  };

  for (const file of files) {
    if (!SOURCE_FILE_RE.test(file)) continue;
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    scanFile(file, text, sig);
  }

  return buildFindings(sig);
}
