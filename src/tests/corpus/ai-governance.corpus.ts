import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "AI_BIAS_TESTING_ABSENT",
    check: "ai-governance",
    positive: {
      file: "src/models/loan_approval.py",
      content: `from sklearn.ensemble import RandomForestClassifier\n\nmodel = RandomForestClassifier(n_estimators=100)\n\ndef approve_loan(applicant_features):\n    """Predict whether a loan applicant should be approved."""\n    prediction = model.predict([applicant_features])\n    return prediction[0] == 1\n`
    },
    negative: {
      file: "src/models/loan_approval.py",
      content: `from sklearn.ensemble import RandomForestClassifier\nfrom fairlearn.metrics import demographic_parity_difference\n\nmodel = RandomForestClassifier(n_estimators=100)\n\ndef approve_loan(applicant_features, protected_attribute):\n    """Predict whether a loan applicant should be approved."""\n    prediction = model.predict([applicant_features])\n    return prediction[0] == 1\n\ndef audit_bias(y_true, y_pred, sensitive_features):\n    """Fairness audit: measure demographic parity across protected attributes before promoting the model."""\n    return demographic_parity_difference(y_true, y_pred, sensitive_features=sensitive_features)\n`
    },
    note: "Negative keeps the same sklearn loan-decision model but adds a fairlearn demographic-parity audit over a protected attribute in the same file, the exact remediation the rule's requiredActions ask for — not a renamed variable or deleted call."
  },
  {
    ruleId: "AI_SHADOW_EXFIL_SECRET_TO_LLM",
    check: "ai-governance",
    positive: {
      file: "src/ai/supportBot.ts",
      content: `import OpenAI from "openai";\n\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n\nexport async function draftSupportReply(customerQuery: string) {\n  const stripeKey = process.env.STRIPE_SECRET_KEY;\n  const prompt = "Customer asked: " + customerQuery + " Stripe key for lookup: " + stripeKey;\n\n  const response = await openai.chat.completions.create({\n    model: "gpt-4",\n    messages: [{ role: "user", content: prompt }]\n  });\n\n  return response.choices[0].message.content;\n}\n`
    },
    negative: {
      file: "src/ai/supportBot.ts",
      content: `import { redact } from "../security/dlp.js";\nimport { llmClient } from "./llmClient.js";\n\nexport async function draftSupportReply(customerQuery: string, lookupToken: string) {\n  const sanitizedQuery = redact(customerQuery);\n  const prompt = "Customer asked: " + sanitizedQuery + " Lookup reference: " + lookupToken;\n\n  const response = await llmClient.chat.completions.create({\n    model: "gpt-4",\n    messages: [{ role: "user", content: prompt }]\n  });\n\n  return response.choices[0].message.content;\n}\n`
    },
    note: "Negative removes every process.env/apiKey/secretKey/accessToken/privateKey/clientSecret token from the file entirely (auth moves to an imported llmClient module, the raw stripeKey becomes an opaque lookupToken, and the query is passed through a redact() step) so SECRET_ID_RE never matches at all, regardless of the LLM call shape staying identical."
  },
  {
    ruleId: "AI_DEEPFAKE_VERIFICATION_ABSENT",
    check: "ai-governance",
    positive: {
      file: "src/finance/wireTransfer.ts",
      content: `export async function wireTransfer(request: TransferRequest) {\n  // CFO called and asked to expedite this transfer immediately.\n  await ledger.debit(request.fromAccount, request.amount);\n  await bank.sendMoney(request.toAccount, request.amount);\n  return { status: "completed" };\n}\n`
    },
    negative: {
      file: "src/finance/wireTransfer.ts",
      content: `export async function wireTransfer(request: TransferRequest) {\n  const verified = await verifyViaKnownGoodNumber(request.requestedBy);\n  if (!verified) {\n    throw new Error("Refusing to execute transfer without verification");\n  }\n  await ledger.debit(request.fromAccount, request.amount);\n  await bank.sendMoney(request.toAccount, request.amount);\n  return { status: "completed" };\n}\n\nasync function verifyViaKnownGoodNumber(requester: Requester): Promise<boolean> {\n  // Place an out-of-band callback to the requester's known-good number on file\n  // and require a second factor OTP before authorizing the transfer.\n  const callbackOk = await placeOutOfBandCallback(requester.knownGoodNumberOnFile);\n  const otpOk = await confirmOtp(requester.id);\n  return callbackOk && otpOk;\n}\n`
    },
    note: "Negative keeps the same wireTransfer/sendMoney flow but gates execution on an out-of-band callback to a known-good number plus a second-factor OTP, matching requiredActions verbatim, rather than merely stripping the vulnerable call."
  }
];
