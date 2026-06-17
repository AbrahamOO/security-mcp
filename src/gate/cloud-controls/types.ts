import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
// src/gate/cloud-controls -> repo root is three levels up (dist/gate/cloud-controls at runtime).
const PKG_ROOT = resolve(__dirname, "../../..");

export const CloudProviderSchema = z.enum(["aws", "gcp", "azure"]);
export type CloudProvider = z.infer<typeof CloudProviderSchema>;

const DetectSchema = z.object({
  // How the rule body is matched:
  //   "terraform"      — HCL resource blocks (supports auto-fix).
  //   "cloudformation" — CloudFormation/SAM resources in JSON or YAML (detect-only).
  //   "bicep"          — Bicep resource declarations (detect-only).
  // Only "terraform" supports auto-remediation; the others are emit-and-fix-manually.
  target: z.enum(["terraform", "cloudformation", "bicep"]),
  // Resource type for the target: Terraform "aws_instance", CloudFormation
  // "AWS::S3::Bucket", or Bicep "Microsoft.Storage/storageAccounts".
  resourceType: z.string(),
  // Regex; if it matches inside the resource block the resource is INSECURE.
  forbid: z.string().optional(),
  // Regex; if it is ABSENT from the resource block the resource is insecure-by-omission.
  require: z.string().optional(),
  // Cross-resource: the resource is insecure unless a companion resource of this
  // Terraform type exists in the same file and references it by local name.
  requireCompanionType: z.string().optional()
});
export type DetectSpec = z.infer<typeof DetectSchema>;

const RemediateSchema = z.object({
  strategy: z.enum(["set-attr", "insert-block", "companion-resource", "manual"]),
  // Dotted attribute path -> raw HCL value literal. Depth up to 2 (parent.child).
  // e.g. { "metadata_options.http_tokens": "\"required\"" }.
  ensure: z.record(z.string(), z.string()).optional(),
  // Companion resource HCL template. "${name}" is substituted with the offending
  // resource's local name. Used by strategy "companion-resource".
  companion: z.string().optional(),
  // Hardened snippet / guidance emitted when the fix cannot be applied automatically.
  snippet: z.string().optional()
});
export type RemediateSpec = z.infer<typeof RemediateSchema>;

const RuleSchema = z.object({
  ruleId: z.string(),
  // The attack this misconfiguration enables — why it matters, not "it's non-compliant".
  threat: z.string(),
  // Framework labels for context only, e.g. ["AWS FSBP EC2.8", "CIS AWS Foundations Benchmark 5.6"].
  frameworks: z.array(z.string()).default([]),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  title: z.string(),
  detect: DetectSchema,
  remediate: RemediateSchema,
  requiredActions: z.array(z.string()).min(1)
});
export type CloudRuleRecord = z.infer<typeof RuleSchema>;

const RegistrySchema = z.object({
  version: z.string(),
  rules: z.array(RuleSchema)
});

// A rule enriched with the provider it was loaded from.
export type CloudRule = CloudRuleRecord & { cloud: CloudProvider };

const PROVIDER_FILES: Record<CloudProvider, string> = {
  aws: "defaults/cloud-controls/aws.json",
  gcp: "defaults/cloud-controls/gcp.json",
  azure: "defaults/cloud-controls/azure.json"
};

async function loadProvider(cloud: CloudProvider): Promise<CloudRule[]> {
  const path = resolve(PKG_ROOT, PROVIDER_FILES[cloud]);
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch {
    return [];
  }
  const parsed = RegistrySchema.parse(JSON.parse(raw));
  return parsed.rules.map((rule) => ({ ...rule, cloud }));
}

/** Load every cloud-control rule across all providers, tagged with its cloud. */
export async function loadCloudRules(providers?: CloudProvider[]): Promise<CloudRule[]> {
  const list = providers ?? (["aws", "gcp", "azure"] as CloudProvider[]);
  const groups = await Promise.all(list.map(loadProvider));
  const seen = new Set<string>();
  const rules: CloudRule[] = [];
  for (const group of groups) {
    for (const rule of group) {
      if (seen.has(rule.ruleId)) {
        throw new Error(`Duplicate cloud-control ruleId: ${rule.ruleId}`);
      }
      seen.add(rule.ruleId);
      rules.push(rule);
    }
  }
  return rules;
}
