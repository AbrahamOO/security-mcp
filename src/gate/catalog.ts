import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "../..");

const ControlSchema = z.object({
  id: z.string(),
  description: z.string(),
  automation: z.enum(["workflow", "evidence", "tooling", "approval"]),
  surfaces: z.array(z.string()).default(["all"]),
  frameworks: z.array(z.string()).default([]),
  evidence: z.array(z.string()).optional(),
  required_scanners: z.array(z.string()).optional(),
  required_steps: z.array(z.string()).optional()
});

const CatalogSchema = z.object({
  version: z.string(),
  controls: z.array(ControlSchema)
});

export type ControlCatalog = z.infer<typeof CatalogSchema>;
export type CatalogControl = z.infer<typeof ControlSchema>;

export type SurfaceScope = {
  web: boolean;
  api: boolean;
  infra: boolean;
  mobileIos: boolean;
  mobileAndroid: boolean;
  ai: boolean;
};

async function readJsonWithFallback(relPath: string, fallbackName: string): Promise<string> {
  const overrideEnvMap: Record<string, string> = {
    ".mcp/catalog/control-catalog.json": "SECURITY_GATE_CONTROL_CATALOG"
  };
  const overrideEnv = overrideEnvMap[relPath];
  if (overrideEnv && process.env[overrideEnv]) {
    return await readFile(join(process.cwd(), process.env[overrideEnv] as string), "utf-8");
  }

  try {
    return await readFile(join(process.cwd(), relPath), "utf-8");
  } catch {
    return await readFile(join(PKG_ROOT, "defaults", fallbackName), "utf-8");
  }
}

export async function loadControlCatalog(): Promise<ControlCatalog> {
  const raw = await readJsonWithFallback(".mcp/catalog/control-catalog.json", "control-catalog.json");
  return CatalogSchema.parse(JSON.parse(raw));
}

export function controlApplies(control: CatalogControl, surfaces: SurfaceScope): boolean {
  const mobile = surfaces.mobileIos || surfaces.mobileAndroid;
  if (control.surfaces.includes("all")) return true;
  if (control.surfaces.includes("web") && surfaces.web) return true;
  if (control.surfaces.includes("api") && surfaces.api) return true;
  if (control.surfaces.includes("infra") && surfaces.infra) return true;
  if (control.surfaces.includes("ai") && surfaces.ai) return true;
  if (control.surfaces.includes("mobile") && mobile) return true;
  return false;
}
