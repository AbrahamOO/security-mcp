import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import * as https from "node:https";

const CACHE_DIR = join(homedir(), ".security-mcp");
const CACHE_PATH = join(CACHE_DIR, "update-check.json");
const SKILL_VERSIONS_PATH = join(CACHE_DIR, "skill-versions.json");
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const PROMPT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REGISTRY_URL = "https://registry.npmjs.org/security-mcp/latest";
const SKILLS_MANIFEST_URL =
  "https://raw.githubusercontent.com/AbrahamOO/security-mcp/main/skills-manifest.json";

interface UpdateCheckCache {
  lastCheckedAt?: string;
  latestVersion?: string;
  lastPromptedVersion?: string;
  lastPromptedAt?: string;
  skillsManifestVersion?: string;
  skillsWithUpdates?: string[];
}

function parseVersion(input: string): { major: number; minor: number; patch: number; prerelease: string | null } | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(input.trim());
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null
  };
}

function compareVersions(a: string, b: string): number {
  const parsedA = parseVersion(a);
  const parsedB = parseVersion(b);
  if (!parsedA || !parsedB) return 0;
  if (parsedA.major !== parsedB.major) return parsedA.major < parsedB.major ? -1 : 1;
  if (parsedA.minor !== parsedB.minor) return parsedA.minor < parsedB.minor ? -1 : 1;
  if (parsedA.patch !== parsedB.patch) return parsedA.patch < parsedB.patch ? -1 : 1;
  if (parsedA.prerelease === parsedB.prerelease) return 0;
  if (parsedA.prerelease === null) return 1;
  if (parsedB.prerelease === null) return -1;
  return parsedA.prerelease < parsedB.prerelease ? -1 : 1;
}

function readCache(): UpdateCheckCache {
  try {
    return JSON.parse(readFileSync(CACHE_PATH, "utf-8")) as UpdateCheckCache;
  } catch {
    return {};
  }
}

function writeCache(cache: UpdateCheckCache): void {
  try {
    mkdirSync(dirname(CACHE_PATH), { recursive: true });
    writeFileSync(CACHE_PATH, JSON.stringify(cache, null, 2) + "\n", "utf-8");
  } catch {
    // Non-fatal: update notifications should never block command execution.
  }
}

function fetchLatestVersion(timeoutMs = 1500): Promise<string | null> {
  return new Promise((resolve) => {
    const req = https.get(
      REGISTRY_URL,
      {
        headers: { "User-Agent": "security-mcp-update-checker" }
      },
      (res) => {
        if ((res.statusCode ?? 500) >= 400) {
          res.resume();
          resolve(null);
          return;
        }
        const MAX_BYTES = 64 * 1024; // 64 KB — npm registry version response
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
          if (Buffer.byteLength(body, "utf8") > MAX_BYTES) { req.destroy(); resolve(null); }
        });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(body) as { version?: string };
            resolve(parsed.version ?? null);
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on("error", () => resolve(null));
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      resolve(null);
    });
  });
}

function shouldPrompt(cache: UpdateCheckCache, latestVersion: string, now: number): boolean {
  if (!cache.lastPromptedVersion || !cache.lastPromptedAt) return true;
  if (cache.lastPromptedVersion !== latestVersion) return true;
  const lastPromptedAt = Date.parse(cache.lastPromptedAt);
  if (Number.isNaN(lastPromptedAt)) return true;
  return now - lastPromptedAt >= PROMPT_INTERVAL_MS;
}

/** Check the skills manifest for skills that have newer versions than what is locally installed. */
async function checkSkillUpdates(): Promise<string[]> {
  try {
    const body = await new Promise<string | null>((resolve) => {
      const req = https.get(
        SKILLS_MANIFEST_URL,
        { headers: { "User-Agent": "security-mcp-update-checker" } },
        (res) => {
          if ((res.statusCode ?? 500) >= 400) { res.resume(); resolve(null); return; }
          const MAX_MANIFEST_BYTES = 256 * 1024; // 256 KB
          let buf = "";
          res.setEncoding("utf8");
          res.on("data", (c) => {
            buf += c;
            if (Buffer.byteLength(buf, "utf8") > MAX_MANIFEST_BYTES) { req.destroy(); resolve(null); }
          });
          res.on("end", () => resolve(buf));
        }
      );
      req.on("error", () => resolve(null));
      req.setTimeout(3000, () => { req.destroy(); resolve(null); });
    });

    if (!body) return [];

    interface SkillEntry { version: string; }
    const manifest = JSON.parse(body) as { skills: Record<string, SkillEntry> };

    let installed: Record<string, { version: string }> = {};
    try {
      installed = JSON.parse(readFileSync(SKILL_VERSIONS_PATH, "utf-8")) as Record<string, { version: string }>;
    } catch { /* not installed yet */ }

    const outdated: string[] = [];
    for (const [name, entry] of Object.entries(manifest.skills)) {
      const local = installed[name]?.version;
      if (local && local !== entry.version) {
        outdated.push(`${name}: ${local} → ${entry.version}`);
      }
    }
    return outdated;
  } catch {
    return [];
  }
}

function printUpdateNotices(cache: UpdateCheckCache, currentVersion: string, now: number): void {
  const hasMcpUpdate = cache.latestVersion && compareVersions(currentVersion, cache.latestVersion) < 0;
  const hasSkillUpdates = (cache.skillsWithUpdates?.length ?? 0) > 0;

  if (!hasMcpUpdate && !hasSkillUpdates) return;
  if (cache.latestVersion && !shouldPrompt(cache, cache.latestVersion, now)) return;

  if (hasMcpUpdate && cache.latestVersion) {
    console.error(
      `\nUpdate available: security-mcp ${currentVersion} → ${cache.latestVersion}\n` +
      "Run the CISO Orchestrator skill and choose option (A) to update automatically, or:\n" +
      `  npm install -g security-mcp@${cache.latestVersion}\n` +
      "  security-mcp install\n"
    );
  }

  if (hasSkillUpdates && cache.skillsWithUpdates) {
    console.error(
      "\nSkill updates available:\n" +
      cache.skillsWithUpdates.map((s) => `  • ${s}`).join("\n") +
      "\nRun the CISO Orchestrator skill to apply skill updates automatically.\n"
    );
  }
}

export async function notifyIfUpdateAvailable(currentVersion: string): Promise<void> {
  const now = Date.now();
  const cache = readCache();

  const lastCheckedAt = cache.lastCheckedAt ? Date.parse(cache.lastCheckedAt) : Number.NaN;
  const shouldRefresh = Number.isNaN(lastCheckedAt) || now - lastCheckedAt >= CHECK_INTERVAL_MS;

  if (shouldRefresh) {
    const latestVersion = await fetchLatestVersion();
    if (latestVersion) cache.latestVersion = latestVersion;
    const skillUpdates = await checkSkillUpdates();
    if (skillUpdates.length > 0) cache.skillsWithUpdates = skillUpdates;
    cache.lastCheckedAt = new Date(now).toISOString();
    writeCache(cache);
  }

  printUpdateNotices(cache, currentVersion, now);

  if (cache.latestVersion) {
    cache.lastPromptedVersion = cache.latestVersion;
    cache.lastPromptedAt = new Date(now).toISOString();
    writeCache(cache);
  }
}
