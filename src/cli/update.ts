import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import * as https from "node:https";

const CACHE_DIR = join(homedir(), ".security-mcp");
const CACHE_PATH = join(CACHE_DIR, "update-check.json");
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const PROMPT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REGISTRY_URL = "https://registry.npmjs.org/security-mcp/latest";

interface UpdateCheckCache {
  lastCheckedAt?: string;
  latestVersion?: string;
  lastPromptedVersion?: string;
  lastPromptedAt?: string;
}

function parseVersion(input: string): { major: number; minor: number; patch: number; prerelease: string | null } | null {
  const match = input.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
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
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
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

export async function notifyIfUpdateAvailable(currentVersion: string): Promise<void> {
  const now = Date.now();
  const cache = readCache();

  const lastCheckedAt = cache.lastCheckedAt ? Date.parse(cache.lastCheckedAt) : Number.NaN;
  const shouldRefresh = Number.isNaN(lastCheckedAt) || now - lastCheckedAt >= CHECK_INTERVAL_MS;

  if (shouldRefresh) {
    const latestVersion = await fetchLatestVersion();
    if (latestVersion) {
      cache.latestVersion = latestVersion;
    }
    cache.lastCheckedAt = new Date(now).toISOString();
    writeCache(cache);
  }

  if (!cache.latestVersion) return;
  if (compareVersions(currentVersion, cache.latestVersion) >= 0) return;
  if (!shouldPrompt(cache, cache.latestVersion, now)) return;

  process.stderr.write(
    `\nUpdate available: security-mcp ${currentVersion} -> ${cache.latestVersion}\n` +
      "Update command: npm install -g security-mcp@latest\n" +
      "Then refresh editor config: security-mcp install-global\n\n"
  );

  cache.lastPromptedVersion = cache.latestVersion;
  cache.lastPromptedAt = new Date(now).toISOString();
  writeCache(cache);
}
