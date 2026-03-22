/**
 * Threat Intelligence Feed Integration
 * Fetches CISA KEV and EPSS scores for CVE prioritization.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_API_BASE = "https://api.first.org/data/v1/epss";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export type ThreatIntelResult = {
  kevMatches: string[];
  highEpss: Array<{ cve: string; score: number }>;
  failed: boolean;
};

async function ensureDir(dir: string): Promise<void> {
  try {
    await mkdir(dir, { recursive: true });
  } catch {
    // ignore
  }
}

async function readCacheJson<T>(cachePath: string): Promise<T | null> {
  try {
    const raw = await readFile(cachePath, "utf-8");
    const parsed = JSON.parse(raw) as { ts: number; data: T };
    if (Date.now() - parsed.ts < CACHE_TTL_MS) {
      return parsed.data;
    }
  } catch {
    // cache miss or corrupt
  }
  return null;
}

async function writeCacheJson(cachePath: string, data: unknown): Promise<void> {
  try {
    await writeFile(cachePath, JSON.stringify({ ts: Date.now(), data }, null, 2), "utf-8");
  } catch {
    // best-effort cache write
  }
}

async function fetchWithTimeout(url: string, timeoutMs = 10_000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetches the CISA Known Exploited Vulnerabilities catalog.
 * Returns a Set of CVE IDs. Returns empty set on failure.
 */
export async function fetchCisaKev(cacheDir: string): Promise<Set<string>> {
  await ensureDir(cacheDir);
  const cachePath = join(cacheDir, "cisa-kev.json");

  const cached = await readCacheJson<string[]>(cachePath);
  if (cached) return new Set(cached);

  try {
    const res = await fetchWithTimeout(CISA_KEV_URL, 10_000);
    if (!res.ok) {
      console.warn(`[threat-intel] CISA KEV fetch failed: HTTP ${res.status}`);
      return new Set();
    }
    const json = (await res.json()) as any;
    const vulns: string[] = Array.isArray(json?.vulnerabilities)
      ? (json.vulnerabilities as Array<{ cveID?: string }>)
          .map((v) => v.cveID ?? "")
          .filter(Boolean)
      : [];
    await writeCacheJson(cachePath, vulns);
    return new Set(vulns);
  } catch (err) {
    console.warn(`[threat-intel] CISA KEV fetch error: ${String(err)}`);
    return new Set();
  }
}

/**
 * Fetches EPSS scores for a list of CVE IDs.
 * Batches up to 100 CVEs per request. Returns a Map of CVE → score.
 */
export async function fetchEpssScores(
  cveIds: string[],
  cacheDir: string
): Promise<Map<string, number>> {
  if (cveIds.length === 0) return new Map();
  await ensureDir(join(cacheDir, "epss"));

  const result = new Map<string, number>();
  const today = new Date().toISOString().slice(0, 10);
  const cachePath = join(cacheDir, "epss", `${today}.json`);

  const cached = await readCacheJson<Record<string, number>>(cachePath);
  const cachedMap: Map<string, number> = cached ? new Map(Object.entries(cached)) : new Map();

  const needed = cveIds.filter((id) => !cachedMap.has(id));
  for (const [k, v] of cachedMap) result.set(k, v);

  if (needed.length === 0) return result;

  // Batch in chunks of 100
  for (let i = 0; i < needed.length; i += 100) {
    const chunk = needed.slice(i, i + 100);
    const url = `${EPSS_API_BASE}?cve=${chunk.join(",")}`;
    let retried = false;
    while (true) {
      try {
        const res = await fetchWithTimeout(url, 10_000);
        if (res.status === 429 && !retried) {
          retried = true;
          await new Promise((r) => setTimeout(r, 2000));
          continue;
        }
        if (!res.ok) break;
        const json = (await res.json()) as any;
        if (Array.isArray(json?.data)) {
          for (const item of json.data as Array<{ cve?: string; epss?: string }>) {
            if (item.cve && item.epss !== undefined) {
              result.set(item.cve, parseFloat(item.epss));
            }
          }
        }
        break;
      } catch {
        break;
      }
    }
  }

  // Persist updated cache
  const mergedCache: Record<string, number> = {};
  for (const [k, v] of result) mergedCache[k] = v;
  await writeCacheJson(cachePath, mergedCache);

  return result;
}

/**
 * Main entry point: check CVEs against KEV and EPSS.
 */
export async function checkActiveExploitation(
  cveIds: string[],
  cacheDir: string
): Promise<ThreatIntelResult> {
  if (cveIds.length === 0) {
    return { kevMatches: [], highEpss: [], failed: false };
  }

  try {
    const [kevSet, epssMap] = await Promise.all([
      fetchCisaKev(cacheDir),
      fetchEpssScores(cveIds, cacheDir)
    ]);

    const kevMatches = cveIds.filter((id) => kevSet.has(id));
    const highEpss = cveIds
      .map((cve) => ({ cve, score: epssMap.get(cve) ?? 0 }))
      .filter((e) => e.score > 0.5);

    return { kevMatches, highEpss, failed: false };
  } catch (err) {
    console.warn(`[threat-intel] checkActiveExploitation failed: ${String(err)}`);
    return { kevMatches: [], highEpss: [], failed: true };
  }
}
