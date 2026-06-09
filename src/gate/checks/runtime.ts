/**
 * Runtime evidence verification.
 * Checks HTTP security headers and TLS configuration against a live target.
 * Also contains static Dockerfile security analysis.
 */
import * as dns from "node:dns/promises";
import * as net from "node:net";
import * as https from "node:https";
import * as tls from "node:tls";
import { Finding } from "../result.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

// CWE-918: SSRF guard — block private/link-local/metadata IP ranges
const PRIVATE_CIDR_PATTERNS = [
  /^127\./,           // loopback
  /^10\./,            // RFC-1918
  /^172\.(1[6-9]|2\d|3[01])\./,  // RFC-1918
  /^192\.168\./,      // RFC-1918
  /^169\.254\./,      // link-local / cloud metadata (169.254.169.254)
  /^::1$/,            // IPv6 loopback
  /^fc/,              // IPv6 ULA
  /^fd/,              // IPv6 ULA
  /^0\./,             // 0.0.0.0/8
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // RFC-6598 shared address space
];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_CIDR_PATTERNS.some((re) => re.test(ip));
}

// CWE-367: return the resolved IP alongside safe/unsafe so callers can connect
// directly to the IP (eliminating the TOCTOU race between DNS check and actual request).
async function isSafeUrl(rawUrl: string): Promise<{ safe: boolean; resolvedIp?: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { safe: false };
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return { safe: false };
  const host = parsed.hostname;
  // Block bare IP references — "resolved" IP is the hostname itself
  if (net.isIP(host)) {
    return isPrivateIp(host) ? { safe: false } : { safe: true, resolvedIp: host };
  }
  // Block known metadata hostnames
  if (host === "localhost" || host === "metadata.google.internal" ||
      host === "169.254.169.254" || host.endsWith(".internal")) {
    return { safe: false };
  }
  // Resolve DNS once — all returned IPs must be public; return the first for direct connection
  try {
    const resolved = await dns.lookup(host, { all: true });
    for (const { address } of resolved) {
      if (isPrivateIp(address)) return { safe: false };
    }
    const firstIp = resolved[0]?.address;
    return firstIp ? { safe: true, resolvedIp: firstIp } : { safe: false };
  } catch {
    return { safe: false }; // can't resolve → skip
  }
}

const REQUIRED_HEADERS: Array<{
  name: string;
  findingId: string;
  validate?: (value: string) => { ok: boolean; findingId?: string; detail?: string };
}> = [
  {
    name: "content-security-policy",
    findingId: "RUNTIME_HEADER_MISSING",
    validate: (v) => {
      if (/unsafe-inline|unsafe-eval/i.test(v)) {
        return { ok: false, findingId: "RUNTIME_HEADER_UNSAFE", detail: "CSP contains unsafe-inline or unsafe-eval" };
      }
      return { ok: true };
    }
  },
  {
    name: "strict-transport-security",
    findingId: "RUNTIME_HEADER_MISSING",
    validate: (v) => {
      const match = /max-age=(\d+)/i.exec(v);
      const maxAge = match ? parseInt(match[1], 10) : 0;
      if (maxAge < 31536000) {
        return { ok: false, findingId: "RUNTIME_HEADER_UNSAFE", detail: `HSTS max-age ${maxAge} is below minimum 31536000` };
      }
      return { ok: true };
    }
  },
  {
    name: "x-frame-options",
    findingId: "RUNTIME_HEADER_MISSING",
    validate: (v) => {
      if (!/^(deny|sameorigin)$/i.test(v.trim())) {
        return { ok: false, findingId: "RUNTIME_HEADER_UNSAFE", detail: `X-Frame-Options value '${v}' is not DENY or SAMEORIGIN` };
      }
      return { ok: true };
    }
  },
  { name: "x-content-type-options", findingId: "RUNTIME_HEADER_MISSING" },
  { name: "referrer-policy", findingId: "RUNTIME_HEADER_MISSING" },
  { name: "permissions-policy", findingId: "RUNTIME_HEADER_MISSING" }
];

const WEAK_CIPHERS = [
  "RC4", "DES", "3DES", "NULL", "EXPORT", "ADH", "AECDH", "aNULL", "eNULL"
];

async function fetchHeaders(
  url: string,
  timeoutMs: number,
  resolvedIp?: string  // CWE-367: pass pre-validated IP to eliminate DNS TOCTOU race
): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    try {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        // Connect to the already-validated IP directly; use the original hostname for SNI
        hostname: resolvedIp ?? parsedUrl.hostname,
        servername: resolvedIp ? parsedUrl.hostname : undefined,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname || "/",
        method: "HEAD",
        rejectUnauthorized: true, // CWE-295: always validate TLS certificates
        timeout: timeoutMs
      };
      const req = https.request(options, (res) => {
        clearTimeout(timer);
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === "string") headers[k.toLowerCase()] = v;
          else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(", ");
        }
        res.resume();
        resolve(headers);
      });
      req.on("error", () => { clearTimeout(timer); resolve(null); });
      req.on("timeout", () => { req.destroy(); clearTimeout(timer); resolve(null); });
      req.end();
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}

interface TlsCheckResult {
  version: string;
  cipher: string;
  cert: {
    subject: string;
    issuer: string;
    validTo: string;
    selfSigned: boolean;
  } | null;
  error?: string;
}

async function checkTls(hostname: string, port: number, timeoutMs: number): Promise<TlsCheckResult | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    try {
      const socket = tls.connect(
        { host: hostname, port, rejectUnauthorized: false, timeout: timeoutMs },
        () => {
          clearTimeout(timer);
          const proto = socket.getProtocol() ?? "";
          const cipher = socket.getCipher();
          const certDer = socket.getPeerCertificate(true);
          let cert: TlsCheckResult["cert"] = null;
          if (certDer) {
            const issuer = certDer.issuer ? JSON.stringify(certDer.issuer) : "";
            const subject = certDer.subject ? JSON.stringify(certDer.subject) : "";
            cert = {
              subject,
              issuer,
              validTo: certDer.valid_to ?? "",
              selfSigned: issuer !== "" && issuer === subject
            };
          }
          socket.destroy();
          resolve({
            version: proto,
            cipher: cipher?.name ?? "",
            cert
          });
        }
      );
      socket.on("error", (err) => {
        clearTimeout(timer);
        resolve({ version: "", cipher: "", cert: null, error: err.message });
      });
      socket.on("timeout", () => {
        socket.destroy();
        clearTimeout(timer);
        resolve(null);
      });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}

/**
 * Run HTTP header and TLS runtime checks against SECURITY_STAGING_URL or policy-provided targets.
 */
export async function runRuntimeChecks(opts: {
  targets: string[];
  changedFiles: string[];
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Determine target URL
  const stagingUrl = process.env["SECURITY_STAGING_URL"];
  const rawTargets = stagingUrl ? [stagingUrl, ...opts.targets] : opts.targets;
  // CWE-918 / CWE-367: resolve hostnames once, reject private/metadata IPs, and
  // carry the resolved IP forward so fetchHeaders connects to the validated IP
  // directly — eliminating the TOCTOU race between DNS check and actual request.
  const safeChecks = await Promise.all(
    rawTargets.map(async (t) => ({ t, ...(await isSafeUrl(t)) }))
  );
  // Deduplicate by URL, keeping the first resolved IP for each unique URL
  const seen = new Map<string, { t: string; resolvedIp?: string }>();
  for (const c of safeChecks) {
    if (c.safe && !seen.has(c.t)) seen.set(c.t, c);
  }
  const checkedTargets = [...seen.values()];

  if (checkedTargets.length === 0) return findings;

  const timeoutMs = 15_000;

  for (const { t: targetUrl, resolvedIp } of checkedTargets) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      continue;
    }

    // --- HTTP Header checks ---
    const headers = await fetchHeaders(targetUrl, timeoutMs, resolvedIp);

    if (headers !== null) {
      for (const headerDef of REQUIRED_HEADERS) {
        const value = headers[headerDef.name];
        if (!value) {
          findings.push({
            id: "RUNTIME_HEADER_MISSING",
            title: `Security header missing: ${headerDef.name} on ${targetUrl}`,
            severity: "HIGH",
            evidence: [`URL: ${targetUrl}`, `Missing header: ${headerDef.name}`],
            requiredActions: [
              `Add the '${headerDef.name}' response header to your application.`,
              "Verify headers are set for all routes including error pages."
            ]
          });
        } else if (headerDef.validate) {
          const check = headerDef.validate(value);
          if (!check.ok) {
            findings.push({
              id: check.findingId ?? "RUNTIME_HEADER_UNSAFE",
              title: check.detail ?? `Unsafe header value: ${headerDef.name} on ${targetUrl}`,
              severity: "HIGH",
              evidence: [`URL: ${targetUrl}`, `Header: ${headerDef.name}: ${value}`],
              requiredActions: [
                `Fix the '${headerDef.name}' header value.`,
                check.detail ?? "Review security header configuration."
              ]
            });
          }
        }
      }
    }

    // --- TLS checks ---
    if (parsedUrl.protocol === "https:") {
      const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : 443;
      const tlsResult = await checkTls(parsedUrl.hostname, port, timeoutMs);

      if (tlsResult && !tlsResult.error) {
        const proto = tlsResult.version.toUpperCase();

        if (proto === "TLSV1" || proto === "TLSV1.0" || proto === "TLSV1.1" || proto === "SSLV3") {
          findings.push({
            id: "RUNTIME_TLS_WEAK",
            title: `Weak TLS version detected: ${tlsResult.version} on ${parsedUrl.hostname}`,
            severity: "CRITICAL",
            evidence: [`Host: ${parsedUrl.hostname}`, `TLS version: ${tlsResult.version}`],
            requiredActions: [
              "Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum, TLS 1.3 preferred.",
              "Update your server's SSL/TLS configuration."
            ]
          });
        }

        const cipherUpper = tlsResult.cipher.toUpperCase();
        if (WEAK_CIPHERS.some((wc) => cipherUpper.includes(wc))) {
          findings.push({
            id: "RUNTIME_TLS_WEAK",
            title: `Weak cipher suite in use: ${tlsResult.cipher} on ${parsedUrl.hostname}`,
            severity: "CRITICAL",
            evidence: [`Host: ${parsedUrl.hostname}`, `Cipher: ${tlsResult.cipher}`],
            requiredActions: [
              "Remove weak cipher suites from your TLS configuration.",
              "Use only ECDHE/DHE with AES-GCM or ChaCha20 cipher suites."
            ]
          });
        }

        if (tlsResult.cert) {
          const validTo = new Date(tlsResult.cert.validTo);
          const now = new Date();
          const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          if (daysRemaining < 0) {
            findings.push({
              id: "RUNTIME_CERT_EXPIRED",
              title: `TLS certificate has expired on ${parsedUrl.hostname}`,
              severity: "CRITICAL",
              evidence: [
                `Host: ${parsedUrl.hostname}`,
                `Expired: ${tlsResult.cert.validTo}`,
                `Days overdue: ${Math.abs(daysRemaining)}`
              ],
              requiredActions: [
                "Renew the TLS certificate immediately.",
                "Set up certificate auto-renewal (e.g., Let's Encrypt with certbot)."
              ]
            });
          } else if (daysRemaining < 30) {
            findings.push({
              id: "RUNTIME_CERT_EXPIRING",
              title: `TLS certificate expiring in ${daysRemaining} days on ${parsedUrl.hostname}`,
              severity: "HIGH",
              evidence: [
                `Host: ${parsedUrl.hostname}`,
                `Expires: ${tlsResult.cert.validTo}`,
                `Days remaining: ${daysRemaining}`
              ],
              requiredActions: [
                "Renew the TLS certificate before it expires.",
                "Verify auto-renewal is configured and working."
              ]
            });
          }

          if (tlsResult.cert.selfSigned) {
            findings.push({
              id: "RUNTIME_TLS_WEAK",
              title: `Self-signed certificate detected on ${parsedUrl.hostname}`,
              severity: "CRITICAL",
              evidence: [`Host: ${parsedUrl.hostname}`, `Issuer: ${tlsResult.cert.issuer}`],
              requiredActions: [
                "Replace the self-signed certificate with one from a trusted CA.",
                "Use Let's Encrypt or your organization's PKI."
              ]
            });
          }
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Static Dockerfile analysis
// ---------------------------------------------------------------------------

const DOCKERFILE_GLOBS = ["**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"];
const COMPOSE_GLOBS = ["**/docker-compose*.yml", "**/docker-compose*.yaml"];
const IGNORE = ["**/node_modules/**", "**/dist/**", "**/.git/**"];

async function loadDockerfiles(): Promise<Array<{ file: string; content: string }>> {
  const paths = await fg(DOCKERFILE_GLOBS, { ignore: IGNORE });
  const results: Array<{ file: string; content: string }> = [];
  for (const file of paths) {
    try {
      const content = await readFileSafe(file);
      results.push({ file, content });
    } catch {
      // skip unreadable files
    }
  }
  return results;
}

async function loadComposeFiles(): Promise<Array<{ file: string; content: string }>> {
  const paths = await fg(COMPOSE_GLOBS, { ignore: IGNORE });
  const results: Array<{ file: string; content: string }> = [];
  for (const file of paths) {
    try {
      const content = await readFileSafe(file);
      results.push({ file, content });
    } catch {
      // skip unreadable files
    }
  }
  return results;
}

async function checkDockerfileNoUser(): Promise<Finding[]> {
  const dockerfiles = await loadDockerfiles();
  const offending = dockerfiles
    .filter(({ content }) => {
      if (!/^FROM\s/m.test(content)) return false;
      // For multi-stage builds the USER directive must appear in the final stage
      // (after the last FROM). A USER only in an earlier build stage still leaves
      // the runtime stage running as root.
      const lines = content.split("\n");
      let lastFromIdx = -1;
      lines.forEach((line, idx) => { if (/^FROM\s/i.test(line)) lastFromIdx = idx; });
      return !lines.slice(lastFromIdx).some((l) => /^USER\s/i.test(l));
    })
    .map(({ file }) => file)
    .slice(0, 10);
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_NO_USER_DIRECTIVE",
    title: "Dockerfile has no USER directive — container runs all processes as root (CWE-250)",
    severity: "HIGH",
    files: offending,
    requiredActions: [
      "Add a USER directive to each Dockerfile to run the process as a non-root user.",
      "Create a dedicated low-privilege user (e.g. RUN adduser --disabled-password appuser) and switch to it before CMD/ENTRYPOINT."
    ]
  }];
}

async function checkDockerfileAddUrl(): Promise<Finding[]> {
  const dockerfiles = await loadDockerfiles();
  const offending = dockerfiles
    .filter(({ content }) => /^ADD\s+https?:\/\//m.test(content))
    .map(({ file }) => file)
    .slice(0, 10);
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_ADD_REMOTE_URL",
    title: "Dockerfile ADD with remote URL — no integrity check, CDN compromise or DNS hijack injects malicious content",
    severity: "HIGH",
    files: offending,
    requiredActions: [
      "Replace ADD <url> with RUN curl --fail -sSL <url> | sha256sum -c <expected> to verify integrity.",
      "Prefer COPY over ADD for local files; use a multi-stage build to fetch and verify remote artifacts."
    ]
  }];
}

async function checkDockerfileSecretsInEnv(): Promise<Finding[]> {
  const dockerfiles = await loadDockerfiles();
  const offending = dockerfiles
    .filter(({ content }) =>
      // Match assignment form (ENV KEY=val), legacy space form (ENV KEY val), and
      // secret as a non-first variable on one line (ENV PORT=3000 DB_PASSWORD=x).
      // Negative lookbehind ensures keyword is not mid-word (e.g. MONKEY won't match KEY).
      /^ENV\s+.*(?<![A-Z\d])(?:PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE_KEY|API_KEY|KEY)(?:\s*=|\s+\S)/im.test(content)
    )
    .map(({ file }) => file)
    .slice(0, 10);
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_SECRETS_IN_ENV",
    title: "Dockerfile ENV instruction contains secret-named variable — credentials baked into image layer, visible in docker inspect",
    severity: "CRITICAL",
    files: offending,
    requiredActions: [
      "Remove secret values from ENV instructions; inject secrets at runtime via Docker secrets, environment variables passed at container start, or a secrets manager.",
      "Audit existing image layers with 'docker history --no-trunc' to confirm no secret values are stored."
    ]
  }];
}

async function checkDockerPrivilegedFlag(): Promise<Finding[]> {
  const allGlobs = [
    ...DOCKERFILE_GLOBS,
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "**/*.docker-compose.yml"
  ];
  const paths = await fg(allGlobs, { ignore: IGNORE });
  const offending: string[] = [];
  for (const file of paths) {
    try {
      const content = await readFileSafe(file);
      if (/privileged:\s*true|--privileged/.test(content)) {
        offending.push(file);
        if (offending.length >= 10) break;
      }
    } catch {
      // skip unreadable files
    }
  }
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_PRIVILEGED_FLAG",
    title: "Container started with --privileged or privileged:true — all Linux capabilities granted, complete isolation disabled",
    severity: "CRITICAL",
    files: offending,
    requiredActions: [
      "Remove privileged: true and --privileged from all container configurations.",
      "Grant only the specific Linux capabilities required using the cap_add directive (e.g. NET_ADMIN, SYS_PTRACE)."
    ]
  }];
}

async function checkDockerSocketMountCompose(): Promise<Finding[]> {
  const composeFiles = await loadComposeFiles();
  const offending = composeFiles
    .filter(({ content }) => /\/var\/run\/docker\.sock/.test(content))
    .map(({ file }) => file)
    .slice(0, 10);
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_SOCKET_MOUNT",
    title: "Docker socket mounted into container in docker-compose — full Docker daemon control enables host root escape",
    severity: "CRITICAL",
    files: offending,
    requiredActions: [
      "Remove /var/run/docker.sock volume mounts from all docker-compose services.",
      "If Docker-in-Docker is required, use rootless Docker or a dedicated DinD sidecar with a restricted socket proxy (e.g. Tecnativa/docker-socket-proxy)."
    ]
  }];
}

export async function runDockerChecks(_opts: { changedFiles: string[] }): Promise<Finding[]> {
  const settled = await Promise.allSettled([
    checkDockerfileNoUser(),
    checkDockerfileAddUrl(),
    checkDockerfileSecretsInEnv(),
    checkDockerPrivilegedFlag(),
    checkDockerSocketMountCompose()
  ]);
  const findings: Finding[] = [];
  for (const r of settled) {
    if (r.status === "fulfilled") findings.push(...r.value);
  }
  return findings;
}
