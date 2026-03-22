/**
 * Runtime evidence verification.
 * Checks HTTP security headers and TLS configuration against a live target.
 */
import * as https from "node:https";
import * as tls from "node:tls";
import { Finding } from "../result.js";

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
  timeoutMs: number
): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    try {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname || "/",
        method: "HEAD",
        rejectUnauthorized: false, // we verify cert separately
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
  const targets = stagingUrl ? [stagingUrl, ...opts.targets] : opts.targets;
  const uniqueTargets = [...new Set(targets)].filter((t) => t.startsWith("http"));

  if (uniqueTargets.length === 0) return findings;

  const timeoutMs = 15_000;

  for (const targetUrl of uniqueTargets) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      continue;
    }

    // --- HTTP Header checks ---
    const headers = await fetchHeaders(targetUrl, timeoutMs);

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
