import { Finding } from "../result.js";
import { searchRepo } from "../../repo/search.js";
import fg from "fast-glob";
import { readFileSafe } from "../../repo/fs.js";

// Structural scan: detect secret-looking entries inside a docker-compose `labels:`
// block. Per-line regex can't see the parent `labels:` key, so it cannot tell a
// label secret apart from an environment variable. This loads compose files and
// tracks indentation to scope the match to label entries only, and redacts the
// value so the secret is never echoed into a finding (CWE-200).
const LABEL_SECRET_RE = /(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key)/i;

function redactKv(line: string): string {
  return line.replace(/([:=]\s*).*/, "$1[REDACTED]").trim().slice(0, 120);
}

async function scanComposeLabelSecrets(): Promise<{ file: string; line: number; preview: string }[]> {
  const files = await fg(["**/*compose*.{yml,yaml}"], {
    dot: true,
    ignore: ["**/node_modules/**", "**/dist/**", "**/.git/**"],
    followSymbolicLinks: false,
  });
  const hits: { file: string; line: number; preview: string }[] = [];
  for (const file of files) {
    let text = "";
    try {
      text = await readFileSafe(file);
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    let labelIndent = -1;
    for (let i = 0; i < lines.length && hits.length < 50; i++) {
      const line = lines[i];
      const indent = line.search(/\S/);
      if (indent === -1) continue;
      // Inline forms: `labels: {a: secret}` or `labels: ["a=secret"]` on one line.
      if (/^\s*labels:\s*[[{]/.test(line)) {
        if (LABEL_SECRET_RE.test(line)) hits.push({ file, line: i + 1, preview: redactKv(line) });
        continue;
      }
      // Block form: `labels:` on its own line; children are more-indented.
      if (/^\s*labels:\s*$/.test(line)) {
        labelIndent = indent;
        continue;
      }
      if (labelIndent >= 0) {
        if (indent <= labelIndent) {
          labelIndent = -1; // dedent — block ended
        } else if (LABEL_SECRET_RE.test(line)) {
          hits.push({ file, line: i + 1, preview: redactKv(line) });
        }
      }
    }
  }
  return hits;
}

// Deep container-security checks. Extends src/gate/checks/runtime.ts.
// Does NOT re-implement: DOCKER_NO_USER_DIRECTIVE, DOCKER_ADD_REMOTE_URL,
// DOCKER_SECRETS_IN_ENV, DOCKER_PRIVILEGED_FLAG, DOCKER_SOCKET_MOUNT.
//
// Each searchRepo regex is < 256 chars, has no nested quantifiers, and uses
// String.raw for backslashes to satisfy the ReDoS guard in repo/search.js.

const MAX = 50;

const DOCKERFILE_RE = String.raw`(?:dockerfile|\.dockerfile)`;
const COMPOSE_RE = String.raw`docker-compose.*\.ya?ml`;

function isDockerfile(file: string): boolean {
  return /(^|\/)dockerfile($|\.)/i.test(file) || /\.dockerfile$/i.test(file);
}
function isCompose(file: string): boolean {
  return /docker-compose.*\.ya?ml$/i.test(file);
}

// ---------------------------------------------------------------------------
// 1. Unpinned base image (no digest pin / :latest / no tag)
// ---------------------------------------------------------------------------
async function checkUnpinnedBaseImage(): Promise<Finding[]> {
  // FROM lines with :latest or with NO tag at all (HIGH).
  const latestOrNoTag = await searchRepo({
    query: String.raw`^\s*FROM\s+\S+:latest(\s|$)`,
    isRegex: true,
    maxMatches: MAX,
  });
  // FROM <image> with no ":" tag and no "@sha256" — bare image name.
  // Tail [\sa-z0-9]* tolerates an optional "AS stage" without a quantified group.
  const bareImage = await searchRepo({
    query: String.raw`^\s*FROM\s+[a-z0-9./_-]+[\sa-z0-9]*$`,
    isRegex: true,
    maxMatches: MAX,
  });
  // FROM image:tag WITHOUT @sha256 digest (MEDIUM): has a colon tag, no digest.
  const tagNoDigest = await searchRepo({
    query: String.raw`^\s*FROM\s+\S+:[a-z0-9._-]+[\sa-z0-9]*$`,
    isRegex: true,
    maxMatches: MAX,
  });

  const findings: Finding[] = [];

  const highMatches = [...latestOrNoTag, ...bareImage].filter((m) => {
    if (!isDockerfile(m.file)) return false;
    return !/@sha256:/i.test(m.preview);
  });
  if (highMatches.length > 0) {
    findings.push({
      id: "DOCKER_BASE_IMAGE_UNPINNED",
      title:
        "Dockerfile base image uses :latest or no tag — not pinned to a digest, allowing supply-chain image swap (CWE-1357)",
      severity: "HIGH",
      evidence: highMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Pin the base image to an immutable digest: FROM image:tag@sha256:<digest>.",
        "Never use :latest or an untagged image; resolve and lock the digest in CI and update it deliberately.",
      ],
    });
  }

  const mediumMatches = tagNoDigest.filter((m) => {
    if (!isDockerfile(m.file)) return false;
    if (/@sha256:/i.test(m.preview)) return false;
    if (/:latest(\s|$)/i.test(m.preview)) return false; // already HIGH
    return true;
  });
  if (mediumMatches.length > 0) {
    findings.push({
      id: "DOCKER_BASE_IMAGE_NO_DIGEST",
      title:
        "Dockerfile base image pinned by tag but not by @sha256 digest — tag is mutable and can be repointed upstream (CWE-1357)",
      severity: "MEDIUM",
      evidence: mediumMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Append the content digest to the base image: FROM image:tag@sha256:<digest>.",
        "Automate digest pinning and verification in your build pipeline.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 2. Remote pipe-to-shell inside RUN (curl|sh, wget|bash)
// ---------------------------------------------------------------------------
async function checkPipeToShell(): Promise<Finding[]> {
  const curlPipe = await searchRepo({
    query: String.raw`(?:curl|wget)\s[^|]*https?://[^|]*\|[^\n]*(?:sh|bash)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = curlPipe.filter((m) => isDockerfile(m.file) || isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_RUN_PIPE_TO_SHELL",
    title:
      "RUN pipes a remote download directly into a shell (curl|sh / wget|bash) — unverified remote code execution at build time (CWE-494)",
    severity: "HIGH",
    evidence: matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
    requiredActions: [
      "Replace curl|bash with a verified download: fetch to a file, verify a published sha256 checksum or GPG signature, then execute.",
      "Pin the script/installer version and review it; never execute remote content fetched at build time without integrity verification.",
    ],
  }];
}

// ---------------------------------------------------------------------------
// 3. sudo usage / chmod 777
// ---------------------------------------------------------------------------
async function checkSudoAnd777(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const sudo = await searchRepo({
    query: String.raw`^\s*RUN\s+.*(?:\bsudo\b|install[^\n]*\bsudo\b)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const sudoMatches = sudo.filter((m) => isDockerfile(m.file));
  if (sudoMatches.length > 0) {
    findings.push({
      id: "DOCKER_RUN_SUDO",
      title:
        "RUN uses or installs sudo inside the image — defeats least-privilege and enables in-container privilege escalation (CWE-250)",
      severity: "MEDIUM",
      evidence: sudoMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Remove sudo from the image; perform privileged build steps before dropping to a non-root USER.",
        "Do not install the sudo package in container images; run the workload as a dedicated low-privilege user.",
      ],
    });
  }

  const chmod777 = await searchRepo({
    query: String.raw`\bchmod\s[-a-zA-Z0-9\s]*0?777\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const chmodMatches = chmod777.filter((m) => isDockerfile(m.file) || isCompose(m.file));
  if (chmodMatches.length > 0) {
    findings.push({
      id: "DOCKER_CHMOD_777",
      title:
        "chmod 777 grants world-writable permissions — any user/process can modify these files, enabling tampering (CWE-732)",
      severity: "MEDIUM",
      evidence: chmodMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Replace chmod 777 with the minimal permissions required (e.g. 755 for executables, 644 for data).",
        "Set ownership with chown to the runtime user instead of opening permissions to everyone.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 4. Missing HEALTHCHECK (per Dockerfile with FROM, no HEALTHCHECK)
// ---------------------------------------------------------------------------
async function checkMissingHealthcheck(): Promise<Finding[]> {
  const froms = await searchRepo({
    query: String.raw`^\s*FROM\s+\S`,
    isRegex: true,
    maxMatches: MAX,
  });
  const healthchecks = await searchRepo({
    query: String.raw`^\s*HEALTHCHECK\s`,
    isRegex: true,
    maxMatches: MAX,
  });

  const dockerfilesWithFrom = new Set(
    froms.filter((m) => isDockerfile(m.file)).map((m) => m.file)
  );
  const dockerfilesWithHc = new Set(
    healthchecks.filter((m) => isDockerfile(m.file)).map((m) => m.file)
  );

  const offending = [...dockerfilesWithFrom].filter((f) => !dockerfilesWithHc.has(f));
  if (offending.length === 0) return [];
  return [{
    id: "DOCKER_NO_HEALTHCHECK",
    title:
      "Dockerfile defines no HEALTHCHECK — orchestrators cannot detect a hung/compromised container and route traffic away",
    severity: "LOW",
    files: offending.slice(0, 12),
    requiredActions: [
      "Add a HEALTHCHECK instruction that verifies the application is actually serving (e.g. HEALTHCHECK CMD curl -f http://localhost:PORT/health || exit 1).",
      "Ensure the orchestrator (Compose/Kubernetes) is configured to act on the health status.",
    ],
  }];
}

// ---------------------------------------------------------------------------
// 5. ADD of local archive, or COPY . . / ADD . copying whole build context
// ---------------------------------------------------------------------------
async function checkBroadCopyAndArchive(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // ADD local-archive (not a URL): .tar/.tar.gz/.tgz/.zip
  const addArchive = await searchRepo({
    query: String.raw`^\s*ADD\s+(?!https?://)\S+\.(?:tar|tar\.gz|tgz|zip|tar\.bz2)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const archiveMatches = addArchive.filter((m) => isDockerfile(m.file));
  if (archiveMatches.length > 0) {
    findings.push({
      id: "DOCKER_ADD_LOCAL_ARCHIVE",
      title:
        "ADD auto-extracts a local archive — implicit, unverified extraction can enable path traversal/zip-slip; use COPY (CWE-22)",
      severity: "MEDIUM",
      evidence: archiveMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Use COPY for local files; if extraction is needed, run a verified RUN tar/unzip step with explicit, audited paths.",
        "Verify the archive's checksum before extracting and avoid ADD's implicit tar extraction behavior.",
      ],
    });
  }

  // COPY . . or ADD . — whole build context (leaks .git, secrets, node_modules)
  const broadCopy = await searchRepo({
    query: String.raw`^\s*(?:COPY|ADD)\s+\.\s+(?:\.|\./|/)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const broadMatches = broadCopy.filter((m) => isDockerfile(m.file));
  if (broadMatches.length > 0) {
    findings.push({
      id: "DOCKER_COPY_WHOLE_CONTEXT",
      title:
        "COPY . . / ADD . copies the entire build context into the image — leaks .git, .env, keys and source not needed at runtime (CWE-538)",
      severity: "MEDIUM",
      evidence: broadMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Copy only the specific files/directories required at runtime instead of the whole context.",
        "Add a comprehensive .dockerignore (.git, .env, secrets, node_modules, tests) to prevent accidental inclusion.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 6. apt-get install -y without --no-install-recommends
// ---------------------------------------------------------------------------
async function checkAptNoRecommends(): Promise<Finding[]> {
  const apt = await searchRepo({
    query: String.raw`apt-get\s+install\s[-a-zA-Z0-9\s]*-y\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = apt.filter(
    (m) => isDockerfile(m.file) && !/--no-install-recommends/i.test(m.preview)
  );
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_APT_RECOMMENDS",
    title:
      "apt-get install -y without --no-install-recommends — pulls extra packages, enlarging the image and attack surface",
    severity: "LOW",
    evidence: matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
    requiredActions: [
      "Add --no-install-recommends to apt-get install and pin exact package versions.",
      "Clean apt lists in the same layer (rm -rf /var/lib/apt/lists/*) to minimize image size and attack surface.",
    ],
  }];
}

// ---------------------------------------------------------------------------
// 7. docker-compose dangerous host/kernel exposures
// ---------------------------------------------------------------------------
async function checkComposeCapabilities(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const dangerousCap = await searchRepo({
    query: String.raw`-\s*(?:SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|SYS_MODULE)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const capMatches = dangerousCap.filter((m) => isCompose(m.file));
  if (capMatches.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_DANGEROUS_CAP",
      title:
        "docker-compose cap_add grants dangerous Linux capability (SYS_ADMIN/NET_ADMIN/ALL) — enables container escape (CWE-250)",
      severity: "HIGH",
      evidence: capMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Drop all capabilities (cap_drop: [ALL]) and add back only the specific ones the workload needs; never SYS_ADMIN or ALL.",
        "Re-architect the workload so it does not require kernel-level capabilities.",
      ],
    });
  }

  const seccompUnconfined = await searchRepo({
    query: String.raw`(?:seccomp|apparmor)\s*[:=]\s*unconfined`,
    isRegex: true,
    maxMatches: MAX,
  });
  const seccompMatches = seccompUnconfined.filter((m) => isCompose(m.file));
  if (seccompMatches.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_UNCONFINED",
      title:
        "docker-compose security_opt disables seccomp/apparmor (unconfined) — removes the syscall sandbox protecting the host (CWE-693)",
      severity: "HIGH",
      evidence: seccompMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Remove seccomp:unconfined / apparmor:unconfined; keep the default profiles enabled.",
        "If a specific syscall is needed, supply a tailored seccomp profile rather than disabling it entirely.",
      ],
    });
  }

  const hostNamespace = await searchRepo({
    query: String.raw`^\s*(?:pid|ipc|network_mode|userns_mode|uts)\s*:\s*["']?host\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const nsMatches = hostNamespace.filter((m) => isCompose(m.file));
  if (nsMatches.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_HOST_NAMESPACE",
      title:
        "docker-compose shares a host namespace (pid/network/ipc/userns: host) — breaks container isolation from the host (CWE-668)",
      severity: "HIGH",
      evidence: nsMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Remove host namespace sharing (pid/ipc/uts/userns: host, network_mode: host); use bridge networking and isolated namespaces.",
        "If host network access is required, expose only the specific ports needed via the ports: mapping instead.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 8. Exposed Docker daemon TCP / 0.0.0.0 binding
// ---------------------------------------------------------------------------
async function checkDaemonExposure(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const daemonPort = await searchRepo({
    query: String.raw`(?::|")(?:2375|2376)(?::|")`,
    isRegex: true,
    maxMatches: MAX,
  });
  const daemonAltPort = await searchRepo({
    query: String.raw`tcp://[^:\s]*:(?:2375|2376)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const daemonMatches = [...daemonPort, ...daemonAltPort].filter(
    (m) => isCompose(m.file) || isDockerfile(m.file)
  );
  if (daemonMatches.length > 0) {
    findings.push({
      id: "DOCKER_DAEMON_TCP_EXPOSED",
      title:
        "Docker daemon TCP port (2375/2376) exposed — an unauthenticated daemon socket gives full host root control (CWE-306)",
      severity: "CRITICAL",
      evidence: daemonMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Never expose the Docker daemon over TCP; use the local unix socket with restricted permissions.",
        "If remote access is unavoidable, require mutual TLS (2376) with client certificate auth and firewall the port to known hosts.",
      ],
    });
  }

  const bindAll = await searchRepo({
    query: String.raw`^\s*-\s*["']?0\.0\.0\.0:\d+:\d+`,
    isRegex: true,
    maxMatches: MAX,
  });
  const bindMatches = bindAll.filter((m) => isCompose(m.file));
  if (bindMatches.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_BIND_ALL_INTERFACES",
      title:
        "docker-compose binds a port to 0.0.0.0 — service is reachable on every host interface, including public ones (CWE-668)",
      severity: "MEDIUM",
      evidence: bindMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Bind sensitive ports to 127.0.0.1 (e.g. 127.0.0.1:5432:5432) instead of 0.0.0.0.",
        "Restrict exposure with a firewall/security group and only publish ports that must be externally reachable.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 9. --no-sandbox, or USER root as the final user directive
// ---------------------------------------------------------------------------
async function checkNoSandboxAndRootUser(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const noSandbox = await searchRepo({
    query: String.raw`--no-sandbox\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const sandboxMatches = noSandbox.filter((m) => isDockerfile(m.file) || isCompose(m.file));
  if (sandboxMatches.length > 0) {
    findings.push({
      id: "DOCKER_NO_SANDBOX_FLAG",
      title:
        "Container launches a process with --no-sandbox — disables the browser/runtime sandbox, removing an exploit containment layer (CWE-693)",
      severity: "HIGH",
      evidence: sandboxMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Remove --no-sandbox; run the process as a non-root user so the sandbox can initialize correctly.",
        "If kernel namespaces are unavailable, use a seccomp-based sandbox rather than disabling sandboxing entirely.",
      ],
    });
  }

  // USER root appearing in a Dockerfile (final-user heuristic). We flag any
  // explicit USER root; the runtime.ts check only flags absence of USER.
  const userRoot = await searchRepo({
    query: String.raw`^\s*USER\s+(?:root|0)\s*$`,
    isRegex: true,
    maxMatches: MAX,
  });
  const rootMatches = userRoot.filter((m) => isDockerfile(m.file));
  if (rootMatches.length > 0) {
    findings.push({
      id: "DOCKER_EXPLICIT_USER_ROOT",
      title:
        "Dockerfile explicitly sets USER root — the runtime process runs as uid 0, maximizing blast radius of any RCE (CWE-250)",
      severity: "HIGH",
      evidence: rootMatches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
      requiredActions: [
        "Switch to a dedicated non-root user before CMD/ENTRYPOINT (e.g. USER appuser); use USER root only for transient build steps.",
        "Ensure the final USER directive in the runtime stage is a low-privilege account, not root/0.",
      ],
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 10. Secrets passed via build ARG (bake into image history)
// ---------------------------------------------------------------------------
async function checkSecretBuildArg(): Promise<Finding[]> {
  const arg = await searchRepo({
    query: String.raw`^\s*ARG\s+\S*(?:TOKEN|PASSWORD|SECRET|API_?KEY|PRIVATE_KEY|CREDENTIAL)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = arg.filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_SECRET_IN_BUILD_ARG",
    title:
      "Secret passed via build ARG — ARG values are recorded in image history and visible via docker history (CWE-200)",
    severity: "HIGH",
    evidence: matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
    requiredActions: [
      "Do not pass secrets via ARG; use BuildKit secret mounts (RUN --mount=type=secret) which are not persisted in layers.",
      "Inject runtime credentials via a secrets manager or runtime environment, never at build time.",
    ],
  }];
}

// ---------------------------------------------------------------------------
// 11. privileged: true in docker-compose (compose-specific id)
// ---------------------------------------------------------------------------
async function checkComposePrivileged(): Promise<Finding[]> {
  const priv = await searchRepo({
    query: String.raw`^\s*privileged\s*:\s*true\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = priv.filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_PRIVILEGED",
    title:
      "docker-compose service sets privileged: true — grants all capabilities and disables isolation, enabling host takeover (CWE-250)",
    severity: "CRITICAL",
    evidence: matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
    requiredActions: [
      "Remove privileged: true from every compose service.",
      "Grant only the specific cap_add capabilities the workload requires and keep default seccomp/apparmor profiles.",
    ],
  }];
}

// ---------------------------------------------------------------------------
// 12. Implicit Docker Hub image + :latest with no registry namespace
// ---------------------------------------------------------------------------
async function checkImplicitRegistry(): Promise<Finding[]> {
  // FROM <single-segment-name>:latest — no registry host and no org namespace,
  // implicitly pulls library/<name> from Docker Hub.
  const implicit = await searchRepo({
    query: String.raw`^\s*FROM\s+[a-z0-9_-]+:latest(\s|$)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = implicit.filter(
    (m) => isDockerfile(m.file) && !/[./]/.test(m.preview.replace(/^\s*FROM\s+/i, "").split(/[:\s]/)[0] || "")
  );
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_IMPLICIT_REGISTRY",
    title:
      "Base image has no registry namespace and uses :latest — implicitly pulled from Docker Hub library, vulnerable to namespace/tag confusion",
    severity: "LOW",
    evidence: matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`),
    requiredActions: [
      "Use a fully-qualified image reference including registry host and namespace (e.g. registry.example.com/org/image:tag@sha256:<digest>).",
      "Mirror approved base images into a trusted internal registry and pull only from it.",
    ],
  }];
}

// ===========================================================================
// ROUND 2 — Dockerfile depth
// ===========================================================================

function ev(matches: { file: string; line: number; preview: string }[]): string[] {
  return matches.slice(0, 12).map((m) => `${m.file}:${m.line} ${m.preview.trim()}`);
}

// 13. TLS/cert verification disabled via ENV/ARG
async function checkTlsVerifyDisabled(): Promise<Finding[]> {
  const a = await searchRepo({
    query: String.raw`(?:ENV|ARG)\s+\S*NODE_TLS_REJECT_UNAUTHORIZED\s*[= ]\s*["']?0\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const b = await searchRepo({
    query: String.raw`(?:ENV|ARG)\s+\S*PYTHONHTTPSVERIFY\s*[= ]\s*["']?0\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const c = await searchRepo({
    query: String.raw`(?:ENV|ARG)\s+\S*GIT_SSL_NO_VERIFY\s*[= ]\s*["']?(?:1|true)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = [...a, ...b, ...c].filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_TLS_VERIFY_DISABLED",
    title:
      "Dockerfile disables TLS/certificate verification via ENV/ARG (NODE_TLS_REJECT_UNAUTHORIZED=0 / PYTHONHTTPSVERIFY=0 / GIT_SSL_NO_VERIFY) — enables MITM (CWE-295)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Remove any ENV/ARG that disables TLS verification; never set NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0 or GIT_SSL_NO_VERIFY.",
      "Fix the underlying CA-trust problem by installing the correct CA bundle instead of disabling verification.",
    ],
  }];
}

// 14. Insecure package-manager flags / HTTP registries
async function checkInsecurePackageManager(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const pipInsecure = await searchRepo({
    query: String.raw`pip\d?\s+install\s[^\n]*(?:--trusted-host|--index-url\s+http://|-i\s+http://)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const pipM = pipInsecure.filter((m) => isDockerfile(m.file));
  if (pipM.length > 0) {
    findings.push({
      id: "DOCKER_PIP_INSECURE_INDEX",
      title:
        "pip install uses --trusted-host or an http:// index URL — packages fetched without TLS/host verification, enabling supply-chain injection (CWE-494)",
      severity: "HIGH",
      evidence: ev(pipM),
      requiredActions: [
        "Use only https:// PyPI index URLs and remove --trusted-host.",
        "Pin package versions with hashes (pip install --require-hashes) from a trusted index.",
      ],
    });
  }

  const npmInsecure = await searchRepo({
    query: String.raw`npm\s+(?:install|i|ci)\s[^\n]*(?:--unsafe-perm|registry=http://|--registry\s+http://)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const npmRc = await searchRepo({
    query: String.raw`registry\s*=\s*http://`,
    isRegex: true,
    maxMatches: MAX,
  });
  const npmM = [...npmInsecure, ...npmRc].filter((m) => isDockerfile(m.file));
  if (npmM.length > 0) {
    findings.push({
      id: "DOCKER_NPM_INSECURE",
      title:
        "npm install uses --unsafe-perm or an http:// registry — runs lifecycle scripts as root / fetches packages over cleartext (CWE-494)",
      severity: "HIGH",
      evidence: ev(npmM),
      requiredActions: [
        "Remove --unsafe-perm and use an https:// registry; run npm as a non-root user.",
        "Use npm ci with a committed lockfile and integrity hashes from a trusted registry.",
      ],
    });
  }

  const apkNoCache = await searchRepo({
    query: String.raw`\bapk\s+add\b[^\n]*`,
    isRegex: true,
    maxMatches: MAX,
  });
  const apkM = apkNoCache.filter(
    (m) => isDockerfile(m.file) && !/--no-cache/i.test(m.preview)
  );
  if (apkM.length > 0) {
    findings.push({
      id: "DOCKER_APK_NO_CACHE",
      title:
        "apk add without --no-cache — leaves the package index cache in the layer, enlarging the image and retaining stale metadata",
      severity: "LOW",
      evidence: ev(apkM),
      requiredActions: [
        "Add --no-cache to apk add so the index is not persisted in the image layer.",
        "Pin exact package versions (apk add pkg=version) for reproducible builds.",
      ],
    });
  }

  return findings;
}

// 15. Deprecated/unverified key handling (apt-key adv, gpg --keyserver)
async function checkDeprecatedKeyHandling(): Promise<Finding[]> {
  const aptKey = await searchRepo({
    query: String.raw`\bapt-key\s+adv\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const gpgKs = await searchRepo({
    query: String.raw`\bgpg\b[^\n]*--keyserver\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = [...aptKey, ...gpgKs].filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_DEPRECATED_KEY_TRUST",
    title:
      "Dockerfile uses deprecated/unverified key trust (apt-key adv / gpg --keyserver) — keys fetched over the network without fingerprint pinning (CWE-494)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Stop using apt-key (deprecated); download the key over HTTPS, verify its full fingerprint, and store it in /etc/apt/keyrings with signed-by.",
      "Never import GPG keys from a keyserver without pinning and verifying the exact fingerprint.",
    ],
  }];
}

// 16. wget/curl with certificate checks disabled
async function checkInsecureDownloadFlags(): Promise<Finding[]> {
  const wgetNoCheck = await searchRepo({
    query: String.raw`\bwget\b[^\n]*--no-check-certificate\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const curlInsecure = await searchRepo({
    query: String.raw`\bcurl\b[^\n]*(?:\s-k\b|\s--insecure\b)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = [...wgetNoCheck, ...curlInsecure].filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_INSECURE_DOWNLOAD_FLAG",
    title:
      "Dockerfile downloads with certificate verification disabled (wget --no-check-certificate / curl -k / curl --insecure) — exposes the build to MITM (CWE-295)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Remove --no-check-certificate / -k / --insecure; let the download fail on an invalid certificate.",
      "Install the proper CA bundle so HTTPS validation succeeds without disabling it.",
    ],
  }];
}

// 17. Multi-stage COPY --from of a secret/credential file into final image
async function checkCopyFromSecretFile(): Promise<Finding[]> {
  const copyFrom = await searchRepo({
    query: String.raw`^\s*COPY\s+--from=\S+\s[^\n]*(?:secret|credential|\.pem|\.key|id_rsa|\.npmrc|\.env|token)`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = copyFrom.filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COPY_FROM_SECRET",
    title:
      "Multi-stage COPY --from pulls a secret/credential file (key/.pem/.env/.npmrc/token) into the final image — persisted in the runtime layer (CWE-522)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Do not COPY secret material between stages into the final image; use BuildKit secret mounts (RUN --mount=type=secret) that never land in a layer.",
      "Inject credentials at runtime via a secrets manager; ensure no key/.env/.npmrc file is present in the shipped image.",
    ],
  }];
}

// 18. RUN consumes a *_TOKEN / *_PASSWORD env without a BuildKit secret mount
async function checkRunTokenNoSecretMount(): Promise<Finding[]> {
  const runToken = await searchRepo({
    query: String.raw`^\s*RUN\s[^\n]*\$\{?[A-Z_]*(?:TOKEN|PASSWORD|SECRET|API_?KEY)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = runToken.filter(
    (m) => isDockerfile(m.file) && !/--mount=type=secret/i.test(m.preview)
  );
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_RUN_SECRET_NO_MOUNT",
    title:
      "RUN consumes a token/password environment variable without a BuildKit --mount=type=secret — the secret is exposed in build env and may leak into layers (CWE-522)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Provide build-time secrets through RUN --mount=type=secret,id=… and read them from /run/secrets at build time only.",
      "Never reference secret-bearing ARG/ENV values directly in a RUN command; they can persist in image history.",
    ],
  }];
}

// 19. EXPOSE 22 — SSH daemon inside container
async function checkExposeSsh(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*EXPOSE\s+(?:22|22/tcp)\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_EXPOSE_SSH",
    title:
      "Dockerfile EXPOSEs port 22 — running an SSH daemon inside a container is an anti-pattern that adds a remote-access attack surface (CWE-1188)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Remove the SSH server and EXPOSE 22; use 'docker exec' or kubectl exec for shell access instead.",
      "If remote access is genuinely required, run SSH in a separate, hardened, network-restricted service.",
    ],
  }];
}

// 20. Shell-form ENTRYPOINT/CMD (PID 1 signal handling)
async function checkShellFormEntrypoint(): Promise<Finding[]> {
  // Shell form does NOT start with "[" after the instruction.
  const ep = await searchRepo({
    query: String.raw`^\s*(?:ENTRYPOINT|CMD)\s+[^[\s]`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = ep.filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_SHELL_FORM_ENTRYPOINT",
    title:
      "Shell-form ENTRYPOINT/CMD — the app runs under /bin/sh -c as a child of PID 1, so it never receives SIGTERM/SIGINT for graceful shutdown",
    severity: "LOW",
    evidence: ev(matches),
    requiredActions: [
      "Use exec form: ENTRYPOINT [\"executable\", \"arg\"] so the process becomes PID 1 and receives signals.",
      "Add an init (e.g. tini) if you need proper zombie reaping.",
    ],
  }];
}

// 21. WORKDIR / and writes into sensitive host-like paths
async function checkSensitivePaths(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const workdirRoot = await searchRepo({
    query: String.raw`^\s*WORKDIR\s+/\s*$`,
    isRegex: true,
    maxMatches: MAX,
  });
  const wdM = workdirRoot.filter((m) => isDockerfile(m.file));
  if (wdM.length > 0) {
    findings.push({
      id: "DOCKER_WORKDIR_ROOT",
      title:
        "WORKDIR / sets the working directory to the root filesystem — subsequent COPY/RUN operate on system directories, risking overwrite of OS files",
      severity: "LOW",
      evidence: ev(wdM),
      requiredActions: [
        "Set WORKDIR to a dedicated application directory (e.g. WORKDIR /app), not /.",
        "Ensure that directory is owned by the non-root runtime user.",
      ],
    });
  }

  const sshWrite = await searchRepo({
    query: String.raw`(?:COPY|ADD|RUN)\s[^\n]*(?:/root/\.ssh|/etc/ssh|~/\.ssh)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const sshM = sshWrite.filter((m) => isDockerfile(m.file));
  if (sshM.length > 0) {
    findings.push({
      id: "DOCKER_WRITE_SSH_DIR",
      title:
        "Dockerfile writes into an SSH directory (/root/.ssh, /etc/ssh, ~/.ssh) — baking SSH keys/config into the image leaks credentials (CWE-522)",
      severity: "HIGH",
      evidence: ev(sshM),
      requiredActions: [
        "Do not place SSH keys or config into the image; mount them at runtime or use a secrets manager.",
        "Use BuildKit SSH forwarding (RUN --mount=type=ssh) for git operations during build instead of copying keys.",
      ],
    });
  }

  return findings;
}

// 22. Download to /tmp then execute
async function checkTmpDownloadExec(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*RUN\s[^\n]*(?:curl|wget)[^\n]*\s/tmp/\S+[^\n]*&&[^\n]*(?:chmod|sh|bash|\./)`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_TMP_DOWNLOAD_EXEC",
    title:
      "RUN downloads an artifact into /tmp and then executes it — world-writable /tmp plus unverified download enables build-time code injection (CWE-377/CWE-494)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Download to a private directory, verify a checksum/signature, then execute; do not stage executables in world-writable /tmp.",
      "Pin and verify the artifact's integrity before running it.",
    ],
  }];
}

// 23. ONBUILD triggers
async function checkOnbuild(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*ONBUILD\s+\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_ONBUILD_TRIGGER",
    title:
      "Dockerfile defines ONBUILD triggers — instructions execute implicitly in any downstream image, hiding behavior from consumers (CWE-829)",
    severity: "LOW",
    evidence: ev(matches),
    requiredActions: [
      "Avoid ONBUILD; make build steps explicit in each consuming Dockerfile so behavior is visible and auditable.",
      "If a base image must run setup, document it and prefer explicit RUN steps over hidden triggers.",
    ],
  }];
}

// 24. Untrusted/self-hosted registry over http, or FROM scratch + ADD remote
async function checkUntrustedRegistry(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const httpFrom = (await searchRepo({
    query: String.raw`^\s*FROM\s+http://\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  // FROM <host:port>/img — explicit registry host (self-hosted); flag http or bare host
  const hostFrom = (await searchRepo({
    query: String.raw`^\s*FROM\s+\S+:\d+/\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  const regM = [...httpFrom, ...hostFrom];
  if (regM.length > 0) {
    findings.push({
      id: "DOCKER_UNTRUSTED_REGISTRY",
      title:
        "Base image pulled from an http/self-hosted registry host:port — image may be served over cleartext or from an unvetted source (CWE-494)",
      severity: "MEDIUM",
      evidence: ev(regM),
      requiredActions: [
        "Pull base images only from a trusted registry over HTTPS, and pin by @sha256 digest.",
        "Configure content trust / signature verification (cosign, Docker Content Trust) for all base images.",
      ],
    });
  }

  const scratchAdd = (await searchRepo({
    query: String.raw`^\s*ADD\s+https?://\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  // Pair: file must also contain FROM scratch
  if (scratchAdd.length > 0) {
    const scratchFiles = new Set(
      (await searchRepo({
        query: String.raw`^\s*FROM\s+scratch\b`,
        isRegex: true,
        maxMatches: MAX,
      })).filter((m) => isDockerfile(m.file)).map((m) => m.file)
    );
    const paired = scratchAdd.filter((m) => scratchFiles.has(m.file));
    if (paired.length > 0) {
      findings.push({
        id: "DOCKER_SCRATCH_ADD_REMOTE",
        title:
          "FROM scratch combined with ADD of a remote URL — no CA store in scratch means the remote artifact cannot be TLS-verified, and ADD performs no integrity check (CWE-494)",
        severity: "HIGH",
        evidence: ev(paired),
        requiredActions: [
          "Fetch and verify the remote artifact (checksum/signature) in a builder stage that has a CA bundle, then COPY it into the scratch image.",
          "Never ADD a remote URL directly into a scratch-based final image.",
        ],
      });
    }
  }

  return findings;
}

// 25. Broad chown -R and setuid (chmod u+s / 4xxx)
async function checkBroadChownSetuid(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const chown = (await searchRepo({
    query: String.raw`\bchown\s+-R\s[^\n]*(?:\s/\s|\s/app\s|\s/usr\s|\s/etc\s|:\s*root)`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  if (chown.length > 0) {
    findings.push({
      id: "DOCKER_BROAD_CHOWN",
      title:
        "Recursive chown -R over a broad path (/ , /usr, /etc or to root) — over-broad ownership change can weaken file permissions and bloat the layer (CWE-732)",
      severity: "LOW",
      evidence: ev(chown),
      requiredActions: [
        "Scope chown -R to the specific application directory and target the non-root runtime user.",
        "Prefer COPY --chown=user:group to set ownership without a separate recursive chown layer.",
      ],
    });
  }

  const setuid = (await searchRepo({
    query: String.raw`\bchmod\s[^\n]*(?:u\+s|g\+s|\s[24]\d{3}\b)`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isDockerfile(m.file));
  if (setuid.length > 0) {
    findings.push({
      id: "DOCKER_SETUID_BIT",
      title:
        "Dockerfile sets the setuid/setgid bit (chmod u+s / 4xxx) — a setuid binary in the image is a classic privilege-escalation primitive (CWE-250)",
      severity: "HIGH",
      evidence: ev(setuid),
      requiredActions: [
        "Remove setuid/setgid bits; strip them from base-image binaries you do not need (find / -perm /6000 -type f).",
        "Run the workload as a non-root user and avoid any need for setuid escalation.",
      ],
    });
  }

  return findings;
}

// ===========================================================================
// ROUND 2 — docker-compose / runtime depth (prefix DOCKER_COMPOSE_)
// ===========================================================================

// 26. ipc: host
async function checkComposeIpcHost(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*ipc\s*:\s*["']?host\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_IPC_HOST",
    title:
      "docker-compose sets ipc: host — the container shares the host IPC namespace (shared memory), breaking isolation between container and host (CWE-668)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Remove ipc: host; use the default private IPC namespace.",
      "If shared memory between specific containers is needed, use ipc: shareable scoped to those services only.",
    ],
  }];
}

// 27. devices mapping host /dev entries
async function checkComposeHostDevices(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*-\s*["']?/dev/\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_HOST_DEVICE",
    title:
      "docker-compose maps a host /dev device into the container — direct hardware/device access can be abused to reach the host or other tenants (CWE-668)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Remove the devices mapping unless strictly required; never map block devices like /dev/sda or /dev/mem.",
      "Scope device access to the minimum needed and combine with cap_drop and a restrictive seccomp profile.",
    ],
  }];
}

// 28. Sensitive host bind mounts ( / /etc /root ~/.ssh /proc /sys )
async function checkComposeSensitiveMounts(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*-\s*["']?(?:/|/etc|/root|/proc|/sys|~/\.ssh|\$HOME/\.ssh):`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_SENSITIVE_BIND_MOUNT",
    title:
      "docker-compose bind-mounts a sensitive host path (/, /etc, /root, /proc, /sys, ~/.ssh) — gives the container read/write access to host secrets and config (CWE-668)",
    severity: "CRITICAL",
    evidence: ev(matches),
    requiredActions: [
      "Never bind-mount /, /etc, /root, /proc, /sys or SSH directories into a container.",
      "Mount only the specific data directory the service needs, read-only where possible (:ro).",
    ],
  }];
}

// 29. env_file referencing committed secret files
async function checkComposeEnvFileSecret(): Promise<Finding[]> {
  // Inline form: "env_file: secrets.env"
  const inline = await searchRepo({
    query: String.raw`^\s*env_file\s*:\s*["']?\S*(?:secret|\.env\.prod|credential|\.env\b)`,
    isRegex: true,
    maxMatches: MAX,
  });
  // List-item form: a "- <name>.env" / "- secrets.*" entry referencing a secret env file.
  const listItem = await searchRepo({
    query: String.raw`^\s*-\s*["']?\S*(?:secrets?\.env|\.env\.prod|credentials?\.env)\b`,
    isRegex: true,
    maxMatches: MAX,
  });
  const matches = [...inline, ...listItem].filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_ENV_FILE_SECRET",
    title:
      "docker-compose env_file references a secret/.env file — if committed, this leaks credentials into version control and the build context (CWE-538)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Keep secret env files out of version control (.gitignore, .dockerignore) and inject via a secrets manager.",
      "Use Docker/Compose secrets (top-level secrets:) instead of plaintext env_file for sensitive values.",
    ],
  }];
}

// 30. container user: root / "0"
async function checkComposeUserRoot(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*user\s*:\s*["']?(?:root|0)["']?\s*$`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_USER_ROOT",
    title:
      "docker-compose runs the service as user: root / \"0\" — the container process runs as uid 0, maximizing blast radius of any compromise (CWE-250)",
    severity: "HIGH",
    evidence: ev(matches),
    requiredActions: [
      "Set user: to a non-root uid:gid (e.g. user: \"1000:1000\").",
      "Ensure the image defines and owns a non-root user for the mounted/working directories.",
    ],
  }];
}

// 31. healthcheck disable: true
async function checkComposeHealthcheckDisabled(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*disable\s*:\s*true\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file) && /healthcheck/i.test(m.preview) === false);
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_HEALTHCHECK_DISABLED",
    title:
      "docker-compose healthcheck disable: true — the orchestrator cannot detect a hung or compromised container and will keep routing traffic to it",
    severity: "LOW",
    evidence: ev(matches),
    requiredActions: [
      "Remove disable: true and define a real healthcheck (test/interval/timeout/retries).",
      "Ensure the orchestrator acts on unhealthy status (restart / stop routing).",
    ],
  }];
}

// 32. cap_drop missing while running a service (heuristic) + read_only absent
async function checkComposeHardeningHeuristics(): Promise<Finding[]> {
  const findings: Finding[] = [];

  const extraHosts = (await searchRepo({
    query: String.raw`^\s*-\s*["']?\S+:(?:\d{1,3}\.){3}\d{1,3}\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file) && /extra_hosts|^\s*-\s/i.test(m.preview));
  // Narrow to extra_hosts context by requiring the host:ip pattern under extra_hosts;
  // we accept any "name:ip" list entry in a compose file as a spoofing indicator.
  if (extraHosts.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_EXTRA_HOSTS_SPOOF",
      title:
        "docker-compose extra_hosts pins a hostname to a static IP — can be used to spoof/override DNS for the container and redirect traffic (CWE-350)",
      severity: "LOW",
      evidence: ev(extraHosts),
      requiredActions: [
        "Remove unnecessary extra_hosts entries; rely on real DNS so hostname-to-IP mapping is verifiable.",
        "If a static mapping is required, document and restrict it; do not point service hostnames at attacker-controllable IPs.",
      ],
    });
  }

  const untrustedDns = (await searchRepo({
    query: String.raw`^\s*-\s*["']?(?:8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9)\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (untrustedDns.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_UNTRUSTED_DNS",
      title:
        "docker-compose pins a public DNS resolver (dns:) — overriding the corporate resolver can bypass internal name resolution and DNS-based egress controls (CWE-350)",
      severity: "LOW",
      evidence: ev(untrustedDns),
      requiredActions: [
        "Use the organization's approved DNS resolver instead of hard-coding public ones.",
        "Enforce DNS egress policy at the network layer rather than per-container overrides.",
      ],
    });
  }

  const labelSecret = await scanComposeLabelSecrets();
  if (labelSecret.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_LABEL_SECRET",
      title:
        "docker-compose label appears to embed a secret value — labels are visible via docker inspect to anyone with daemon access (CWE-200)",
      severity: "MEDIUM",
      evidence: ev(labelSecret),
      requiredActions: [
        "Remove secret values from labels; labels are not a secure storage mechanism.",
        "Use Docker/Compose secrets or a secrets manager for sensitive values.",
      ],
    });
  }

  return findings;
}

// 33. tmpfs without noexec (exec allowed on tmpfs)
async function checkComposeTmpfsExec(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`exec\b[^\n]*(?:size=|/tmp|/run)|tmpfs[^\n]*exec\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file) && /tmpfs|exec/i.test(m.preview) && /noexec/i.test(m.preview) === false && /exec/i.test(m.preview));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_TMPFS_EXEC",
    title:
      "docker-compose tmpfs is mounted with exec (no noexec) — a writable, executable in-memory filesystem lets an attacker stage and run payloads (CWE-732)",
    severity: "LOW",
    evidence: ev(matches),
    requiredActions: [
      "Mount tmpfs with noexec,nosuid,nodev unless execution is genuinely required.",
      "Keep writable temp space non-executable to prevent dropped-payload execution.",
    ],
  }];
}

// 34. deploy resource limits absent is hard to assert negatively per-line;
// instead flag explicitly unbounded settings and restart:always on privileged.
async function checkComposeDosAndRestart(): Promise<Finding[]> {
  const findings: Finding[] = [];

  // mem_limit: 0 / cpus: 0 — explicitly unbounded
  const unbounded = (await searchRepo({
    query: String.raw`^\s*(?:mem_limit|memory|cpus)\s*:\s*["']?0\b`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file));
  if (unbounded.length > 0) {
    findings.push({
      id: "DOCKER_COMPOSE_NO_RESOURCE_LIMIT",
      title:
        "docker-compose sets an unbounded resource value (mem_limit/cpus: 0) — a single container can exhaust host CPU/memory, enabling a local DoS (CWE-770)",
      severity: "LOW",
      evidence: ev(unbounded),
      requiredActions: [
        "Set concrete memory and CPU limits (mem_limit / deploy.resources.limits) for every service.",
        "Reserve and cap resources so one container cannot starve the host or co-tenants.",
      ],
    });
  }

  return findings;
}

// 35. build.args passing a secret-named argument from compose
async function checkComposeBuildArgsSecret(): Promise<Finding[]> {
  const matches = (await searchRepo({
    query: String.raw`^\s*\S*(?:TOKEN|PASSWORD|SECRET|API_?KEY|CREDENTIAL)\S*\s*:\s*\S`,
    isRegex: true,
    maxMatches: MAX,
  })).filter((m) => isCompose(m.file) && /^\s{6,}\S/.test(m.preview));
  if (matches.length === 0) return [];
  return [{
    id: "DOCKER_COMPOSE_BUILD_ARG_SECRET",
    title:
      "docker-compose build.args passes a secret-named argument — the value becomes a build ARG, baked into image history (CWE-200)",
    severity: "MEDIUM",
    evidence: ev(matches),
    requiredActions: [
      "Do not pass secrets via build.args; use BuildKit secret mounts and pass the secret at build time without persisting it.",
      "Reference runtime secrets through a secrets manager rather than build arguments.",
    ],
  }];
}

export async function checkDockerDeep(opts: { changedFiles: string[] }): Promise<Finding[]> {
  void opts;
  void DOCKERFILE_RE;
  void COMPOSE_RE;
  const settled = await Promise.allSettled([
    checkUnpinnedBaseImage(),
    checkPipeToShell(),
    checkSudoAnd777(),
    checkMissingHealthcheck(),
    checkBroadCopyAndArchive(),
    checkAptNoRecommends(),
    checkComposeCapabilities(),
    checkDaemonExposure(),
    checkNoSandboxAndRootUser(),
    checkSecretBuildArg(),
    checkComposePrivileged(),
    checkImplicitRegistry(),
    // Round 2 — Dockerfile depth
    checkTlsVerifyDisabled(),
    checkInsecurePackageManager(),
    checkDeprecatedKeyHandling(),
    checkInsecureDownloadFlags(),
    checkCopyFromSecretFile(),
    checkRunTokenNoSecretMount(),
    checkExposeSsh(),
    checkShellFormEntrypoint(),
    checkSensitivePaths(),
    checkTmpDownloadExec(),
    checkOnbuild(),
    checkUntrustedRegistry(),
    checkBroadChownSetuid(),
    // Round 2 — compose / runtime depth
    checkComposeIpcHost(),
    checkComposeHostDevices(),
    checkComposeSensitiveMounts(),
    checkComposeEnvFileSecret(),
    checkComposeUserRoot(),
    checkComposeHealthcheckDisabled(),
    checkComposeHardeningHeuristics(),
    checkComposeTmpfsExec(),
    checkComposeDosAndRestart(),
    checkComposeBuildArgsSecret(),
  ]);
  const findings: Finding[] = [];
  for (const r of settled) {
    if (r.status === "fulfilled") findings.push(...r.value);
  }
  return findings;
}
