import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DOCKER_BASE_IMAGE_UNPINNED",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:latest\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\nCMD ["node", "index.js"]\n`
    },
    note: "Positive's FROM node:latest matches the latestOrNoTag regex directly. Negative pins the same base image to an immutable @sha256 digest (the rule's exact requiredAction), so both the 'not @sha256' guard on the HIGH path and the bare-image regex fail to match."
  },
  {
    ruleId: "DOCKER_BASE_IMAGE_NO_DIGEST",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM python:3.11-slim\nWORKDIR /app\nCOPY requirements.txt ./\nRUN pip install -r requirements.txt\nCMD ["python", "app.py"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM python:3.11-slim@sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddee\nWORKDIR /app\nCOPY requirements.txt ./\nRUN pip install -r requirements.txt\nCMD ["python", "app.py"]\n`
    },
    note: "Positive has a mutable tag (3.11-slim) with no digest, matching tagNoDigest. Negative appends the @sha256 digest to the same tag, which the mediumMatches filter explicitly excludes via !/@sha256:/i.test(preview)."
  },
  {
    ruleId: "DOCKER_RUN_PIPE_TO_SHELL",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM debian:12-slim\nRUN curl -sSL https://get.example.com/install.sh | bash\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM debian:12-slim\nRUN curl -fsSL https://get.example.com/install.sh -o /tmp/install.sh && echo "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  /tmp/install.sh" > /tmp/install.sh.sha256 && sha256sum -c /tmp/install.sh.sha256 && bash /tmp/install.sh && rm -f /tmp/install.sh /tmp/install.sh.sha256\n`
    },
    note: "Matching is per-line (searchRepo tests each line independently), so the regex needs curl...https://...|...bash all on one line. The positive line has a literal '|' piping straight into bash. The negative's RUN line downloads to a file, verifies a sha256 checksum, then executes the verified file — and contains no '|' character at all, so the pipe-to-shell regex cannot match regardless of backtracking."
  },
  {
    ruleId: "DOCKER_RUN_SUDO",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y sudo curl && usermod -aG sudo appuser\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\nUSER appuser\n`
    },
    note: "Positive's RUN line contains the word 'sudo', matching \\bsudo\\b. Negative performs the privileged apt-get step (as required by the fix) but never installs or invokes sudo, and drops to a non-root USER instead — no 'sudo' substring anywhere in the file."
  },
  {
    ruleId: "DOCKER_CHMOD_777",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod -R 777 /app/data\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM alpine:3.19\nCOPY entrypoint.sh /entrypoint.sh\nRUN chmod 755 /entrypoint.sh && chown -R appuser:appuser /app/data && chmod -R 750 /app/data\n`
    },
    note: "Positive's 'chmod -R 777' matches \\bchmod\\s[-a-zA-Z0-9\\s]*0?777\\b directly. Negative uses the minimal permissions the rule's requiredActions recommend (755 for the executable, 750 for data) plus explicit chown — no '777' substring anywhere in the file."
  },
  {
    ruleId: "DOCKER_COPY_WHOLE_CONTEXT",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci --omit=dev\nCOPY src ./src\nCOPY public ./public\nCMD ["node", "src/index.js"]\n`
    },
    note: "Positive's 'COPY . .' matches ^\\s*(?:COPY|ADD)\\s+\\.\\s+(?:\\.|\\./|/) because the first argument is a bare '.'. Negative (paired with a .dockerignore in a real repo) copies only the specific manifests and directories the runtime needs, so no COPY/ADD line's first token is a solitary '.'."
  },
  {
    ruleId: "DOCKER_EXPLICIT_USER_ROOT",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY . /app\nUSER root\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nRUN addgroup --system app && adduser --system --ingroup app appuser\nCOPY --chown=appuser:app . /app\nUSER appuser\nCMD ["node", "index.js"]\n`
    },
    note: "Positive's final 'USER root' line matches ^\\s*USER\\s+(?:root|0)\\s*$ exactly. Negative creates a dedicated low-privilege user and sets USER appuser as the final directive — 'appuser' is not 'root' or '0', so the exact-match regex cannot fire."
  },
  {
    ruleId: "DOCKER_SECRET_IN_BUILD_ARG",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nARG NPM_TOKEN\nRUN npm config set //registry.npmjs.org/:_authToken=\${NPM_TOKEN} && npm ci\n`
    },
    negative: {
      file: "Dockerfile",
      content: `# syntax=docker/dockerfile:1.4\nFROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nRUN --mount=type=secret,id=npm_token \\\n    npm config set //registry.npmjs.org/:_authToken="$(cat /run/secrets/npm_token)" && npm ci\n`
    },
    note: "Positive declares 'ARG NPM_TOKEN', matching ^\\s*ARG\\s+\\S*(?:TOKEN|...)\\b. Negative never declares an ARG at all — it uses a BuildKit secret mount (RUN --mount=type=secret) and reads the value from /run/secrets at build time, exactly the fix requiredActions describes, so no ARG line exists to match."
  },
  {
    ruleId: "DOCKER_TLS_VERIFY_DISABLED",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\nRUN npm ci\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nCOPY ca-certs/internal-ca.crt /usr/local/share/ca-certificates/internal-ca.crt\nRUN update-ca-certificates\nRUN npm ci\n`
    },
    note: "Positive's ENV line matches (?:ENV|ARG)\\s+\\S*NODE_TLS_REJECT_UNAUTHORIZED\\s*[= ]\\s*[\"']?0\\b directly. Negative fixes the underlying CA-trust gap by installing the correct internal CA certificate instead of disabling verification, so none of the NODE_TLS_REJECT_UNAUTHORIZED / PYTHONHTTPSVERIFY / GIT_SSL_NO_VERIFY patterns appear anywhere."
  },
  {
    ruleId: "DOCKER_COPY_FROM_SECRET",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 AS builder\nRUN npm ci && npm run build\n\nFROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nCOPY --from=builder /build/secrets/service.key /app/service.key\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 AS builder\nRUN npm ci && npm run build\n\nFROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nCOPY --from=builder /build/dist /app/dist\nCMD ["node", "index.js"]\n`
    },
    note: "Positive's COPY --from=builder line references '/build/secrets/service.key', matching the (?:secret|...|\\.key|...) alternation twice over. Negative copies only the compiled /build/dist output between stages — no secret/credential/.pem/.key/id_rsa/.npmrc/.env/token substring appears in the line."
  },
  {
    ruleId: "DOCKER_SHELL_FORM_ENTRYPOINT",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY . .\nCMD npm start\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY . .\nCMD ["npm", "start"]\n`
    },
    note: "Positive's 'CMD npm start' is shell form: the first non-whitespace char after CMD is 'n', matching [^[\\s]. Negative uses exec form 'CMD [\"npm\", \"start\"]' — the first non-whitespace char is '[', which the same character class explicitly excludes, so PID 1 becomes the actual npm process and receives signals correctly."
  },
  {
    ruleId: "DOCKER_ONBUILD_TRIGGER",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nONBUILD COPY . /app\nONBUILD RUN npm ci\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci --omit=dev\nCOPY src ./src\nCMD ["node", "src/index.js"]\n`
    },
    note: "Positive's 'ONBUILD COPY . /app' matches ^\\s*ONBUILD\\s+\\S. Negative makes every build step explicit in the Dockerfile itself (the rule's requiredAction) and contains no ONBUILD instruction at all."
  },
  {
    ruleId: "DOCKER_COPY_GIT_DIR",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY .git /app/.git\nCOPY package.json package-lock.json ./\nRUN npm ci\nCMD ["node", "index.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\nCOPY src ./src\nCMD ["node", "index.js"]\n`
    },
    note: "Positive's 'COPY .git /app/.git' matches ^\\s*(?:COPY|ADD)\\b[^\\n]*\\.git(?:/|\\s|\"|$) (the trailing '/app/.git' at end-of-line satisfies the '$' alternative) and contains none of the excluded .gitignore/.gitattributes/.github/.gitmodules/.gitkeep substrings. Negative (paired with .git in .dockerignore in a real repo) never references .git in any COPY/ADD line."
  },
  {
    ruleId: "DOCKER_EXPOSE_SENSITIVE_PORT",
    check: "docker-deep",
    positive: {
      file: "Dockerfile",
      content: `FROM postgres:16\nEXPOSE 3306\nCMD ["postgres"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-bullseye@sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\nWORKDIR /app\nCOPY . .\nEXPOSE 8080\nCMD ["node", "index.js"]\n`
    },
    note: "Positive's 'EXPOSE 3306' matches ^\\s*EXPOSE\\s[^\\n]*\\b(?:23|25|3306|5432)\\b. Negative exposes only the application's own HTTP port (8080); the database runs in its own dedicated container/network and is never EXPOSEd from this image."
  },
  {
    ruleId: "DOCKER_COMPOSE_PRIVILEGED",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    privileged: true\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    cap_drop: ["ALL"]\n    cap_add: ["NET_BIND_SERVICE"]\n`
    },
    note: "Positive's 'privileged: true' line matches ^\\s*privileged\\s*:\\s*true\\b directly. Negative removes privileged entirely and grants only the one specific capability the workload needs via inline (flow-style) YAML — no 'privileged' keyword appears anywhere in the file."
  },
  {
    ruleId: "DOCKER_COMPOSE_DANGEROUS_CAP",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    cap_add:\n      - SYS_ADMIN\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    cap_drop: ["ALL"]\n    cap_add: ["NET_BIND_SERVICE"]\n`
    },
    note: "Positive's block-list '- SYS_ADMIN' line matches -\\s*(?:SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|SYS_MODULE)\\b. The regex can't distinguish cap_add from cap_drop context, so even a correctly hardened 'cap_drop:\\n  - ALL' block-list would false-positive here — the negative deliberately uses inline flow syntax (cap_drop: [\"ALL\"]) with no leading '-' dash and adds back only NET_BIND_SERVICE, a capability outside the dangerous set, so the regex has no '-'-prefixed dangerous token to match."
  },
  {
    ruleId: "DOCKER_COMPOSE_SENSITIVE_BIND_MOUNT",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    volumes:\n      - "/etc:/etc:ro"\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    volumes:\n      - "app-data:/var/lib/app/data"\n`
    },
    note: "Positive's '- \"/etc:/etc:ro\"' line matches ^\\s*-\\s*[\"']?(?:/|/etc|/root|/proc|/sys|~/\\.ssh|\\$HOME/\\.ssh): because the value immediately after the opening quote is '/etc' followed by ':'. Negative mounts a named Docker volume ('app-data') scoped to the service's own data directory — the value right after the quote is 'app-data', which matches none of the sensitive-path alternatives anchored at that position."
  },
  {
    ruleId: "DOCKER_COMPOSE_USER_ROOT",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    user: "root"\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    user: "1000:1000"\n`
    },
    note: "Positive's 'user: \"root\"' matches ^\\s*user\\s*:\\s*[\"']?(?:root|0)[\"']?\\s*$ exactly (whole value is 'root'). Negative pins a concrete non-root uid:gid ('1000:1000'), which is not literally 'root' or '0', so the exact-match alternation cannot fire."
  },
  {
    ruleId: "DOCKER_DAEMON_TCP_EXPOSED",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  dind:\n    image: docker:dind\n    ports:\n      - "2375:2375"\n    environment:\n      DOCKER_HOST: "tcp://0.0.0.0:2375"\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  app:\n    image: myorg/app:1.0\n    ports:\n      - "8080:8080"\n`
    },
    note: "Positive's port mapping '\"2375:2375\"' matches (?::|\")(?:2375|2376)(?::|\") (quote immediately before, colon immediately after), and the DOCKER_HOST line separately matches the tcp:// alt-port regex. Negative never exposes the daemon over TCP at all — no port mapping or DOCKER_HOST value contains 2375 or 2376 anywhere."
  },
  {
    ruleId: "DOCKER_COMPOSE_BIND_ALL_INTERFACES",
    check: "docker-deep",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  db:\n    image: postgres:16\n    ports:\n      - "0.0.0.0:5432:5432"\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.9"\nservices:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n`
    },
    note: "Positive's '- \"0.0.0.0:5432:5432\"' matches ^\\s*-\\s*[\"']?0\\.0\\.0\\.0:\\d+:\\d+ literally. Negative binds the same sensitive database port to loopback only (127.0.0.1), the rule's exact requiredAction, so the fixed '0.0.0.0' prefix the regex requires is absent."
  }
];
