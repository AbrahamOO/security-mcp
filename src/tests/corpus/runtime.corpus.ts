import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "DOCKER_NO_USER_DIRECTIVE",
    check: "docker",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --production\nCOPY . .\nEXPOSE 3000\nCMD ["node", "server.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --production\nCOPY . .\nRUN adduser --disabled-password --gecos "" appuser\nUSER appuser\nEXPOSE 3000\nCMD ["node", "server.js"]\n`
    },
    note: "Negative adds a dedicated non-root user and a USER directive after the last FROM, the exact fix the rule's requiredActions recommend — not just a renamed variable."
  },
  {
    ruleId: "DOCKER_ADD_REMOTE_URL",
    check: "docker",
    positive: {
      file: "Dockerfile",
      content: `FROM ubuntu:22.04\nADD https://example.com/releases/app.tar.gz /opt/app.tar.gz\nRUN tar -xzf /opt/app.tar.gz -C /opt\nCMD ["/opt/app/start.sh"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM ubuntu:22.04\nRUN curl --fail -sSL https://example.com/releases/app.tar.gz -o /opt/app.tar.gz \\\n  && echo "3f786850e387550fdab836ed7e6dc881de23001b  /opt/app.tar.gz" | sha256sum -c - \\\n  && tar -xzf /opt/app.tar.gz -C /opt \\\n  && rm /opt/app.tar.gz\nCMD ["/opt/app/start.sh"]\n`
    },
    note: "Negative has no line beginning with 'ADD <url>'; it fetches via RUN curl and verifies a checksum before extracting, the exact mitigation the rule's requiredActions describe."
  },
  {
    ruleId: "DOCKER_SECRETS_IN_ENV",
    check: "docker",
    positive: {
      file: "Dockerfile",
      content: `FROM node:20-alpine\nENV NODE_ENV=production\nENV DB_PASSWORD=SuperSecretPass123\nCMD ["node", "server.js"]\n`
    },
    negative: {
      file: "Dockerfile",
      content: `FROM node:20-alpine\nENV NODE_ENV=production\nENV PORT=3000\n# DB_PASSWORD and other credentials are injected at container start via\n# \`docker run -e DB_PASSWORD=...\` or a secrets manager, never baked into an ENV instruction.\nCMD ["node", "server.js"]\n`
    },
    note: "Negative's ENV instructions carry only non-secret config (NODE_ENV, PORT); the secret name appears only inside a comment line, which the rule's ^ENV anchor never inspects, matching real deploys that inject secrets at runtime."
  },
  {
    ruleId: "DOCKER_PRIVILEGED_FLAG",
    check: "docker",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.8"\nservices:\n  app:\n    image: myapp:latest\n    privileged: true\n    ports:\n      - "8080:8080"\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.8"\nservices:\n  app:\n    image: myapp:latest\n    cap_add:\n      - NET_ADMIN\n    security_opt:\n      - no-new-privileges:true\n    ports:\n      - "8080:8080"\n`
    },
    note: "Negative grants only the specific capability required (cap_add: NET_ADMIN) and sets no-new-privileges:true instead of privileged: true — a genuinely different YAML value, not a cosmetic rename (the substring 'privileges' in no-new-privileges never matches the rule's literal 'privileged')."
  },
  {
    ruleId: "DOCKER_SOCKET_MOUNT",
    check: "docker",
    positive: {
      file: "docker-compose.yml",
      content: `version: "3.8"\nservices:\n  ci-runner:\n    image: docker:24-dind\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    command: ["./run-tests.sh"]\n`
    },
    negative: {
      file: "docker-compose.yml",
      content: `version: "3.8"\nservices:\n  ci-runner:\n    image: docker:24-dind\n    environment:\n      DOCKER_HOST: "tcp://docker-proxy:2375"\n    depends_on:\n      - docker-proxy\n  docker-proxy:\n    image: tecnativa/docker-socket-proxy\n    environment:\n      CONTAINERS: 1\n      IMAGES: 1\n      POST: 0\n    ports:\n      - "2375"\n`
    },
    note: "Negative removes the raw socket bind mount entirely and talks to a restricted socket-proxy sidecar over TCP instead — no '/var/run/docker.sock' path appears anywhere in this compose file, unlike a variant that merely relabels the same mount."
  }
];
