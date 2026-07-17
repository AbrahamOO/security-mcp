import type { RuleCase } from "./types.js";

export const cases: RuleCase[] = [
  {
    ruleId: "SBOM_MISSING",
    check: "sbom",
    positive: {
      file: "package.json",
      content: `{\n  "name": "example-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "express": "^4.18.2"\n  }\n}\n`
    },
    negative: {
      file: ".mcp/sbom/latest.json",
      content: `{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "components": [\n    { "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2" }\n  ]\n}\n`
    },
    note: "Positive is a normal repo with only package.json committed, no .mcp/sbom/latest.json — triggers SBOM_MISSING because the fixed SBOM path is absent (requires the `syft` binary to be resolvable on PATH; the check silently skips this finding when syft is unavailable). Negative places a valid CycloneDX SBOM at that exact fixed path (freshly written by the test harness, so it also reads as not-stale and cannot trip SBOM_STALE); since no package.json exists alongside it, SBOM_COMPONENT_MISMATCH also cannot fire."
  },
  {
    ruleId: "PROVENANCE_MISSING",
    check: "sbom",
    positive: {
      file: ".github/workflows/release.yml",
      content: `name: release\non:\n  push:\n    tags:\n      - 'v*'\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm run build\n      - run: npm publish\n`
    },
    negative: {
      file: ".mcp/attestations/provenance.intoto.jsonl",
      content: `{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YxIn0=","signatures":[{"keyid":"release-key-01","sig":"MEUCIQDx3example4signature4bytes4here4base64AiEA1exampleSignaturePadding=="}]}\n`
    },
    note: "Positive is a realistic release workflow that builds and publishes a tagged release but never emits an SLSA attestation, so the fixed .mcp/attestations/ directory (auto-created empty by the check) has zero matching files and PROVENANCE_MISSING fires. Negative places a well-formed in-toto attestation bundle at .mcp/attestations/provenance.intoto.jsonl, matching the `**/*.intoto.jsonl` glob the check scans for, which suppresses the finding regardless of the (unparsed) attestation payload contents."
  }
];
