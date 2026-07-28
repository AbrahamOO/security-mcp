# Limitations

Created: 2026-07-25
Last updated: 2026-07-27

What this tool does not do, cannot do, or does less well than it might appear. Written
for a reviewer deciding how much weight to put on its output.

If you find something here that is out of date, it is a defect. File it.

## Agent execution

Everything in this section concerns `src/agent-exec/`, the subsystem that drives your locally
installed agent CLIs as child processes. Its architecture is described in
[ARCHITECTURE.md](ARCHITECTURE.md) and its trust boundaries in [DATA_FLOW.md](DATA_FLOW.md).

**Agent *execution* requires an explicit `orchestration.start_agent_run`. Adapter *detection* does
not.** `orchestration.executor_status` probes for installed CLIs, and `security.fortify` calls it to
decide which next steps to hand back. Detection runs each candidate binary with its version flag, so
a plain `security.fortify` call does spawn subprocesses even though it spawns no agents. "Costs zero
tokens" is true; "runs nothing" is not.

**Three CLI adapters are verified; the rest are guesses.** `claude` (2.1.92), `codex`
(0.146.0-alpha.3.1), and `copilot` (1.0.75) were each driven end to end on real code and
their flags confirmed. `gemini`, `ollama`, `aider`, `cursor-agent`, `opencode`, and
`goose` ship as best-effort configuration with a populated `_unverified[]` field, which
`orchestration.executor_status` reports verbatim at runtime. Fixing a wrong flag is a
JSON edit in `defaults/agent-clis.json`, not a code change.

**Copilot auth cannot be confirmed, only presumed.** It exposes no `login status`
subcommand and stores its OAuth token in the system credential store, which is not
readable. The adapter reports `auth.presumed: true` and the run diagnoses failure on the
first agent rather than the eighty-fourth.

**Copilot cannot run headless with per-tool prompting.** `--allow-all-tools` is required
for non-interactive mode, so least privilege is expressed through `--available-tools`,
`--excluded-tools`, `--deny-tool`, `--add-dir`, and `--deny-url` instead. That is a
weaker boundary than Codex's `-s read-only` sandbox. The adapter records it.

**Codex lives inside a VS Code extension bundle**, so its path changes when the
extension updates. Detection re-globs and the cache is keyed on file mtime, but a
hard-coded absolute path in a user config will rot. `SECURITY_AGENT_CLI` accepts an
explicit path.

**Codex 0.146.0-alpha.3.1 is an alpha.** Flags move between releases.

**Class B (completion-only) execution is not a security review.** When the server has to
supply the agent loop itself for a CLI with no tools, a small local model reads a handful
of files out of thousands, misses cross-file taint chains, and invents CWE numbers. It is
useful for smoke-testing the pipeline and for air-gapped obvious-mistake passes. The
capability floor marks such runs non-compliant, and they cannot produce a green gate.
Prefer `codex --oss --local-provider ollama`, which gives a local model a real agent loop.

**Throttling is real.** 84 agents will hit rate limits even spread across three
subscriptions. The AIMD limiter degrades gracefully and never abandons a run, but a full
sweep on constrained plans can stall for a long time. `executor_status` estimates
wall-clock before you start.

## Trust in findings

**Corroboration measures agreement, not truth.** A `corroborated` label means two or more
independent providers confirmed the claim from the cited code without seeing the original
reasoning. Three models can share a blind spot, particularly on framework-specific
behaviour and on anything thin in training data.

**Findings are model output.** Every one cites a file that was verified to exist and sit
inside the workspace, and hallucinated paths are dropped and counted. That prevents
fabricated locations. It does not prevent a plausible-sounding but wrong analysis of a
real file.

**Severity is coerced when a model emits something unrecognised.** The fallback is
MEDIUM, and `severity_coerced` is recorded in the agent's degradation reasons.

**Prompt injection into a tool-armed child is a genuine new risk.** In `auto_apply` mode
a model reading untrusted repository content holds write access. Mitigations: audit-only
is the default, sandbox modes are applied where the CLI supports them, access is scoped
to the workspace root, network tools are denied unless `internetPermitted`, the parent's
secrets are stripped from the child environment, and a hardening preamble frames all repo
content as data. These reduce the risk. They do not remove it.

## Reports and evidence

**`security.generate_compliance_report` is an evidence-gathering aid, not an audit.** A
control is marked satisfied only when a gate run completed its required steps with no
adverse finding, never by default, and every control is `unverified` when no gate run is
supplied.

**An unsigned attestation chain is tamper-evident, not tamper-proof.** Without
`SECURITY_AUDIT_HMAC_KEY` the chain is SHA-256 over public data, so anyone with write
access to the run directory can recompute it over edited content. Set the key to make a
rewrite require the secret.

**Cost figures on a subscription plan are API-equivalent, not money charged.** They are
labelled `notionalCostUsd` with `costIsNotional: true` and must never be presented as
spend.

## Coverage

**`completed_na` is a real verdict, not a skip — but it is a cheap one.** It is decided
from stack detection plus a filename sweep for the agent's own signals, both of which must
come up empty. It records which signals were searched. It does not read source code, so a
domain present only in code that no filename hints at could be missed.

**Scope prefiltering is a hint, not a boundary.** Each agent is handed candidate files
matched from its manifest keywords and told explicitly that the list is a starting point.
An agent that ignores the hint and searches the repo itself is behaving correctly.

**A scanner that is not installed is not a clean result.** Missing scanners are listed in
the run's context pack under "Scanners UNAVAILABLE" precisely so absence of findings is
not read as absence of problems.

## The detection engine

**Content matching is line-based.** Every rule driven by `searchRepo` sees one line at a
time, so a construct spread over several lines is only judged by the line that matched.
Rules where that matters read a window around the hit instead (the password-reset and
refresh-token rules do), but this is per rule, not a property of the engine. A vulnerable
pattern split across lines in a way no rule anticipates can be missed.

**Each query stops at its match cap, and the run says so.** A capped search returns the
same shape as an exhausted one, so a rule that filters its hits — keep the ones without a
sanitizer on the line — can have the match that mattered sitting past the cap.
`SEARCH_RESULTS_TRUNCATED` (MEDIUM) names the queries that hit the ceiling. It means
reduced confidence in the absence of findings for those rules, not a vulnerability, and it
is expected on large monorepos. Scan in slices to clear it.

**Nothing is excluded from a scan by directory name.** Per-project exclusions come only
from `SECURITY_GATE_IGNORE`, which the operator sets. Anything excluded that way is
genuinely unscanned: the tool cannot distinguish "no findings here" from "never looked".

**Two rules are narrower than their names suggest.** `PIP_NO_HASH_CHECKING` fires on a
`pip install` invocation without `--require-hashes`, not on a `requirements.txt` that
merely lacks hashes — flagging every hash-less requirements file would fire on nearly
every Python repository. `AGENT_SYMLINK_ESCAPE` is about a real symlink whose target
leaves the workspace, not about a path written inside an instruction file's text; a
`../../etc/passwd` mentioned in prose is not a symlink and is not this finding.

**Finding ids are the rule's name, not a generic category.** A weak-random identifier is
`CRYPTO_INSECURE_RANDOM`, a header-splitting sink is `HTTP_RESPONSE_SPLITTING_HEADER`, and
a hardcoded credential is usually `POSSIBLE_SECRET` at CRITICAL. Searching a report for a
category name you expected, rather than reading the ids present, will read as a gap that
is not there.

## Historical data

**The 13 agent runs predating this work are not evidence.** They sit at `phase: 0` with
266 of 280 agent slots never executed, and their report files were hand-authored by an LLM
with mutually incompatible schemas and invented midnight timestamps. The completion gate
now refuses to merge or attest them, which is the honest outcome. Move them aside rather
than treating them as history.

## Change History

- 2026-07-27 - Added "The detection engine": line-based matching, the per-query match cap and
  the `SEARCH_RESULTS_TRUNCATED` finding that now reports it, the rule that nothing is excluded
  by directory name (only `SECURITY_GATE_IGNORE`), the two rules narrower than their names
  (`PIP_NO_HASH_CHECKING`, `AGENT_SYMLINK_ESCAPE`), and the fact that finding ids are rule names
  rather than generic categories.

- 2026-07-25 - Created. Documents adapter verification status, Class B quality ceiling, corroboration semantics, attestation and cost caveats, N/A and prefilter limits, and the status of pre-existing runs.
