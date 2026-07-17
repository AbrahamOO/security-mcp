import type { RuleCase } from "./types.js";

/**
 * src/gate/checks/playbook.ts emits 3 finding ids:
 *   - IR_PLAYBOOK_MISSING    (required playbook file does not exist)
 *   - IR_PLAYBOOK_INCOMPLETE (playbook exists but is missing required sections)
 *   - IR_PLAYBOOK_STALE      (playbook exists but mtime is 180+ days old)
 *
 * Only IR_PLAYBOOK_INCOMPLETE is testable under this harness. Both other ids
 * are structurally incompatible with a single-file mkdtemp workspace:
 *
 * - IR_PLAYBOOK_MISSING: the corpus runner's baseCtx forces every surface
 *   (web, api, infra, mobileIos, mobileAndroid, ai) true, so the check always
 *   requires 7 distinct playbook paths to exist simultaneously (web-compromise.md,
 *   api-compromise.md, llm-prompt-injection.md, model-data-poisoning.md,
 *   cloud-misconfiguration.md, ransomware.md, mobile-credential-theft.md). The
 *   runner writes exactly one file per case, so at least 6 of those paths are
 *   always missing — the id fires unconditionally on both positive AND negative
 *   samples regardless of content. There is no single-file negative that avoids it.
 * - IR_PLAYBOOK_STALE: staleness is decided purely by `stat().mtimeMs` on the
 *   file the runner just wrote via `writeFileSync`, which is always "now". No
 *   file content can make a freshly created temp file appear 180 days old, so
 *   the positive case can never fire in this harness.
 */
export const cases: RuleCase[] = [
  {
    ruleId: "IR_PLAYBOOK_INCOMPLETE",
    check: "playbook",
    positive: {
      file: "security/playbooks/web-compromise.md",
      content: `# Web Compromise Incident Response Playbook

## Detection
Detection criteria: monitor WAF and CDN logs for indicators of compromise such as
unexpected admin logins, defaced pages, or unusual outbound traffic.

## Containment
Isolate the affected host from the network and disable any compromised credentials
immediately to contain the incident.
`
    },
    negative: {
      file: "security/playbooks/web-compromise.md",
      content: `# Web Compromise Incident Response Playbook

## Detection
Detection criteria: monitor WAF and application logs for indicators of compromise
such as unexpected admin logins, defaced pages, or unusual outbound traffic.

## Escalation
The on-call security lead is paged automatically. The incident commander declares
severity and coordinates the response team.

## Containment
Isolate the affected host from the network. Contain the blast radius by revoking
compromised credentials and blocking malicious IPs at the WAF.

## Eradication
Eradicate the root cause: remove any web shells, patch the vulnerable component,
and rebuild the compromised host from a known-good image.

## Recovery
Restore service from clean backups and recover normal traffic routing once
eradication is confirmed.

## Communication
Notification templates are used to inform stakeholders, including customers and
executives, per the communication plan.

## Post-Incident Review
Conduct a post-incident retrospective within 5 business days. Document lessons
learned and update this playbook accordingly.

## Targets
MTTD target: 15 minutes. MTTR target: 4 hours. Mean time to detect and mean time
to respond are tracked and reported quarterly; response time targets are reviewed
after each incident.
`
    },
    note: "Negative adds the six sections the positive omits (escalation, eradication, recovery, communication, post-incident, mttd-mttr) using the rule's own vocabulary, so missingSections is empty rather than just rewording the two sections already present."
  }
];
