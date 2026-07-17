/**
 * Contract for per-rule true-positive / true-negative corpus cases.
 *
 * One `RuleCase` proves two things about a single detection rule: it fires on a
 * realistic vulnerable sample (positive), and it does NOT fire on a realistic
 * safe sample that exercises the same code shape (negative). The negative must
 * be a genuine safe variant of the positive, not a trivial edit (renamed
 * variable, deleted sink) — a negative that only superficially differs measures
 * nothing about the rule's real false-positive rate.
 */
export type RuleCase = {
  /** The finding id this case targets, e.g. "WEB_OPEN_REDIRECT". */
  ruleId: string;
  /** The CHECKS[].name (src/gate/policy.ts) whose run() should be invoked. */
  check: string;
  /** A file that WOULD trigger ruleId. */
  positive: { file: string; content: string };
  /** A file that exercises the same shape but must NOT trigger ruleId. */
  negative: { file: string; content: string };
  /** Optional: why the negative is a genuine safe variant, not a cosmetic diff. */
  note?: string;
};
