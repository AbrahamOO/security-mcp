#!/usr/bin/env bash
# Blocks `git commit` / `git push` when this change set moves code without moving the
# documentation bound to it in docs/doc-map.json.
#
# Claude Code PreToolUse hook — receives tool input as JSON on stdin.
# Exit 0 = allow, Exit 2 = block, other non-zero = hook error.
#
# This lives in the repo, not in ~/.claude/hooks/, because the doc map is project-specific
# while ciso-pre-commit.sh is global and shared across every project. Wire it as a SECOND
# entry in the existing PreToolUse Bash matcher, after the ciso hook. Both are blocking
# gates, so if either fails the commit does not happen.
#
# Budget: one `git diff --name-only` plus a handful of substring scans. Well under 20s.
#
# Escape hatch: DOC_DRIFT_ALLOW=1 bypasses the block, and says so on stderr. A bypass that
# leaves no evidence is not a bypass, it is a hole.

input=$(cat)
cmd=$(echo "$input" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tool_input', {}).get('command', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")

# Only intercept git commit and git push.
echo "$cmd" | grep -qE '^\s*git\s+(commit|push)' || exit 0

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
CHECKER="$ROOT/scripts/check-doc-drift.mjs"
MAP="$ROOT/docs/doc-map.json"

# Not this project, or the checker is absent. Do not block on something that is not here.
[ -f "$CHECKER" ] || exit 0
[ -f "$MAP" ]     || exit 0

# Scope the change set the same way ciso-pre-commit.sh does: staged for commit, the
# push range for push. If origin/main is unreachable (shallow clone, no remote), the
# checker reports the range as skipped rather than treating it as clean.
if echo "$cmd" | grep -qE '^\s*git\s+push'; then
  SCOPE=(--range "origin/main..HEAD")
else
  SCOPE=(--staged)
fi

output=$(cd "$ROOT" && node "$CHECKER" "${SCOPE[@]}" 2>&1)
status=$?

[ $status -eq 0 ] && exit 0

if [ "${DOC_DRIFT_ALLOW:-}" = "1" ]; then
  echo "doc-drift-gate: BYPASSED via DOC_DRIFT_ALLOW=1. Drift below was not fixed." >&2
  echo "$output" >&2
  exit 0
fi

echo "$output" >&2
echo "" >&2
echo "doc-drift-gate: blocking $(echo "$cmd" | awk '{print $1, $2}')." >&2
echo "Update the doc(s) named above, or set DOC_DRIFT_ALLOW=1 to proceed on the record." >&2
exit 2
