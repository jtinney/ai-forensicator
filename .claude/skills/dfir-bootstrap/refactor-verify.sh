#!/usr/bin/env bash
# refactor-verify.sh — re-runnable conformance checks for the
# 2026-05-02 refactor (worktree purge, working/ migration, DISCIPLINE
# SSoT, XML rewrite, hedge audit, marker bump, ARCHITECTURE.md).
#
# Read-only. Prints PASS / FAIL per gate, exits nonzero on any FAIL.
#
# Usage
#   bash .claude/skills/dfir-bootstrap/refactor-verify.sh
#
# Run from the project root. Walks the full repo; do not run from
# inside a case workspace.

set -u

PROJECT_ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$PROJECT_ROOT" || { echo "FAIL: cannot cd to $PROJECT_ROOT" >&2; exit 2; }

fails=0
emit() { printf '%-70s %s\n' "$1" "$2"; }

# ---- 1. Discipline marker ----
SELF="$(basename "$0")"
markers=$(grep -rn "discipline_v" .claude/ CLAUDE.md ARCHITECTURE.md README.md VALIDATION.md 2>/dev/null \
          | grep -v "$SELF" | grep -c "discipline_v4_loaded" || true)
older_remaining=$(grep -rnE "discipline_v[0-3]_loaded" .claude/ CLAUDE.md ARCHITECTURE.md README.md VALIDATION.md 2>/dev/null \
               | grep -v "$SELF" | wc -l)
if [[ "$markers" -gt 0 && "$older_remaining" -eq 0 ]]; then
    emit "1. discipline marker (v4 only, $markers ref)" "PASS"
else
    emit "1. discipline marker (v4=$markers older=$older_remaining)" "FAIL"
    fails=$((fails+1))
fi

# ---- 2. Audit-log restatement count ----
audit_refs=$(grep -rnE 'audit\.sh|forensic_audit\.log' .claude/ CLAUDE.md 2>/dev/null \
             | grep -v ':\s*#' | wc -l)
if [[ "$audit_refs" -lt 80 ]]; then
    emit "2. audit-log refs ($audit_refs)" "PASS"
else
    emit "2. audit-log refs ($audit_refs > 80)" "WARN"
fi

# ---- 3. Hedge-language audit ----
hedge_hits=$(grep -rnE '(^|[^a-z])(MAY|may|consider|optional|might|could)([^a-z]|$)' \
             .claude/agents/ .claude/skills/ORCHESTRATE.md .claude/skills/TRIAGE.md \
             .claude/skills/dfir-discipline/SKILL.md CLAUDE.md ARCHITECTURE.md 2>/dev/null \
             | grep -vE '#|^Binary|`[^`]*(may|might|could|optional)' \
             | wc -l)
if [[ "$hedge_hits" -le 5 ]]; then
    emit "3. hedge audit (rewritten files, $hedge_hits hits)" "PASS"
else
    emit "3. hedge audit ($hedge_hits)" "FAIL"
    grep -rnE '(^|[^a-z])(MAY|may|consider|optional|might|could)([^a-z]|$)' \
        .claude/agents/ .claude/skills/ORCHESTRATE.md .claude/skills/TRIAGE.md \
        .claude/skills/dfir-discipline/SKILL.md CLAUDE.md ARCHITECTURE.md 2>/dev/null \
        | grep -vE '#|^Binary|`[^`]*(may|might|could|optional)' | head -5 >&2
    fails=$((fails+1))
fi

# ---- 4. analysis/_extracted residue ----
extracted=$(grep -rln "analysis/_extracted" .claude/ CLAUDE.md ARCHITECTURE.md README.md VALIDATION.md cases/ 2>/dev/null \
            | grep -v "$SELF" | wc -l)
if [[ "$extracted" -eq 0 ]]; then
    emit "4. analysis/_extracted residue (0)" "PASS"
else
    emit "4. analysis/_extracted residue ($extracted)" "FAIL"
    fails=$((fails+1))
fi

# ---- 5. Worktree clones ----
wts=$(find .claude/worktrees -maxdepth 1 -type d -name "agent-*" 2>/dev/null | wc -l)
if [[ "$wts" -eq 0 ]]; then
    emit "5. worktree clones (0)" "PASS"
else
    emit "5. worktree clones ($wts)" "FAIL"
    fails=$((fails+1))
fi

# ---- 6. XML structure on rewritten files ----
xml_files=$(grep -l '<role>' \
            .claude/agents/dfir-{triage,surveyor,investigator,correlator,reporter,qa}.md \
            .claude/skills/ORCHESTRATE.md .claude/skills/TRIAGE.md \
            .claude/skills/dfir-discipline/SKILL.md 2>/dev/null | wc -l)
if [[ "$xml_files" -eq 9 ]]; then
    emit "6. XML <role> in 9 rewritten files" "PASS"
else
    emit "6. XML <role> ($xml_files / 9)" "FAIL"
    fails=$((fails+1))
fi

# ---- 7. ARCHITECTURE.md present ----
if [[ -f ARCHITECTURE.md ]]; then
    emit "7. ARCHITECTURE.md present ($(wc -l < ARCHITECTURE.md) lines)" "PASS"
else
    emit "7. ARCHITECTURE.md absent" "FAIL"
    fails=$((fails+1))
fi

# ---- 8. New policy rules in DISCIPLINE.md ----
policies=$(grep -cE '^<rule id="P-(pcap|diskimage|priority|yara|sigma)"' \
           .claude/skills/dfir-discipline/DISCIPLINE.md 2>/dev/null)
if [[ "$policies" -eq 5 ]]; then
    emit "8. DISCIPLINE.md policy rules (5 / 5)" "PASS"
else
    emit "8. DISCIPLINE.md policy rules ($policies / 5)" "FAIL"
    fails=$((fails+1))
fi

# ---- 8b. v4 disk-image residue scan ----
# After the mount-don't-convert refactor, the strings working/e01 and
# conversion-e01 should not appear in any agent prompt, skill file, or
# CLAUDE.md / ARCHITECTURE.md. ewfacquire is still installed (libewf-tools
# bundles it) but should not be invoked from any prompt.
e01_residue=$(grep -rnE 'working/e01|conversion-e01' \
              .claude/agents/ .claude/skills/ CLAUDE.md ARCHITECTURE.md 2>/dev/null \
              | grep -v "$SELF" | wc -l)
if [[ "$e01_residue" -eq 0 ]]; then
    emit "8b. v4 disk-image residue (0 working/e01|conversion-e01 hits)" "PASS"
else
    emit "8b. v4 disk-image residue ($e01_residue hits)" "FAIL"
    grep -rnE 'working/e01|conversion-e01' \
        .claude/agents/ .claude/skills/ CLAUDE.md ARCHITECTURE.md 2>/dev/null \
        | grep -v "$SELF" | head -5 >&2
    fails=$((fails+1))
fi

# ---- 8c. v4 mount helpers present + executable ----
mount_helpers=(
    .claude/skills/dfir-bootstrap/diskimage-plan.sh
    .claude/skills/dfir-bootstrap/diskimage-mount.sh
    .claude/skills/dfir-bootstrap/diskimage-unmount.sh
    .claude/skills/dfir-bootstrap/diskimage-unmount-all.sh
)
helpers_ok=0
for h in "${mount_helpers[@]}"; do
    if [[ -x "$h" ]]; then
        helpers_ok=$((helpers_ok+1))
    fi
done
if [[ "$helpers_ok" -eq "${#mount_helpers[@]}" ]]; then
    emit "8c. v4 mount helpers ($helpers_ok / ${#mount_helpers[@]} executable)" "PASS"
else
    emit "8c. v4 mount helpers ($helpers_ok / ${#mount_helpers[@]} executable)" "FAIL"
    fails=$((fails+1))
fi

# ---- 9. Line-count targets ----
declare -A targets=(
    [CLAUDE.md]=140
    [.claude/skills/ORCHESTRATE.md]=275
    [.claude/skills/TRIAGE.md]=180
    [.claude/agents/dfir-triage.md]=90
    [.claude/agents/dfir-surveyor.md]=110
    [.claude/agents/dfir-investigator.md]=95
    [.claude/agents/dfir-correlator.md]=145
    [.claude/agents/dfir-reporter.md]=110
    [.claude/agents/dfir-qa.md]=315
)
size_ok=0
size_total=0
for f in "${!targets[@]}"; do
    size_total=$((size_total+1))
    actual=$(wc -l < "$f" 2>/dev/null || echo 0)
    target=${targets[$f]}
    delta=$((actual - target))
    abs_delta=${delta#-}
    pct=$((abs_delta * 100 / target))
    if [[ "$pct" -le 15 ]]; then
        size_ok=$((size_ok+1))
    fi
done
if [[ "$size_ok" -eq "$size_total" ]]; then
    emit "9. line counts ($size_ok / $size_total within ±15%)" "PASS"
else
    emit "9. line counts ($size_ok / $size_total within ±15%)" "WARN"
fi

# ---- 10. Reference style ----
# Bare .claude/skills paths in markdown PROSE (outside fenced code blocks)
# would be a violation. Grep with awk to skip code fences.
prose_violations=$(awk '
    /^[[:space:]]*```/ { in_code = !in_code; next }
    !in_code && /\.claude\/skills/ && !/^[[:space:]]*[`@]/ && !/`\.claude/ {
        print FILENAME ":" NR ":" $0
    }
' CLAUDE.md ARCHITECTURE.md .claude/agents/*.md .claude/skills/ORCHESTRATE.md \
  .claude/skills/TRIAGE.md .claude/skills/dfir-discipline/SKILL.md 2>/dev/null \
  | grep -vE '@\.claude/skills|`\.claude/skills' \
  | grep -vE '\$ \.claude|^\s*bash \.claude|/\.claude/skills' \
  | wc -l)
if [[ "$prose_violations" -le 5 ]]; then
    emit "10. reference-style ($prose_violations near-prose hits)" "PASS"
else
    emit "10. reference-style ($prose_violations)" "WARN"
fi

# ---- summary ----
echo ""
if [[ "$fails" -eq 0 ]]; then
    echo "refactor-verify: PASS"
    exit 0
else
    echo "refactor-verify: FAIL ($fails gates failed)"
    exit 1
fi
