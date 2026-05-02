#!/usr/bin/env bash
# validate-rules.sh — Lint YARA rule files against the project metadata
# convention documented in `.claude/skills/yara-hunting/SKILL.md`
# § "Rule conventions". Also runs `yarac` for full syntax + semantic
# validation.
#
# Usage:
#   bash validate-rules.sh [--fp-test] [--strict] [PATH ...]
#
#   PATH       File or directory of YARA rules. Defaults to
#              `/opt/yara-rules/` (the project's canonical rule corpus
#              per DISCIPLINE.md Rule P-yara).
#   --fp-test  After meta-lint passes, scan PATH against /usr/bin (and
#              /Windows/System32 if mounted) and flag any rule that fires
#              on more than $FP_THRESHOLD distinct files.
#   --strict   Treat the recommended (but optional) keys `reference`
#              and `mitre` as required.
#
# Exit codes:
#   0 — every checked file passed the meta convention and compiled with yarac
#   1 — at least one violation
#   2 — bad invocation (missing yarac, unreadable input)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TARGET="/opt/yara-rules"
FP_THRESHOLD="${FP_THRESHOLD:-5}"
GOODWARE_DIRS=(/usr/bin /usr/sbin /usr/lib/x86_64-linux-gnu)

REQUIRED_META=(author date description severity scope)
STRICT_EXTRA_META=(reference mitre)
ALLOWED_SEVERITY=(informational low medium high critical)
ALLOWED_SCOPE=(file memory both pcap_payload unallocated)

opt_fp=0
opt_strict=0
targets=()

while (($#)); do
    case "$1" in
        --fp-test) opt_fp=1; shift ;;
        --strict)  opt_strict=1; shift ;;
        -h|--help)
            sed -n '2,/^set -u/p' "$0" | sed 's/^# \?//; /^set -u/d'
            exit 0
            ;;
        --) shift; while (($#)); do targets+=("$1"); shift; done ;;
        -*) echo "validate-rules.sh: unknown flag: $1" >&2; exit 2 ;;
        *)  targets+=("$1"); shift ;;
    esac
done

[[ ${#targets[@]} -eq 0 ]] && targets=("$DEFAULT_TARGET")

if ! command -v yarac >/dev/null 2>&1; then
    echo "validate-rules.sh: yarac not found on PATH — install yara to run validation" >&2
    exit 2
fi

# ----------------------------------------------------------------------
# Collect target rule files
# ----------------------------------------------------------------------
files=()
for t in "${targets[@]}"; do
    if [[ -f "$t" ]]; then
        files+=("$t")
    elif [[ -d "$t" ]]; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find "$t" -type f \( -name '*.yar' -o -name '*.yara' \) | sort)
    else
        echo "validate-rules.sh: not a file or directory: $t" >&2
        exit 2
    fi
done

if [[ ${#files[@]} -eq 0 ]]; then
    echo "validate-rules.sh: no .yar / .yara files under: ${targets[*]}" >&2
    exit 2
fi

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
in_list() {
    local needle="$1"; shift
    for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
    return 1
}

# ----------------------------------------------------------------------
# Meta-convention linter (per rule)
# ----------------------------------------------------------------------
# awk emits one line per finding:
#   FILE | LINE | RULE | LEVEL | KEY | MESSAGE
# LEVEL is ERROR (counts toward exit 1) or WARN (informational).
lint_file_meta() {
    local file="$1"
    awk -v F="$file" \
        -v REQ="$(IFS=,; echo "${REQUIRED_META[*]}")" \
        -v STRICT_EXTRA="$(IFS=,; echo "${STRICT_EXTRA_META[*]}")" \
        -v STRICT="$opt_strict" \
        -v SEV_OK="$(IFS=,; echo "${ALLOWED_SEVERITY[*]}")" \
        -v SCOPE_OK="$(IFS=,; echo "${ALLOWED_SCOPE[*]}")" '
    BEGIN {
        n = split(REQ, R, /,/);
        for (i=1;i<=n;i++) req[R[i]] = 1;
        if (STRICT == "1") {
            n = split(STRICT_EXTRA, S, /,/);
            for (i=1;i<=n;i++) req[S[i]] = 1;
        }
        n = split(SEV_OK, SV, /,/);
        for (i=1;i<=n;i++) sev_allow[SV[i]] = 1;
        n = split(SCOPE_OK, SC, /,/);
        for (i=1;i<=n;i++) scope_allow[SC[i]] = 1;
        rule_name = ""; rule_line = 0; in_meta = 0; brace_depth = 0;
    }

    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s; }

    function emit(level, key, msg) {
        printf("%s | %d | %s | %s | %s | %s\n", F, rule_line, rule_name, level, key, msg);
    }

    function close_rule() {
        if (rule_name == "") return;
        for (k in req) {
            if (!(k in seen_meta)) emit("ERROR", k, "missing required meta key");
        }
        # Non-required validations
        if ("date" in seen_meta) {
            if (seen_meta["date"] !~ /^"?[0-9]{4}-[0-9]{2}-[0-9]{2}"?$/)
                emit("ERROR", "date", "must be YYYY-MM-DD: " seen_meta["date"]);
        }
        if ("severity" in seen_meta) {
            v = seen_meta["severity"]; gsub(/^"|"$/, "", v);
            if (!(v in sev_allow)) emit("ERROR", "severity",
                "must be one of {" SEV_OK "}: " seen_meta["severity"]);
        }
        if ("scope" in seen_meta) {
            v = seen_meta["scope"]; gsub(/^"|"$/, "", v);
            if (!(v in scope_allow)) emit("ERROR", "scope",
                "must be one of {" SCOPE_OK "}: " seen_meta["scope"]);
        }
        rule_name = ""; rule_line = 0; in_meta = 0;
        delete seen_meta;
    }

    # Track rule starts. YARA rule header:
    #   rule Name [: tag1 tag2] [{| at column 0 — rare]
    /^[[:space:]]*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
        if (rule_name != "") close_rule();
        line = $0;
        sub(/^[[:space:]]*rule[[:space:]]+/, "", line);
        match(line, /^[A-Za-z_][A-Za-z0-9_]*/);
        rule_name = substr(line, RSTART, RLENGTH);
        rule_line = NR;
        in_meta = 0;
        next;
    }

    # Section markers inside a rule
    rule_name != "" && /^[[:space:]]*meta:[[:space:]]*$/    { in_meta = 1; next }
    rule_name != "" && /^[[:space:]]*strings:[[:space:]]*$/ { in_meta = 0; next }
    rule_name != "" && /^[[:space:]]*condition:[[:space:]]*$/ { in_meta = 0; next }

    # Detect end of rule by a closing brace at the start of a line.
    # YARA rule bodies always close with `}` flush-left or with leading whitespace
    # that has been trimmed; we use "first character non-space is }".
    rule_name != "" && /^[[:space:]]*\}[[:space:]]*$/ {
        close_rule();
        next;
    }

    # Capture meta key/value pairs. Format: `   key = value`
    rule_name != "" && in_meta == 1 && /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/ {
        line = $0;
        sub(/[[:space:]]*\/\/.*$/, "", line);              # strip trailing comment
        eq = index(line, "=");
        key = trim(substr(line, 1, eq-1));
        val = trim(substr(line, eq+1));
        seen_meta[key] = val;
        next;
    }

    END {
        if (rule_name != "") close_rule();
    }
    ' "$file"
}

# ----------------------------------------------------------------------
# yarac compile check (per file)
# ----------------------------------------------------------------------
yarac_check() {
    local file="$1"
    local tmp; tmp="$(mktemp)"
    if yarac "$file" "$tmp" 2>&1; then
        rm -f "$tmp"
        return 0
    else
        rm -f "$tmp"
        return 1
    fi
}

# ----------------------------------------------------------------------
# False-positive sweep against goodware
# ----------------------------------------------------------------------
fp_sweep() {
    local file="$1"
    local good_targets=()
    for d in "${GOODWARE_DIRS[@]}"; do
        [[ -d "$d" ]] && good_targets+=("$d")
    done
    if [[ -d /mnt/windows_mount/Windows/System32 ]]; then
        good_targets+=(/mnt/windows_mount/Windows/System32)
    fi
    [[ ${#good_targets[@]} -eq 0 ]] && return 0

    # yara emits one line per (rule, file) match: `RuleName /path/to/file`
    # group by rule, count distinct files
    local raw
    raw="$(yara -r -f "$file" "${good_targets[@]}" 2>/dev/null)"
    [[ -z "$raw" ]] && return 0

    awk -v F="$file" -v T="$FP_THRESHOLD" '
        { rule = $1; file_hit[rule, $2] = 1; rules[rule]=1 }
        END {
            for (r in rules) {
                c = 0; for (k in file_hit) if (k ~ "^"r SUBSEP) c++;
                if (c > T) printf("%s | 0 | %s | WARN | fp_test | hits %d distinct goodware files (>%d)\n", F, r, c, T);
            }
        }
    ' <<<"$raw"
}

# ----------------------------------------------------------------------
# Drive
# ----------------------------------------------------------------------
err_count=0
warn_count=0
checked=0

printf "validate-rules.sh — checking %d rule file(s)\n" "${#files[@]}"
printf "  required meta keys : %s\n" "${REQUIRED_META[*]}"
[[ "$opt_strict" -eq 1 ]] && printf "  strict extras      : %s\n" "${STRICT_EXTRA_META[*]}"
printf "  allowed severities : %s\n" "${ALLOWED_SEVERITY[*]}"
printf "  allowed scopes     : %s\n" "${ALLOWED_SCOPE[*]}"
[[ "$opt_fp" -eq 1 ]] && printf "  fp-test goodware   : %s\n" "${GOODWARE_DIRS[*]}"
printf "\n"

for f in "${files[@]}"; do
    checked=$((checked+1))

    # 1. yarac compile
    if ! out="$(yarac_check "$f" 2>&1)"; then
        printf "[ERROR] yarac compile failed: %s\n%s\n" "$f" "$out"
        err_count=$((err_count+1))
        continue
    fi

    # 2. meta-convention lint
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # FILE | LINE | RULE | LEVEL | KEY | MESSAGE
        IFS='|' read -r f_path f_line f_rule f_level f_key f_msg <<<"$line"
        f_level="$(echo "$f_level" | tr -d ' ')"
        if [[ "$f_level" == "ERROR" ]]; then
            err_count=$((err_count+1))
        else
            warn_count=$((warn_count+1))
        fi
        printf "[%s] %s:%s rule=%s key=%s — %s\n" \
            "$f_level" "$(echo "$f_path" | xargs)" "$(echo "$f_line" | xargs)" \
            "$(echo "$f_rule" | xargs)" "$(echo "$f_key" | xargs)" "$(echo "$f_msg" | xargs)"
    done < <(lint_file_meta "$f")

    # 3. optional FP sweep
    if [[ "$opt_fp" -eq 1 ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            IFS='|' read -r f_path f_line f_rule f_level f_key f_msg <<<"$line"
            warn_count=$((warn_count+1))
            printf "[WARN ] %s rule=%s key=%s — %s\n" \
                "$(echo "$f_path" | xargs)" "$(echo "$f_rule" | xargs)" \
                "$(echo "$f_key" | xargs)" "$(echo "$f_msg" | xargs)"
        done < <(fp_sweep "$f")
    fi
done

printf "\nvalidate-rules.sh — %d files checked, %d error(s), %d warning(s)\n" \
    "$checked" "$err_count" "$warn_count"

[[ "$err_count" -gt 0 ]] && exit 1
exit 0
