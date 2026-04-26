#!/usr/bin/env bash
# validate-rules.sh — Lint Sigma rule files against the project metadata
# convention documented in `.claude/skills/sigma-hunting/SKILL.md`
# § "Rule conventions". Also runs `chainsaw lint` when available for full
# Sigma-schema validation.
#
# Usage:
#   bash validate-rules.sh [--strict] [PATH ...]
#
#   PATH       File or directory of Sigma .yml rules. Defaults to
#              `.claude/skills/sigma-hunting/rules/local/`.
#   --strict   Treat the recommended (but optional) keys `references`
#              and `tags` as required.
#
# Exit codes:
#   0 — every checked file passed the meta convention and chainsaw lint
#   1 — at least one violation
#   2 — bad invocation

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TARGET="$SCRIPT_DIR/rules/local"

REQUIRED_KEYS=(title id description author date level logsource detection)
STRICT_EXTRA_KEYS=(references tags)
ALLOWED_LEVEL=(informational low medium high critical)
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
DATE_RE='^[0-9]{4}/[0-9]{2}/[0-9]{2}$'

opt_strict=0
targets=()

while (($#)); do
    case "$1" in
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
        done < <(find "$t" -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
    elif [[ ! -e "$t" ]]; then
        echo "validate-rules.sh: not a file or directory: $t" >&2
        exit 2
    fi
done

if [[ ${#files[@]} -eq 0 ]]; then
    echo "validate-rules.sh: no .yml / .yaml files under: ${targets[*]}"
    exit 0
fi

# ----------------------------------------------------------------------
# chainsaw lint helper (optional)
# ----------------------------------------------------------------------
have_chainsaw=0
if command -v chainsaw >/dev/null 2>&1; then
    have_chainsaw=1
fi

chainsaw_lint() {
    local file="$1"
    chainsaw lint --kind sigma "$file" 2>&1
}

# ----------------------------------------------------------------------
# Sigma frontmatter linter
# ----------------------------------------------------------------------
# YAML rule documents are separated by `---`. For each document, capture
# top-level keys (col 1 of the YAML) and check the project convention.
#
# We do NOT depend on a YAML parser — we check just the top-level scalar
# keys that we require. Structured keys (logsource, detection) are
# checked for presence only; chainsaw lint validates their content.
#
# Output one line per finding:
#   FILE | DOC# | RULE_TITLE_OR_ID | LEVEL | KEY | MESSAGE
lint_file() {
    local file="$1"
    awk -v F="$file" \
        -v REQ="$(IFS=,; echo "${REQUIRED_KEYS[*]}")" \
        -v STRICT="$opt_strict" \
        -v STRICT_EXTRA="$(IFS=,; echo "${STRICT_EXTRA_KEYS[*]}")" \
        -v LVL="$(IFS=,; echo "${ALLOWED_LEVEL[*]}")" \
        -v UUID_RE="$UUID_RE" \
        -v DATE_RE="$DATE_RE" '
    BEGIN {
        n = split(REQ, R, /,/);  for (i=1;i<=n;i++) req[R[i]] = 1;
        if (STRICT == "1") {
            n = split(STRICT_EXTRA, S, /,/);
            for (i=1;i<=n;i++) req[S[i]] = 1;
        }
        n = split(LVL, L, /,/);  for (i=1;i<=n;i++) lvl_allow[L[i]] = 1;
        doc = 1;
    }

    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s; }
    function strip_quotes(s) { gsub(/^["'\''`]|["'\''`]$/, "", s); return s; }
    function emit(level, key, msg) {
        ident = (title != "" ? title : (id != "" ? id : "doc#" doc));
        printf("%s | %d | %s | %s | %s | %s\n", F, doc, ident, level, key, msg);
    }
    function close_doc() {
        for (k in req) if (!(k in seen)) emit("ERROR", k, "missing required key");

        if ("date" in seen) {
            v = strip_quotes(seen["date"]);
            if (v !~ DATE_RE) emit("ERROR", "date", "must be YYYY/MM/DD: " seen["date"]);
        }
        if ("level" in seen) {
            v = strip_quotes(seen["level"]);
            if (!(v in lvl_allow)) emit("ERROR", "level", "must be one of {" LVL "}: " seen["level"]);
        }
        if ("id" in seen) {
            v = strip_quotes(seen["id"]);
            if (v !~ UUID_RE) emit("ERROR", "id", "must be a UUID: " seen["id"]);
        }
        delete seen; title=""; id="";
        doc++;
    }

    # Document separator
    /^---[[:space:]]*$/ {
        if (length(seen) > 0 || title != "" || id != "") close_doc();
        next;
    }

    # Top-level scalar key (no leading whitespace, contains a colon).
    # We accept `key: value` and `key:` (block-form value follows).
    /^[A-Za-z_][A-Za-z0-9_]*:/ {
        line = $0;
        sub(/[[:space:]]*#.*$/, "", line);
        cidx = index(line, ":");
        key = trim(substr(line, 1, cidx - 1));
        val = trim(substr(line, cidx + 1));
        seen[key] = val;
        if (key == "title") title = strip_quotes(val);
        if (key == "id")    id    = strip_quotes(val);
        next;
    }

    END {
        if (length(seen) > 0 || title != "" || id != "") close_doc();
    }
    ' "$file"
}

# ----------------------------------------------------------------------
# Drive
# ----------------------------------------------------------------------
err_count=0
warn_count=0
checked=0

printf "validate-rules.sh — checking %d sigma rule file(s)\n" "${#files[@]}"
printf "  required keys     : %s\n" "${REQUIRED_KEYS[*]}"
[[ "$opt_strict" -eq 1 ]] && printf "  strict extras     : %s\n" "${STRICT_EXTRA_KEYS[*]}"
printf "  allowed levels    : %s\n" "${ALLOWED_LEVEL[*]}"
if [[ "$have_chainsaw" -eq 1 ]]; then
    printf "  chainsaw lint     : enabled\n"
else
    printf "  chainsaw lint     : SKIPPED (chainsaw not on PATH)\n"
fi
printf "\n"

for f in "${files[@]}"; do
    checked=$((checked+1))

    # 1. chainsaw lint (when available)
    if [[ "$have_chainsaw" -eq 1 ]]; then
        if ! out="$(chainsaw_lint "$f" 2>&1)"; then
            printf "[ERROR] chainsaw lint failed: %s\n%s\n" "$f" "$out"
            err_count=$((err_count+1))
            continue
        fi
    fi

    # 2. project meta-convention
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        IFS='|' read -r f_path f_doc f_id f_level f_key f_msg <<<"$line"
        f_level="$(echo "$f_level" | tr -d ' ')"
        if [[ "$f_level" == "ERROR" ]]; then
            err_count=$((err_count+1))
        else
            warn_count=$((warn_count+1))
        fi
        printf "[%s] %s doc=%s rule=%s key=%s — %s\n" \
            "$f_level" \
            "$(echo "$f_path" | xargs)" \
            "$(echo "$f_doc" | xargs)" \
            "$(echo "$f_id" | xargs)" \
            "$(echo "$f_key" | xargs)" \
            "$(echo "$f_msg" | xargs)"
    done < <(lint_file "$f")
done

printf "\nvalidate-rules.sh — %d files checked, %d error(s), %d warning(s)\n" \
    "$checked" "$err_count" "$warn_count"

[[ "$err_count" -gt 0 ]] && exit 1
exit 0
