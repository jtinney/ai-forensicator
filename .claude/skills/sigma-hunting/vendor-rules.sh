#!/usr/bin/env bash
# vendor-rules.sh — Pull reputable third-party Sigma + Chainsaw rule sets
# into `.claude/skills/sigma-hunting/rules/vendor/<source>/` and copy
# Chainsaw mapping files into `.claude/skills/sigma-hunting/mappings/`.
#
# This script REQUIRES outbound network access. It is intended to run on a
# connected workstation; transfer the resulting `rules/vendor/` and
# `mappings/` directories to isolated SIFT instances out-of-band.
#
# Usage:
#   bash vendor-rules.sh [--with hayabusa] [--source <name>]
#                        [--verify-only] [--clean] [--list]
#
# Defaults (always pulled unless --source is specified):
#   sigmahq          — SigmaHQ/sigma core, emerging-threats, threat-hunting (DRL 1.1)
#   chainsaw         — WithSecureLabs/chainsaw rules + mapping files (MIT)
#
# Opt-in via --with:
#   hayabusa         — Yamato-Security/hayabusa-rules (DRL 1.1)
#
# Pinning: edit the version table at the top of this file to bump versions.
#
# License compliance is the OPERATOR's responsibility. The manifest records
# what each upstream declares; redistribution rules vary. By default
# `rules/vendor/` is excluded from git.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/rules/vendor"
MAPPINGS_DIR="$SCRIPT_DIR/mappings"
ARCHIVE_DIR="$VENDOR_DIR/.archives"
MANIFEST="$VENDOR_DIR/vendor-manifest.json"

# ----------------------------------------------------------------------
# Pinned versions
# ----------------------------------------------------------------------
declare -A SOURCES
SOURCES[sigmahq,kind]="git-archive"
SOURCES[sigmahq,url]="https://github.com/SigmaHQ/sigma"
SOURCES[sigmahq,ref]="r2025-09-15"
SOURCES[sigmahq,license]="DRL-1.1 (Detection Rule License) — preserve attribution"
SOURCES[sigmahq,note]="core rule pack (rules/, rules-emerging-threats/, rules-threat-hunting/)"

SOURCES[chainsaw,kind]="git-archive"
SOURCES[chainsaw,url]="https://github.com/WithSecureLabs/chainsaw"
SOURCES[chainsaw,ref]="v2.13.0"
SOURCES[chainsaw,license]="MIT"
SOURCES[chainsaw,note]="ships richer Chainsaw-format rules + canonical mappings/ files"

SOURCES[hayabusa,kind]="git-archive"
SOURCES[hayabusa,url]="https://github.com/Yamato-Security/hayabusa-rules"
SOURCES[hayabusa,ref]="main"
SOURCES[hayabusa,license]="DRL-1.1"
SOURCES[hayabusa,note]="IR-triage curated Sigma + Hayabusa-specific rules — opt-in"

DEFAULT_SOURCES=(sigmahq chainsaw)
OPTIONAL_SOURCES=(hayabusa)

# ----------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------
opt_verify=0
opt_clean=0
opt_list=0
selected=()
extras=()

while (($#)); do
    case "$1" in
        --with)        extras+=("$2"); shift 2 ;;
        --source)      selected+=("$2"); shift 2 ;;
        --verify-only) opt_verify=1; shift ;;
        --clean)       opt_clean=1; shift ;;
        --list)        opt_list=1; shift ;;
        -h|--help)
            sed -n '2,/^set -u/p' "$0" | sed 's/^# \?//; /^set -u/d'
            exit 0
            ;;
        *) echo "vendor-rules.sh: unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ "$opt_list" -eq 1 ]]; then
    printf "Available sources:\n"
    for s in "${DEFAULT_SOURCES[@]}" "${OPTIONAL_SOURCES[@]}"; do
        printf "  %-12s ref=%-12s license=%s\n" \
            "$s" "${SOURCES[$s,ref]}" "${SOURCES[$s,license]}"
    done
    exit 0
fi

if [[ "${#selected[@]}" -eq 0 ]]; then
    selected=("${DEFAULT_SOURCES[@]}")
fi
for e in "${extras[@]}"; do
    selected+=("$e")
done

for s in "${selected[@]}"; do
    if [[ -z "${SOURCES[$s,kind]:-}" ]]; then
        echo "vendor-rules.sh: unknown source: $s (try --list)" >&2
        exit 2
    fi
done

mkdir -p "$VENDOR_DIR" "$ARCHIVE_DIR" "$MAPPINGS_DIR"

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

require_net_tool() {
    if ! have curl && ! have wget; then
        echo "vendor-rules.sh: need either curl or wget on PATH" >&2
        exit 2
    fi
}

fetch() {
    local url="$1" out="$2"
    if have curl; then
        curl --fail --location --show-error --silent --output "$out" "$url"
    else
        wget --quiet --output-document="$out" "$url"
    fi
}

sha256_of() { sha256sum "$1" | awk '{print $1}'; }
utc_now() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }

manifest_entries=""
manifest_add() {
    local source="$1" url="$2" ref="$3" sha="$4" license="$5" note="$6" path="$7" pulled_at="$8"
    local entry
    entry=$(printf '  {\n    "source": "%s",\n    "url": "%s",\n    "ref": "%s",\n    "sha256": "%s",\n    "license": "%s",\n    "note": "%s",\n    "path": "%s",\n    "pulled_at": "%s"\n  }' \
        "$source" "$url" "$ref" "$sha" "$license" "$note" "$path" "$pulled_at")
    if [[ -z "$manifest_entries" ]]; then
        manifest_entries="$entry"
    else
        manifest_entries="${manifest_entries},
${entry}"
    fi
}

manifest_write() {
    {
        printf '{\n  "schema": "sigma-vendor-manifest/v1",\n'
        printf '  "generated_at": "%s",\n' "$(utc_now)"
        printf '  "entries": [\n'
        printf '%s\n' "$manifest_entries"
        printf '  ]\n}\n'
    } > "$MANIFEST"
}

# ----------------------------------------------------------------------
# Verify-only mode
# ----------------------------------------------------------------------
if [[ "$opt_verify" -eq 1 ]]; then
    if [[ ! -f "$MANIFEST" ]]; then
        echo "vendor-rules.sh: no manifest at $MANIFEST — run a full pull first" >&2
        exit 1
    fi
    echo "vendor-rules.sh: verifying archives against $MANIFEST"
    drift=0
    while IFS=$'\t' read -r src path expected; do
        [[ -z "$path" ]] && continue
        [[ ! -f "$path" ]] && { echo "  MISSING $src — $path"; drift=1; continue; }
        actual="$(sha256_of "$path")"
        if [[ "$actual" != "$expected" ]]; then
            echo "  DRIFT   $src — expected $expected, got $actual"
            drift=1
        else
            echo "  OK      $src — $path"
        fi
    done < <(awk '
        /"source":/ { gsub(/[",]/,""); src=$2 }
        /"path":/   { gsub(/[",]/,""); path=$2 }
        /"sha256":/ { gsub(/[",]/,""); sha=$2; print src"\t"path"\t"sha }
    ' "$MANIFEST")
    [[ "$drift" -eq 1 ]] && exit 1
    exit 0
fi

# ----------------------------------------------------------------------
# Clean mode
# ----------------------------------------------------------------------
if [[ "$opt_clean" -eq 1 ]]; then
    echo "vendor-rules.sh: removing $VENDOR_DIR contents (except .gitignore)"
    find "$VENDOR_DIR" -mindepth 1 -maxdepth 1 ! -name '.gitignore' -exec rm -rf {} +
    echo "vendor-rules.sh: removing $MAPPINGS_DIR contents (except .gitkeep)"
    find "$MAPPINGS_DIR" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec rm -rf {} +
    exit 0
fi

# ----------------------------------------------------------------------
# Pull selected sources
# ----------------------------------------------------------------------
require_net_tool

for s in "${selected[@]}"; do
    kind="${SOURCES[$s,kind]}"
    url="${SOURCES[$s,url]}"
    ref="${SOURCES[$s,ref]}"
    license="${SOURCES[$s,license]}"
    note="${SOURCES[$s,note]}"
    target_dir="$VENDOR_DIR/$s"
    archive=""
    pulled_at="$(utc_now)"

    echo "vendor-rules.sh: pulling $s @ $ref"
    rm -rf "$target_dir"
    mkdir -p "$target_dir"

    case "$kind" in
        git-archive)
            archive="$ARCHIVE_DIR/${s}-${ref}.tar.gz"
            fetch "${url}/archive/${ref}.tar.gz" "$archive"
            tar -xzf "$archive" -C "$target_dir" --strip-components=1
            ;;
        *)
            echo "vendor-rules.sh: unknown kind for $s: $kind" >&2
            exit 2
            ;;
    esac

    sha="$(sha256_of "$archive")"
    rel_archive="${archive#${SCRIPT_DIR}/}"
    manifest_add "$s" "$url" "$ref" "$sha" "$license" "$note" "$rel_archive" "$pulled_at"

    rule_count=$(find "$target_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) | wc -l)
    echo "  $s: extracted $rule_count rule files"

    # If chainsaw repo, copy mapping files into mappings/
    if [[ "$s" == "chainsaw" && -d "$target_dir/mappings" ]]; then
        cp -v "$target_dir"/mappings/*.yml "$MAPPINGS_DIR/" 2>/dev/null || true
        echo "  $s: copied mapping files into $MAPPINGS_DIR/"
    fi
done

manifest_write
echo "vendor-rules.sh: wrote $MANIFEST"

cat <<EOF

Next steps:
  - Re-run rule enumeration (writes ./analysis/sigma/rules-enumerated.txt):
      bash .claude/skills/sigma-hunting/validate-rules.sh \\
           .claude/skills/sigma-hunting/rules/vendor/sigmahq/rules/

  - Run a hunt:
      chainsaw hunt /path/to/evtx \\
          -s .claude/skills/sigma-hunting/rules/local/ \\
          -s .claude/skills/sigma-hunting/rules/vendor/sigmahq/rules/ \\
          --mapping .claude/skills/sigma-hunting/mappings/sigma-event-logs-all.yml \\
          --csv -o ./analysis/sigma/hits/

The manifest at $MANIFEST records the SHA256 of every archive pulled —
re-run with --verify-only to detect drift.
EOF
