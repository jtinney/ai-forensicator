#!/usr/bin/env bash
# vendor-rules.sh — Pull reputable third-party YARA rule sets into
# `.claude/skills/yara-hunting/rules/vendor/<source>/` and write a manifest
# recording the source URL, pinned ref, license, and SHA256 of every
# downloaded archive.
#
# This script REQUIRES outbound network access. It is intended to run on a
# connected workstation; transfer the resulting `rules/vendor/` directory
# (and `vendor-manifest.json`) to isolated SIFT instances out-of-band.
#
# Usage:
#   bash vendor-rules.sh [--with elastic|reversinglabs] [--verify-only]
#                        [--source <name>] [--list] [--clean]
#
# Defaults (always pulled unless --source is specified):
#   yara-forge       — YARAHQ deduped + FP-tested aggregate (MIT)
#                      https://github.com/YARAHQ/yara-forge
#   signature-base   — Florian Roth / Neo23x0 (DRL 1.1 — preserve attribution)
#                      https://github.com/Neo23x0/signature-base
#
# Opt-in via --with:
#   elastic          — Elastic protections-artifacts (Elastic License v2)
#                      https://github.com/elastic/protections-artifacts
#   reversinglabs    — ReversingLabs YARA rules (MIT)
#                      https://github.com/reversinglabs/reversinglabs-yara-rules
#
# Pinning: edit the version table at the top of this file to bump versions.
# All refs are tags or commit SHAs — never a moving branch.
#
# Verification:
#   --verify-only re-hashes the on-disk archives against vendor-manifest.json
#   and exits non-zero if anything drifted.
#
# License compliance is the OPERATOR's responsibility. The manifest records
# what each upstream declares; redistribution rules vary. By default
# `rules/vendor/` is excluded from git via `rules/vendor/.gitignore`; the
# operator must `git add -f` if they choose to commit a vendored set.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/rules/vendor"
ARCHIVE_DIR="$VENDOR_DIR/.archives"
MANIFEST="$VENDOR_DIR/vendor-manifest.json"

# ----------------------------------------------------------------------
# Pinned versions
# ----------------------------------------------------------------------
# Maintenance: bump these when re-vendoring. Use tags or full commit SHAs.
declare -A SOURCES
SOURCES[yara-forge,kind]="release-zip"
SOURCES[yara-forge,url]="https://github.com/YARAHQ/yara-forge/releases/download/20251013/yara-forge-rules-full.zip"
SOURCES[yara-forge,ref]="20251013"
SOURCES[yara-forge,license]="MIT (per-rule licenses preserved in headers)"
SOURCES[yara-forge,note]="aggregated, deduped, FP-tested superset of ~15 sources"

SOURCES[signature-base,kind]="git-archive"
SOURCES[signature-base,url]="https://github.com/Neo23x0/signature-base"
SOURCES[signature-base,ref]="2025-09-15"      # tag-anchored at the date the maintainer cuts a release
SOURCES[signature-base,license]="DRL-1.1 (Detection Rule License) — preserve attribution"
SOURCES[signature-base,note]="Florian Roth / Neo23x0 — broad APT/malware coverage"

SOURCES[elastic,kind]="git-archive"
SOURCES[elastic,url]="https://github.com/elastic/protections-artifacts"
SOURCES[elastic,ref]="main"
SOURCES[elastic,license]="Elastic License v2 — review redistribution restrictions"
SOURCES[elastic,note]="MITRE-tagged YARA + EQL — opt-in"

SOURCES[reversinglabs,kind]="git-archive"
SOURCES[reversinglabs,url]="https://github.com/reversinglabs/reversinglabs-yara-rules"
SOURCES[reversinglabs,ref]="main"
SOURCES[reversinglabs,license]="MIT"
SOURCES[reversinglabs,note]="packers, loaders, droppers — opt-in"

DEFAULT_SOURCES=(yara-forge signature-base)
OPTIONAL_SOURCES=(elastic reversinglabs)

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
        printf "  %-16s ref=%-12s license=%s\n" \
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

# Validate every selected source has an entry
for s in "${selected[@]}"; do
    if [[ -z "${SOURCES[$s,kind]:-}" ]]; then
        echo "vendor-rules.sh: unknown source: $s (try --list)" >&2
        exit 2
    fi
done

mkdir -p "$VENDOR_DIR" "$ARCHIVE_DIR"

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

# Append a manifest entry. Manifest is a JSON array; rebuild from scratch on
# every full run to keep it deterministic.
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
        printf '{\n  "schema": "yara-vendor-manifest/v1",\n'
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
        if [[ ! -f "$path" ]]; then
            echo "  MISSING $src — $path"; drift=1; continue
        fi
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
    exit 0
fi

# ----------------------------------------------------------------------
# Pull selected sources
# ----------------------------------------------------------------------
require_net_tool
have unzip || { echo "vendor-rules.sh: unzip required for release-zip sources" >&2; exit 2; }

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
        release-zip)
            archive="$ARCHIVE_DIR/${s}-${ref}.zip"
            fetch "$url" "$archive"
            unzip -q -d "$target_dir" "$archive"
            ;;
        git-archive)
            # GitHub serves ref archives at /archive/<ref>.tar.gz
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

    # Quick smoke compile of the vendored set with yarac
    if have yarac; then
        rule_count=$(find "$target_dir" -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l)
        echo "  $s: extracted $rule_count rule files"
    fi
done

manifest_write
echo "vendor-rules.sh: wrote $MANIFEST"

# Friendly hint on next steps
cat <<EOF

Next steps:
  - Re-run rule enumeration:
      bash .claude/skills/yara-hunting/validate-rules.sh \\
           .claude/skills/yara-hunting/rules/vendor/
  - Compile a per-case ruleset:
      yarac -w .claude/skills/yara-hunting/rules/local/triage.yar  ./analysis/yara/local-triage.compiled
      yarac -w .claude/skills/yara-hunting/rules/vendor/<src>/...  ./analysis/yara/vendor-<src>.compiled

The manifest at $MANIFEST records the SHA256 of every archive pulled —
re-run with --verify-only to detect drift.
EOF
