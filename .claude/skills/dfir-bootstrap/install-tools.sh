#!/usr/bin/env bash
# =============================================================================
# install-tools.sh — DFIR tool bootstrapper for SANS SIFT workstations
#
# Modes:
#   sudo bash install-tools.sh          # install only missing components
#   bash install-tools.sh --check       # inventory missing components only
#
# Exit codes:
#   0 = success / fully installed
#   2 = --check found missing components
#   1 = execution error
#
# Requirements for install mode:
#   - root or passwordless sudo
#   - outbound HTTPS
#   - ~3 GB free in /opt for optional components
# =============================================================================

set -uo pipefail

MODE="install"
case "${1:-}" in
    "" ) ;;
    --check ) MODE="check" ;;
    -h|--help )
        cat <<'EOF'
Usage:
  sudo bash install-tools.sh          Install missing DFIR tooling
  bash install-tools.sh --check       Show missing tooling without changes
EOF
        exit 0
        ;;
    * )
        echo "Unknown argument: ${1}"
        echo "Try: bash $0 --help"
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFLIGHT_SCRIPT="${SCRIPT_DIR}/preflight.sh"
LOGFILE="/tmp/dfir-install-$(date -u +%Y%m%d_%H%M%S).log"

EZ_DEST="/opt/zimmermantools"
# Volatility 3 version: defaults to whatever the latest GitHub release tag
# resolves to at install time. If that lookup fails (no network / API
# rate-limit), we fall back to a known-existing pin. Override with
# VOL3_VER=2.27.0 in the environment to force a specific version.
VOL3_VER_FALLBACK="2.27.0"
VOL3_VER=""
VOL3_DIR=""
BASELINER_DIR="/opt/memory-baseliner"
UBUNTU_VER=$(. /etc/os-release 2>/dev/null && echo "$VERSION_ID" || echo "22.04")

APT_UPDATED=0
CHECK_MISSING=0
ERRORS=0

# Required by workflow/docs.
# NOTE: BASE_APT is installed AFTER the GIFT PPA is added (see main()), so any
# package that has a newer GIFT-built version (libewf, libewf-tools,
# bulk-extractor, …) resolves to the GIFT version. Critical detail: the stock
# Ubuntu package "ewf-tools" depends on the OLD libewf2 and conflicts with
# the modern "libewf" that SIFT/GIFT installs — apt will REMOVE ewf-tools
# whenever libewf gets pulled in. The correct GIFT replacement is
# "libewf-tools" (different package name; same ewfinfo/ewfverify/ewfmount
# binaries; depends on the modern libewf).
BASE_APT_REQUIRED=(
    software-properties-common
    sleuthkit
    libewf            # modern libewf shared lib (used by sleuthkit, plaso, etc.)
    libewf-tools      # ewfinfo / ewfverify / ewfmount / ewfacquire / ewfexport
    qemu-utils        # qemu-nbd + qemu-img — disk-image read-only mount adapter (DISCIPLINE §P-diskimage)
    fuse              # ewfmount FUSE backend
    testdisk
    hashdeep
    yara
    python3-pip
    binutils
    git
    curl
    wget
    unzip
)
# Optional: nice to have but the workflow does not require them.
# Do NOT add the stock "ewf-tools" here — it conflicts with libewf and apt
# will remove it again the moment libewf is touched. Use libewf-tools (above).
BASE_APT_OPTIONAL=(bulk-extractor wine64)
# Plaso required = packages that ARE in jammy / GIFT.
# python3-regipy and python3-pyewf are NOT in any apt repo we can reach on
# Ubuntu 22.04 — they go through pip below.
PLASO_APT_REQUIRED=(python3-plaso plaso-tools python3-pytsk3 python3-evtx)
PLASO_APT_OPTIONAL=()
PIP_REQUIRED=(yara-python impacket construct analyzeMFT LnkParse3 regipy)

# Network-forensic apt packages.
# - tshark pulls in wireshark-common, which provides capinfos / mergecap / editcap.
# - Zeek is installed from the upstream openSUSE Build Service binary
#   repository per https://docs.zeek.org/en/current/install.html — handled by
#   install_zeek_obs() / ensure_zeek_obs_repo() further down. The jammy/universe
#   `zeek` package is too old (5.x line) for the current network-forensics
#   workflows and ships without `zkg` and the Spicy toolchain. The OBS package
#   installs a complete environment under /opt/zeek; we pin to ${ZEEK_OBS_PKG}
#   (default zeek-7.0, the LTS line called out in the upstream docs) and
#   symlink /opt/zeek/bin/{zeek,zeek-cut,zeekctl,zkg} into /usr/local/bin so
#   non-interactive subagent shells find the binaries.
# - suricata + suricata-update; ET Open rules pulled lazily on first run.
# - tcpdump / tcpflow / ngrep / nfdump / jq are small, broadly useful CLI helpers.
NETWORK_APT_REQUIRED=(
    tshark
    tcpdump
    tcpflow
    ngrep
    suricata
    suricata-update
    jq
)
NETWORK_APT_OPTIONAL=(nfdump)

# Zeek upstream OBS repo (https://docs.zeek.org/en/current/install.html).
# Override at install time:
#   ZEEK_OBS_PKG=zeek-8.0 sudo bash install-tools.sh   # pin to a different version
#   ZEEK_OBS_PKG=zeek      sudo bash install-tools.sh   # follow feature track
#   ZEEK_OBS_DISTRO=xUbuntu_24.04 ...                   # different host release
# UBUNTU_VER is "22.04" / "24.04" etc. — OBS uses the xUbuntu_<VER> form.
ZEEK_OBS_PKG="${ZEEK_OBS_PKG:-zeek-7.0}"
ZEEK_OBS_DISTRO="${ZEEK_OBS_DISTRO:-xUbuntu_${UBUNTU_VER}}"
ZEEK_OBS_LIST="/etc/apt/sources.list.d/security:zeek.list"
ZEEK_OBS_KEYRING="/etc/apt/trusted.gpg.d/security_zeek.gpg"
ZEEK_PREFIX="/opt/zeek"
ZEEK_BIN_LINKS=(zeek zeek-cut zeekctl zkg)
# scapy + dpkt are optional Python helpers — the stdlib parsers in
# .claude/skills/network-forensics/parsers/ work without either.
NETWORK_PIP_OPTIONAL=(scapy dpkt)
# No pip-optional packages right now.
# Note on pyewf: the original script had `pyewf` in PIP_OPTIONAL, but there is
# no pip package by that name (PyPI returns "no matching distribution"). The
# libyal/libewf Python bindings are shipped via apt on some distros
# (python3-libewf) but NOT on Ubuntu 22.04/jammy. We don't need them anyway —
# Sleuth Kit (fls/icat/mmls) reads .E01 images directly via the libewf2
# shared library already installed by BASE_APT_REQUIRED.
PIP_OPTIONAL=()

# EZ Tools — canonical SANS distribution channel:
#   https://download.ericzimmermanstools.com/net9/<TOOL>.zip
# Channels Eric currently publishes:
#   net9 — current build target; covers every CLI tool we care about
#   net4 — .NET Framework 4 (Windows-only; needs Wine on Linux — we don't use)
# (There is NO net6 channel for the modern tool set — confirmed against
# Eric's current download index. Don't attempt net6 fallback.)
EZ_DOWNLOAD_BASE="https://download.ericzimmermanstools.com/net9"
# Tools whose .zip extracts a single .dll directly into EZ_DEST.
# Format: <ToolName>  →  download URL is "${EZ_DOWNLOAD_BASE}/<ToolName>.zip"
EZ_ROOT_TOOLS=(
    PECmd                   # Prefetch
    RBCmd                   # Recycle Bin $I parser
    MFTECmd                 # $MFT, $J, $Boot, $SDS, $I30, $LogFile
    AppCompatCacheParser    # Shimcache
    AmcacheParser           # Amcache.hve
    LECmd                   # LNK files
    JLECmd                  # Jump lists
    SBECmd                  # Shellbags (CLI)
    SrumECmd                # SRUM database
    SumECmd                 # SUM / Remote Desktop User Access Logs
    bstrings                # Binary strings + regex
    WxTCmd                  # Windows 10 ActivitiesCache.db
    RecentFileCacheParser   # RecentFileCache.bcf
    RLA                     # Registry transaction log replay (zip → rla.dll, lowercase)
)
# Tools whose .zip extracts a subdirectory containing the .dll plus support
# files (Maps/, BatchExamples/, plugins). Format: <ZipName>|<SubdirName>|<DllName>
# ZipName = basename of the .zip on download.ericzimmermanstools.com (some
# differ from the binary name — e.g. EvtxECmd.zip extracts to EvtxeCmd/).
EZ_SUBDIR_TOOLS=(
    "EvtxECmd|EvtxeCmd|EvtxECmd"
    "RECmd|RECmd|RECmd"
    "SQLECmd|SQLECmd|SQLECmd"
)

# Sigma / EVTX hunting tooling — Chainsaw, Hayabusa, evtx_dump.
# All three are referenced by the sigma-hunting skill and the preflight, but
# none ship in any apt repo we can reach on Ubuntu 22.04 — Chainsaw and
# Hayabusa are GitHub-released static Rust binaries, and the canonical
# evtx_dump (omerbenamram/evtx) is also a static Rust binary distributed via
# GitHub. We try apt first for evtx_dump in case a future Ubuntu picks up an
# `evtx-tools` package, then fall back to the GitHub release.
#
# Pattern strings are passed to gh_download() (which uses `grep -i` on the
# release manifest) — they MUST match exactly one asset for the desired
# platform on the latest release of each repo.
SIGMA_CHAINSAW_REPO="WithSecureLabs/chainsaw"
SIGMA_CHAINSAW_DIR="/opt/chainsaw"
SIGMA_CHAINSAW_LINK="/usr/local/bin/chainsaw"
SIGMA_CHAINSAW_ASSET="x86_64-unknown-linux-gnu.tar.gz"

SIGMA_HAYABUSA_REPO="Yamato-Security/hayabusa"
SIGMA_HAYABUSA_DIR="/opt/hayabusa"
SIGMA_HAYABUSA_LINK="/usr/local/bin/hayabusa"
SIGMA_HAYABUSA_ASSET="all-platforms.zip"

SIGMA_EVTX_REPO="omerbenamram/evtx"
SIGMA_EVTX_LINK="/usr/local/bin/evtx_dump"
SIGMA_EVTX_ASSET="x86_64-unknown-linux-musl"
SIGMA_EVTX_APT="evtx-tools"

# ─── colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_log()   { printf "%s\n" "$*" | tee -a "$LOGFILE"; }
ok()     { printf "${GREEN}  OK${NC}  %s\n" "$*"  | tee -a "$LOGFILE"; }
info()   { printf "${CYAN}INFO${NC}  %s\n" "$*"   | tee -a "$LOGFILE"; }
warn()   { printf "${YELLOW}WARN${NC}  %s\n" "$*" | tee -a "$LOGFILE"; }
fail()   { printf "${RED}FAIL${NC}  %s\n" "$*"    | tee -a "$LOGFILE"; (( ERRORS++ )) || true; }
header() { printf "\n${BOLD}=== %s ===${NC}\n" "$*" | tee -a "$LOGFILE"; }

SUDO=()
if [[ "$MODE" == "install" ]]; then
    if [[ $EUID -eq 0 ]]; then
        SUDO=()
    elif sudo -n true 2>/dev/null; then
        SUDO=(sudo)
    else
        echo "ERROR: install mode needs root or passwordless sudo"
        echo "Run: sudo bash $0"
        exit 1
    fi
fi

# ─── generic helpers ─────────────────────────────────────────────────────────
run_cmd() {
    local desc="$1"; shift
    if "$@" >> "$LOGFILE" 2>&1; then
        ok "$desc"
    else
        local rc=$?
        fail "$desc (exit $rc)"
        return "$rc"
    fi
}

mark_missing() {
    local detail="$1"
    (( CHECK_MISSING++ )) || true
    warn "$detail"
}

collect_missing_pkgs() {
    # collect_missing_pkgs <out_array_name> <pkg...>
    local -n out_ref="$1"; shift
    out_ref=()
    local pkg
    for pkg in "$@"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            out_ref+=("$pkg")
        fi
    done
}

ensure_apt_update() {
    if [[ $APT_UPDATED -eq 1 ]]; then
        return 0
    fi
    run_cmd "apt-get update" "${SUDO[@]}" apt-get update -qq || return 1
    APT_UPDATED=1
}

pkg_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

pip_available() {
    command -v pip3 >/dev/null 2>&1 || python3 -m pip --version >/dev/null 2>&1
}

pip_has_package() {
    local pkg="$1"
    python3 -m pip show "$pkg" >/dev/null 2>&1
}

apt_fix_broken() {
    # Recover from a wedged dpkg state before attempting fresh installs.
    # Idempotent — no-op if nothing is broken.
    "${SUDO[@]}" apt-get install -y -qq --fix-broken >> "$LOGFILE" 2>&1 || true
    "${SUDO[@]}" dpkg --configure -a >> "$LOGFILE" 2>&1 || true
}

install_one_pkg() {
    # install_one_pkg <pkg> [optional]
    # Installs a single package. Logs failure but never aborts the caller's
    # loop — that way one held / unavailable / conflicting package cannot
    # cascade-fail an entire group of unrelated packages.
    local pkg="$1"
    local optional="${2:-}"
    if pkg_installed "$pkg"; then
        ok "${pkg}: already installed"
        return 0
    fi
    if "${SUDO[@]}" apt-get install -y -qq "$pkg" >> "$LOGFILE" 2>&1; then
        ok "${pkg}: installed"
        return 0
    fi
    # Surface the actual apt error from the log so the user sees the root cause
    local last_err
    last_err=$("${SUDO[@]}" apt-get install -y "$pkg" 2>&1 \
        | grep -E '^(E:|N:|The following packages have unmet dependencies)' \
        | head -3 | tr '\n' ';' || echo "see $LOGFILE")
    if [[ "$optional" == "optional" ]]; then
        warn "${pkg}: optional install failed (${last_err}); continuing"
    else
        fail "${pkg}: install failed (${last_err})"
    fi
    return 1
}

install_required_packages() {
    # install_required_packages <label> <pkg...>
    local label="$1"; shift
    local missing_pkgs=()
    collect_missing_pkgs missing_pkgs "$@"
    if [[ ${#missing_pkgs[@]} -eq 0 ]]; then
        ok "${label}: already installed"
        return 0
    fi

    ensure_apt_update || return 1
    apt_fix_broken
    local pkg
    for pkg in "${missing_pkgs[@]}"; do
        install_one_pkg "$pkg"
    done
}

install_optional_packages() {
    # install_optional_packages <label> <pkg...>
    local label="$1"; shift
    local missing_pkgs=()
    collect_missing_pkgs missing_pkgs "$@"
    if [[ ${#missing_pkgs[@]} -eq 0 ]]; then
        ok "${label}: already installed"
        return 0
    fi

    ensure_apt_update || return 1
    apt_fix_broken
    local pkg
    for pkg in "${missing_pkgs[@]}"; do
        install_one_pkg "$pkg" optional
    done
}

ensure_gift_ppa() {
    if grep -Rqs "ppa.launchpadcontent.net/gift/stable/ubuntu" \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
        ok "GIFT PPA already configured"
        return 0
    fi
    run_cmd "add GIFT stable PPA" "${SUDO[@]}" add-apt-repository -y ppa:gift/stable || return 1
    APT_UPDATED=0
}

ensure_zeek_obs_repo() {
    # Install the upstream OBS apt source + signing key per
    # https://docs.zeek.org/en/current/install.html. File names match the
    # docs verbatim (security:zeek.list / security_zeek.gpg) so upstream
    # diagnostics apply directly. Idempotent.
    local repo_url="https://download.opensuse.org/repositories/security:/zeek/${ZEEK_OBS_DISTRO}"
    local key_url="https://download.opensuse.org/repositories/security:zeek/${ZEEK_OBS_DISTRO}/Release.key"
    local need_update=0

    if [[ ! -s "$ZEEK_OBS_LIST" ]]; then
        if echo "deb ${repo_url}/ /" \
            | "${SUDO[@]}" tee "$ZEEK_OBS_LIST" >> "$LOGFILE" 2>&1; then
            ok "Zeek OBS apt source: ${ZEEK_OBS_LIST}"
            need_update=1
        else
            fail "write Zeek OBS apt source ${ZEEK_OBS_LIST}"
            return 1
        fi
    else
        ok "Zeek OBS apt source already present: ${ZEEK_OBS_LIST}"
    fi

    if [[ ! -s "$ZEEK_OBS_KEYRING" ]]; then
        local tmp_asc tmp_gpg
        tmp_asc=$(mktemp /tmp/zeek-key-XXXXX.asc)
        tmp_gpg=$(mktemp /tmp/zeek-key-XXXXX.gpg)
        if curl -fsSL --max-time 15 "$key_url" -o "$tmp_asc" >> "$LOGFILE" 2>&1 \
            && gpg --dearmor < "$tmp_asc" > "$tmp_gpg" 2>>"$LOGFILE" \
            && [[ -s "$tmp_gpg" ]] \
            && "${SUDO[@]}" install -m 0644 "$tmp_gpg" "$ZEEK_OBS_KEYRING" >> "$LOGFILE" 2>&1; then
            ok "Zeek OBS signing key: ${ZEEK_OBS_KEYRING}"
            need_update=1
        else
            fail "install Zeek OBS signing key from ${key_url}"
            rm -f "$tmp_asc" "$tmp_gpg"
            return 1
        fi
        rm -f "$tmp_asc" "$tmp_gpg"
    else
        ok "Zeek OBS signing key already present: ${ZEEK_OBS_KEYRING}"
    fi

    if [[ $need_update -eq 1 ]]; then
        APT_UPDATED=0
    fi
    return 0
}

check_network() {
    # check_network <strict|soft>
    local mode="${1:-strict}"
    header "Network connectivity"
    local ok_count=0
    local target code
    for target in \
        "https://github.com" \
        "https://pypi.org" \
        "https://packages.microsoft.com" \
        "https://launchpad.net"; do
        code=$(curl -sL --max-time 6 -o /dev/null -w "%{http_code}" "$target" 2>/dev/null || echo "000")
        if [[ "$code" =~ ^(200|301|302)$ ]]; then
            ok "reachable: $target"
            (( ok_count++ )) || true
        else
            warn "unreachable: $target (HTTP $code)"
        fi
    done

    if [[ $ok_count -eq 0 ]]; then
        if [[ "$mode" == "strict" ]]; then
            fail "No external connectivity — cannot install tools"
            return 1
        fi
        mark_missing "No outbound connectivity from this shell"
    fi
    return 0
}

# ─── check mode ──────────────────────────────────────────────────────────────
check_pkg_group() {
    local label="$1"; shift
    local missing_pkgs=()
    collect_missing_pkgs missing_pkgs "$@"
    if [[ ${#missing_pkgs[@]} -eq 0 ]]; then
        ok "${label}: installed"
    else
        mark_missing "${label}: missing ${missing_pkgs[*]}"
    fi
}

check_cmd_present() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "command present: ${cmd}"
    else
        mark_missing "command missing: ${cmd}"
    fi
}

check_path_present() {
    local path="$1"
    local label="$2"
    if [[ -e "$path" ]]; then
        ok "${label}: ${path}"
    else
        mark_missing "${label}: missing ${path}"
    fi
}

check_pip_pkg() {
    local pkg="$1"
    if ! pip_available; then
        mark_missing "pip unavailable: cannot verify Python package ${pkg}"
        return 0
    fi
    if pip_has_package "$pkg"; then
        ok "pip package present: ${pkg}"
    else
        mark_missing "pip package missing: ${pkg}"
    fi
}

run_check_mode() {
    header "DFIR component check (no changes)"
    info "Log: $LOGFILE"

    # Resolve Volatility 3 install path for the check display
    # (we don't need to actually install — just want the path right)
    if [[ -z "${VOL3_DIR:-}" ]]; then
        VOL3_VER="${VOL3_VER:-$VOL3_VER_FALLBACK}"
        VOL3_DIR="/opt/volatility3-${VOL3_VER}"
    fi

    check_network soft || true

    if sudo -n true >/dev/null 2>&1; then
        ok "sudo non-interactive: available"
    else
        mark_missing "sudo non-interactive unavailable (install mode may be blocked)"
    fi

    header "Apt packages"
    check_pkg_group "Base required apt packages" "${BASE_APT_REQUIRED[@]}"
    check_pkg_group "Base optional apt packages" "${BASE_APT_OPTIONAL[@]}"
    check_pkg_group "dotnet runtime" "dotnet-runtime-9.0"
    check_pkg_group "Plaso/forensic apt packages" "${PLASO_APT_REQUIRED[@]}"
    check_pkg_group "Plaso optional apt packages" "${PLASO_APT_OPTIONAL[@]}"
    check_pkg_group "Network-forensic apt packages (required)" "${NETWORK_APT_REQUIRED[@]}"
    if [[ ${#NETWORK_APT_OPTIONAL[@]} -gt 0 ]]; then
        check_pkg_group "Network-forensic apt packages (optional)" "${NETWORK_APT_OPTIONAL[@]}"
    fi
    check_pkg_group "Zeek (OBS binary, ${ZEEK_OBS_PKG})" "$ZEEK_OBS_PKG"

    header "Commands"
    check_cmd_present fls
    check_cmd_present mactime
    check_cmd_present ewfinfo
    check_cmd_present log2timeline.py
    check_cmd_present yara
    check_cmd_present dotnet
    check_cmd_present python3
    check_cmd_present tshark
    check_cmd_present capinfos
    check_cmd_present tcpdump
    check_cmd_present zeek
    check_cmd_present zeek-cut
    check_cmd_present suricata
    check_cmd_present jq
    check_cmd_present chainsaw
    check_cmd_present hayabusa
    check_cmd_present evtx_dump

    header "Python packages (pip)"
    local pkg
    for pkg in "${PIP_REQUIRED[@]}"; do
        check_pip_pkg "$pkg"
    done

    header "Path-based tools"
    check_path_present "${VOL3_DIR}/vol.py" "Volatility 3"
    check_path_present "${VOL3_DIR}/baseline.py" "Memory Baseliner (baseline.py in vol3 dir)"
    check_path_present "${BASELINER_DIR}" "Memory Baseliner source clone"
    check_path_present "${EZ_DEST}" "EZ Tools root"
    check_path_present "${EZ_DEST}/PECmd.dll" "PECmd.dll"
    check_path_present "${EZ_DEST}/RBCmd.dll" "RBCmd.dll"
    check_path_present "${EZ_DEST}/MFTECmd.dll" "MFTECmd.dll"
    check_path_present "${EZ_DEST}/EvtxeCmd/EvtxECmd.dll" "EvtxECmd.dll"
    check_path_present "${EZ_DEST}/RECmd/RECmd.dll" "RECmd.dll"
    check_path_present "${EZ_DEST}/SQLECmd/SQLECmd.dll" "SQLECmd.dll"
    check_path_present "${ZEEK_PREFIX}/bin/zeek" "Zeek (OBS install prefix)"
    check_path_present "${SIGMA_CHAINSAW_DIR}" "Chainsaw install dir"
    check_path_present "${SIGMA_HAYABUSA_DIR}" "Hayabusa install dir"

    header "Check summary"
    _log "Full log: $LOGFILE"
    if [[ $CHECK_MISSING -eq 0 ]]; then
        printf "${GREEN}${BOLD}All tracked DFIR components are installed.${NC}\n"
        return 0
    fi

    printf "${YELLOW}${BOLD}%d missing check item(s) found.${NC}\n" "$CHECK_MISSING"
    _log "To install missing components:"
    _log "  sudo bash ${SCRIPT_DIR}/install-tools.sh"
    if [[ -x "$PREFLIGHT_SCRIPT" ]]; then
        _log "Then verify:"
        _log "  bash ${PREFLIGHT_SCRIPT} | tee ./analysis/preflight.md"
    fi
    return 2
}

# ─── helper: GitHub release asset download ───────────────────────────────────
# gh_download <owner/repo> <asset_name_fragment> <output_file>
gh_download() {
    local repo="$1" pattern="$2" outfile="$3"
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local headers=(-sL)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi

    local url
    url=$(curl "${headers[@]}" "$api_url" \
        | grep '"browser_download_url"' \
        | grep -i "$pattern" \
        | head -1 \
        | cut -d '"' -f 4)

    if [[ -z "$url" ]]; then
        fail "GitHub: no asset matching '${pattern}' in ${repo}"
        return 1
    fi

    info "Downloading: $url"
    curl -sL "$url" -o "$outfile" >> "$LOGFILE" 2>&1 || {
        fail "Download failed: $url"
        return 1
    }
}

# ─── install mode steps ──────────────────────────────────────────────────────
install_apt_base() {
    header "Base apt packages"
    install_required_packages "base apt packages" "${BASE_APT_REQUIRED[@]}"
    # Optional bucket includes ewf-tools / bulk-extractor / wine64.
    # ewf-tools must come AFTER GIFT PPA is enabled or it tries to pull in
    # libewf2 from jammy/universe and conflicts with the modern libewf already
    # on disk. We install it from the optional list per-package, after the
    # GIFT PPA is in place (see main()).
    install_optional_packages "optional supplementary packages" "${BASE_APT_OPTIONAL[@]}"
}

install_dotnet() {
    header "dotnet runtime 9.0 (for EZ Tools net9 builds)"
    if pkg_installed dotnet-runtime-9.0; then
        ok "dotnet-runtime-9.0 already installed"
        return 0
    fi

    # Register Microsoft's package feed for this Ubuntu version, but ONLY if
    # no Microsoft apt source is already configured. Newer Ubuntu / SIFT
    # images ship a pre-installed /etc/apt/sources.list.d/microsoft.sources
    # (deb822 format) that registers packages.microsoft.com directly — if we
    # then drop in packages-microsoft-prod (which writes microsoft-prod.list),
    # apt logs "Target Packages is configured multiple times" on every
    # update because both files resolve to the same repo URI.
    local ms_repo_present=0
    if dpkg -s packages-microsoft-prod >/dev/null 2>&1; then
        ms_repo_present=1
        ok "Microsoft package feed already registered (packages-microsoft-prod)"
    elif grep -Rqs -E '(packages\.microsoft\.com|^URIs:.*packages\.microsoft\.com)' \
            /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        ms_repo_present=1
        ok "Microsoft package feed already configured via existing apt source — skipping packages-microsoft-prod"
    fi

    if [[ $ms_repo_present -eq 0 ]]; then
        local tmpfile
        tmpfile=$(mktemp /tmp/ms-prod-XXXXX.deb)
        info "Downloading Microsoft package feed (Ubuntu ${UBUNTU_VER})"
        if ! curl -sL --max-time 30 \
            "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VER}/packages-microsoft-prod.deb" \
            -o "$tmpfile" >> "$LOGFILE" 2>&1; then
            fail "download Microsoft package feed"
            rm -f "$tmpfile"; return 1
        fi
        if ! "${SUDO[@]}" dpkg -i "$tmpfile" >> "$LOGFILE" 2>&1; then
            fail "register Microsoft package feed"
            rm -f "$tmpfile"; return 1
        fi
        rm -f "$tmpfile"
        APT_UPDATED=0
    fi

    install_required_packages "dotnet-runtime-9.0" dotnet-runtime-9.0
}

install_plaso() {
    header "Plaso + forensic Python apt packages"
    # GIFT PPA is added in main() before any apt install runs, so we don't
    # need to re-add here. Just install what's missing.
    install_required_packages "Plaso/forensic apt packages" "${PLASO_APT_REQUIRED[@]}"
    if [[ ${#PLASO_APT_OPTIONAL[@]} -gt 0 ]]; then
        install_optional_packages "Plaso optional apt packages" "${PLASO_APT_OPTIONAL[@]}"
    fi
}

ez_download_zip() {
    # ez_download_zip <ZipBasename> <out_path>
    # Downloads from ${EZ_DOWNLOAD_BASE}/<ZipBasename>.zip. Uses HEAD first to
    # fail fast on 404 instead of writing an HTML error page that confuses
    # unzip later. Then sanity-checks the downloaded file is actually a zip.
    local zipname="$1" outfile="$2"
    local url="${EZ_DOWNLOAD_BASE}/${zipname}.zip"
    local code
    code=$(curl -sL -o /dev/null -w "%{http_code}" --max-time 10 -I "$url" 2>/dev/null || echo "000")
    if [[ ! "$code" =~ ^(200|302)$ ]]; then
        fail "${zipname}: HTTP ${code} from ${url} — tool may not exist in net9 channel"
        return 1
    fi
    info "Downloading: $url"
    if ! curl -sL --max-time 60 "$url" -o "$outfile" >> "$LOGFILE" 2>&1; then
        fail "${zipname}: download failed"
        return 1
    fi
    if ! file "$outfile" 2>/dev/null | grep -qi 'zip archive'; then
        fail "${zipname}: downloaded file is not a zip archive (likely 404 HTML)"
        return 1
    fi
    return 0
}

install_ez_root_tool() {
    # install_ez_root_tool <ToolName>
    # Tool zip lands at ${EZ_DOWNLOAD_BASE}/<ToolName>.zip and extracts a .dll
    # into EZ_DEST. Eric occasionally publishes a tool with different case
    # in the .dll filename than the zip basename (e.g. RLA.zip -> rla.dll),
    # so the verify step is case-insensitive and reports the actual filename.
    local name="$1"
    # Case-insensitive presence check — reuse if any case variant already on disk
    local existing
    existing=$(find "$EZ_DEST" -maxdepth 1 -iname "${name}.dll" -print -quit 2>/dev/null)
    if [[ -n "$existing" ]]; then
        ok "${name}: already present as $(basename "$existing")"
        return 0
    fi

    local tmp
    tmp=$(mktemp /tmp/ez_XXXXX.zip)
    if ez_download_zip "$name" "$tmp"; then
        if "${SUDO[@]}" unzip -q -o "$tmp" -d "$EZ_DEST" >> "$LOGFILE" 2>&1; then
            local installed
            installed=$(find "$EZ_DEST" -maxdepth 1 -iname "${name}.dll" -print -quit 2>/dev/null)
            if [[ -n "$installed" ]]; then
                local actual
                actual=$(basename "$installed")
                if [[ "$actual" != "${name}.dll" ]]; then
                    ok "${name}: installed as ${actual} (note: lowercase — invoke with that exact case on Linux)"
                else
                    ok "${name}: installed at ${installed}"
                fi
            else
                fail "${name}: extracted but no ${name}.dll (any case) under ${EZ_DEST}/ — check zip layout in $LOGFILE"
            fi
        else
            fail "${name}: unzip failed"
        fi
    fi
    rm -f "$tmp"
}

install_ez_subdir_tool() {
    # install_ez_subdir_tool <ZipBasename> <SubdirName> <DllName>
    # Zip extracts a subdirectory; the binary lands at
    # ${EZ_DEST}/<SubdirName>/<DllName>.dll. Verify case-insensitively to
    # tolerate Eric's occasional capitalization variations.
    local zipname="$1" subdir="$2" dll="$3"
    local existing
    existing=$(find "$EZ_DEST" -maxdepth 2 -iname "${dll}.dll" -print -quit 2>/dev/null)
    if [[ -n "$existing" ]]; then
        ok "${dll}: already present at ${existing}"
        return 0
    fi

    local tmp
    tmp=$(mktemp /tmp/ez_XXXXX.zip)
    if ez_download_zip "$zipname" "$tmp"; then
        if "${SUDO[@]}" unzip -q -o "$tmp" -d "$EZ_DEST" >> "$LOGFILE" 2>&1; then
            local installed
            installed=$(find "$EZ_DEST" -maxdepth 2 -iname "${dll}.dll" -print -quit 2>/dev/null)
            if [[ -n "$installed" ]]; then
                ok "${dll}: installed at ${installed}"
            else
                fail "${dll}: extracted but no ${dll}.dll (any case) under ${EZ_DEST}/ — check zip layout in $LOGFILE"
            fi
        else
            fail "${dll}: unzip failed"
        fi
    fi
    rm -f "$tmp"
}

install_ez_tools() {
    header "EZ Tools (Zimmerman) — net9 builds"
    "${SUDO[@]}" mkdir -p "$EZ_DEST" >> "$LOGFILE" 2>&1 || { fail "create ${EZ_DEST}"; return 1; }
    "${SUDO[@]}" chmod 755 "$EZ_DEST" >> "$LOGFILE" 2>&1 || true

    local name
    for name in "${EZ_ROOT_TOOLS[@]}"; do
        install_ez_root_tool "$name"
    done

    local entry zipname subdir dll
    for entry in "${EZ_SUBDIR_TOOLS[@]}"; do
        IFS='|' read -r zipname subdir dll <<< "$entry"
        install_ez_subdir_tool "$zipname" "$subdir" "$dll"
    done
}

resolve_vol3_version() {
    # Honors $VOL3_VER from the environment if set; else queries the latest
    # GitHub release tag; else falls back to a known-existing pin.
    if [[ -n "${VOL3_VER:-}" ]]; then
        return 0
    fi
    local tag
    tag=$(curl -sL --max-time 10 \
        https://api.github.com/repos/volatilityfoundation/volatility3/releases/latest \
        2>/dev/null | grep -m1 '"tag_name"' \
        | sed -E 's/.*"v?([0-9.]+)".*/\1/')
    if [[ -n "$tag" ]] && [[ "$tag" =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
        VOL3_VER="$tag"
    else
        warn "Could not resolve latest volatility3 tag; using fallback ${VOL3_VER_FALLBACK}"
        VOL3_VER="$VOL3_VER_FALLBACK"
    fi
}

install_volatility3() {
    resolve_vol3_version
    VOL3_DIR="/opt/volatility3-${VOL3_VER}"
    header "Volatility 3 v${VOL3_VER}"
    if [[ -f "${VOL3_DIR}/vol.py" ]]; then
        ok "Volatility 3 already at ${VOL3_DIR}"
        ensure_vol3_symlink
        return 0
    fi

    local url="https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v${VOL3_VER}.tar.gz"
    local tmp
    tmp=$(mktemp /tmp/vol3_XXXXX.tar.gz)

    info "Downloading: $url"
    if ! curl -sL --max-time 60 "$url" -o "$tmp" >> "$LOGFILE" 2>&1; then
        fail "download Volatility 3 v${VOL3_VER}"
        rm -f "$tmp"; return 1
    fi
    # Sanity: tarball, not a 404 HTML page
    if ! file "$tmp" 2>/dev/null | grep -qiE 'gzip|tar archive'; then
        fail "Volatility 3 v${VOL3_VER}: downloaded file is not a tarball (likely 404 — tag does not exist)"
        rm -f "$tmp"; return 1
    fi

    if ! "${SUDO[@]}" tar -xzf "$tmp" -C /opt/ >> "$LOGFILE" 2>&1; then
        fail "extract Volatility 3 to /opt/"
        rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"

    if [[ -f "${VOL3_DIR}/requirements.txt" ]]; then
        if pip_available; then
            "${SUDO[@]}" pip3 install -q -r "${VOL3_DIR}/requirements.txt" >> "$LOGFILE" 2>&1 \
                && ok "pip install Volatility 3 requirements" \
                || warn "Volatility 3 requirements: pip install failed; some plugins may need extra deps"
        else
            warn "pip unavailable; skipping Volatility 3 requirements (run pip3 install -r ${VOL3_DIR}/requirements.txt later)"
        fi
    fi

    if [[ -f "${VOL3_DIR}/vol.py" ]]; then
        ok "Volatility 3 installed at ${VOL3_DIR}/vol.py"
        ensure_vol3_symlink
    else
        fail "vol.py not found at ${VOL3_DIR} after extraction"
    fi
}

ensure_vol3_symlink() {
    # Maintain a stable /opt/volatility3 symlink → /opt/volatility3-<ver>
    # so skill files don't need to know the version-specific path.
    "${SUDO[@]}" ln -sfn "$VOL3_DIR" /opt/volatility3 >> "$LOGFILE" 2>&1 \
        && ok "symlink /opt/volatility3 -> ${VOL3_DIR}" \
        || warn "could not create /opt/volatility3 symlink"
}

install_memory_baseliner() {
    header "Memory Baseliner (csababarta/memory-baseliner)"
    # Per the upstream README: baseline.py + baseline_objects.py are NOT
    # standalone — they import volatility3 as a library and must live INSIDE
    # the volatility3 directory next to vol.py. We:
    #   1. Clone the repo to ${BASELINER_DIR} (canonical source / for updates)
    #   2. Copy the two .py files into ${VOL3_DIR}/
    # Invocation then becomes: python3 ${VOL3_DIR}/baseline.py ...
    # (or with the /opt/volatility3 symlink: python3 /opt/volatility3/baseline.py)

    if [[ -z "${VOL3_DIR:-}" ]] || [[ ! -f "${VOL3_DIR}/vol.py" ]]; then
        warn "Memory Baseliner: requires Volatility 3 installed first at ${VOL3_DIR:-/opt/volatility3-<ver>}; skipping"
        return 1
    fi

    # 1. Clone source repo (skip if already present)
    if [[ ! -d "${BASELINER_DIR}/.git" ]]; then
        local url="https://github.com/csababarta/memory-baseliner"
        info "git clone $url -> $BASELINER_DIR"
        # GIT_TERMINAL_PROMPT=0 + GIT_ASKPASS=/bin/true (set in main()) ensure
        # this fails fast on 404 / private repo instead of hanging on a
        # credential prompt.
        if ! "${SUDO[@]}" git clone --depth=1 "$url" "$BASELINER_DIR" >> "$LOGFILE" 2>&1; then
            fail "git clone csababarta/memory-baseliner — verify URL is reachable"
            return 1
        fi
        ok "cloned to ${BASELINER_DIR}"
    else
        ok "${BASELINER_DIR} already cloned"
    fi

    # 2. Copy the two scripts into the vol3 directory
    local f copied=0
    for f in baseline.py baseline_objects.py; do
        if [[ ! -f "${BASELINER_DIR}/${f}" ]]; then
            fail "Memory Baseliner: ${BASELINER_DIR}/${f} not present in cloned repo"
            continue
        fi
        if "${SUDO[@]}" cp "${BASELINER_DIR}/${f}" "${VOL3_DIR}/${f}" >> "$LOGFILE" 2>&1; then
            ok "copied ${f} -> ${VOL3_DIR}/${f}"
            (( copied++ )) || true
        else
            fail "copy ${f} -> ${VOL3_DIR}/"
        fi
    done

    if [[ $copied -eq 2 ]]; then
        ok "Memory Baseliner ready: python3 ${VOL3_DIR}/baseline.py -h"
    fi
}

install_zeek_obs() {
    # Install Zeek from the upstream OBS binary repo per
    # https://docs.zeek.org/en/current/install.html. Replaces the older
    # jammy/universe `zeek` install path; pinning keeps us off the auto-
    # transitioning train upstream warns about ("zeek-lts ... no longer
    # supported"). Symlinks /opt/zeek/bin/{zeek,zeek-cut,zeekctl,zkg} into
    # /usr/local/bin so non-interactive shells (orchestrator subagents,
    # preflight) can find the binaries without sourcing a profile script.
    header "Zeek (${ZEEK_OBS_PKG} from OBS — ${ZEEK_OBS_DISTRO})"

    if pkg_installed "$ZEEK_OBS_PKG"; then
        ok "${ZEEK_OBS_PKG}: already installed"
    else
        ensure_zeek_obs_repo || return 1
        ensure_apt_update || return 1
        apt_fix_broken
        if ! "${SUDO[@]}" apt-get install -y -qq "$ZEEK_OBS_PKG" >> "$LOGFILE" 2>&1; then
            local last_err
            last_err=$("${SUDO[@]}" apt-get install -y "$ZEEK_OBS_PKG" 2>&1 \
                | grep -E '^(E:|N:|The following packages have unmet dependencies)' \
                | head -3 | tr '\n' ';' || echo "see $LOGFILE")
            fail "${ZEEK_OBS_PKG}: install failed (${last_err})"
            return 1
        fi
        ok "${ZEEK_OBS_PKG}: installed"
    fi

    # Symlink the user-facing binaries onto PATH. We refuse to overwrite a
    # real file at /usr/local/bin/<name> (would be a previous source-build of
    # Zeek or an unrelated binary); we only manage symlinks.
    local bin tgt link
    for bin in "${ZEEK_BIN_LINKS[@]}"; do
        tgt="${ZEEK_PREFIX}/bin/${bin}"
        link="/usr/local/bin/${bin}"
        if [[ ! -x "$tgt" ]]; then
            warn "${tgt} not present after install; skipping symlink"
            continue
        fi
        if [[ -e "$link" && ! -L "$link" ]]; then
            warn "${link} exists and is not a symlink; not overwriting"
            continue
        fi
        if "${SUDO[@]}" ln -sfn "$tgt" "$link" >> "$LOGFILE" 2>&1; then
            ok "symlink ${link} -> ${tgt}"
        else
            warn "could not create symlink ${link}"
        fi
    done
    return 0
}

install_network_tools() {
    header "Network-forensic tools (tshark / Zeek / Suricata / tcpdump)"
    install_required_packages "network-forensic apt packages" "${NETWORK_APT_REQUIRED[@]}"
    if [[ ${#NETWORK_APT_OPTIONAL[@]} -gt 0 ]]; then
        install_optional_packages "network-forensic optional apt packages" "${NETWORK_APT_OPTIONAL[@]}"
    fi
    install_zeek_obs
    # tshark is normally a non-interactive install on SIFT, but on stock Ubuntu
    # the postinst asks whether non-root users may capture. We accept the
    # default (No — analysis-only host) by pre-seeding debconf.
    if pkg_installed wireshark-common && ! debconf-show wireshark-common 2>/dev/null \
       | grep -q 'wireshark-common/install-setuid: false'; then
        echo "wireshark-common wireshark-common/install-setuid boolean false" \
            | "${SUDO[@]}" debconf-set-selections >> "$LOGFILE" 2>&1 || true
    fi

    # Pull baseline ET Open rules so suricata -r works without network access
    # later. Idempotent — suricata-update tolerates re-run. Failure here is
    # treated as a hard fail (post-case7 hardening): a Suricata install
    # without rules silently runs an empty IDS pass, which produced false
    # confidence on prior cases. Use --check-versions to detect the case
    # where suricata-update can't reach its source.
    SURICATA_RULES_PATH="/var/lib/suricata/rules/suricata.rules"
    if command -v suricata-update >/dev/null 2>&1; then
        if "${SUDO[@]}" suricata-update --no-test >> "$LOGFILE" 2>&1; then
            ok "suricata-update: ET Open rules synced"
        else
            fail "suricata-update FAILED — Suricata IDS will run with no signatures. Re-run with network access to ET Open sources, or pre-stage rules at $SURICATA_RULES_PATH."
        fi
        # Verify the merged ruleset actually landed on disk
        if [[ -s "$SURICATA_RULES_PATH" ]]; then
            sig_count=$(grep -c '^alert' "$SURICATA_RULES_PATH" 2>/dev/null || echo 0)
            ok "Suricata ET Open ruleset present at $SURICATA_RULES_PATH ($sig_count signatures)"
        else
            fail "suricata-update reported success but $SURICATA_RULES_PATH is empty/missing — verify suricata-update sources and re-run."
        fi
    else
        warn "suricata-update not installed — skipping ET Open sync. Install \`suricata-update\` first."
    fi

    # Optional Python helpers — never block on these
    if pip_available; then
        local pkg
        for pkg in "${NETWORK_PIP_OPTIONAL[@]}"; do
            if pip_has_package "$pkg"; then
                ok "pip package already installed (optional): ${pkg}"
                continue
            fi
            if "${SUDO[@]}" pip3 install -q "$pkg" >> "$LOGFILE" 2>&1; then
                ok "pip install (optional) ${pkg}"
            else
                warn "pip install (optional) ${pkg} failed; continuing"
            fi
        done
    fi
}

install_python_libs() {
    header "Python pip libraries"
    if ! pip_available; then
        fail "pip is unavailable; cannot install pip-backed Python libraries (run: sudo apt install python3-pip)"
        return 1
    fi

    local pkg
    for pkg in "${PIP_REQUIRED[@]}"; do
        if pip_has_package "$pkg"; then
            ok "pip package already installed: ${pkg}"
        else
            if "${SUDO[@]}" pip3 install -q "$pkg" >> "$LOGFILE" 2>&1; then
                ok "pip install ${pkg}"
            else
                fail "pip install ${pkg}"
            fi
        fi
    done

    # Optional pip packages (currently empty — see PIP_OPTIONAL definition).
    for pkg in "${PIP_OPTIONAL[@]}"; do
        if pip_has_package "$pkg"; then
            ok "pip package already installed (optional): ${pkg}"
            continue
        fi
        if "${SUDO[@]}" pip3 install -q "$pkg" >> "$LOGFILE" 2>&1; then
            ok "pip install (optional) ${pkg}"
        else
            warn "pip install (optional) ${pkg} failed; continuing"
        fi
    done
}

install_chainsaw() {
    header "Chainsaw (Sigma + Chainsaw-format EVTX hunter)"
    if command -v chainsaw >/dev/null 2>&1; then
        ok "chainsaw: already on PATH ($(command -v chainsaw))"
        return 0
    fi
    "${SUDO[@]}" mkdir -p "$SIGMA_CHAINSAW_DIR" >> "$LOGFILE" 2>&1 \
        || { fail "create $SIGMA_CHAINSAW_DIR"; return 1; }

    local tmp
    tmp=$(mktemp /tmp/chainsaw_XXXXX.tar.gz)
    if ! gh_download "$SIGMA_CHAINSAW_REPO" "$SIGMA_CHAINSAW_ASSET" "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    if ! file "$tmp" 2>/dev/null | grep -qiE 'gzip|tar archive'; then
        fail "chainsaw: downloaded file is not a tarball (likely 404 HTML)"
        rm -f "$tmp"; return 1
    fi

    # Tarball layout has historically alternated between a flat root and a
    # versioned wrapping directory; --strip-components=1 fits the wrapped
    # form, plain extraction fits the flat form. Try the friendlier form
    # first, then fall back.
    if ! "${SUDO[@]}" tar -xzf "$tmp" -C "$SIGMA_CHAINSAW_DIR" --strip-components=1 \
            >> "$LOGFILE" 2>&1; then
        if ! "${SUDO[@]}" tar -xzf "$tmp" -C "$SIGMA_CHAINSAW_DIR" >> "$LOGFILE" 2>&1; then
            fail "chainsaw: extract failed"
            rm -f "$tmp"; return 1
        fi
    fi
    rm -f "$tmp"

    local bin
    bin=$(find "$SIGMA_CHAINSAW_DIR" -maxdepth 2 -type f -name 'chainsaw' -print -quit 2>/dev/null)
    if [[ -z "$bin" ]]; then
        fail "chainsaw: no 'chainsaw' binary in extracted tree (${SIGMA_CHAINSAW_DIR})"
        return 1
    fi
    "${SUDO[@]}" chmod +x "$bin" >> "$LOGFILE" 2>&1 || true

    if [[ -e "$SIGMA_CHAINSAW_LINK" && ! -L "$SIGMA_CHAINSAW_LINK" ]]; then
        warn "${SIGMA_CHAINSAW_LINK} exists and is not a symlink; not overwriting"
    elif "${SUDO[@]}" ln -sfn "$bin" "$SIGMA_CHAINSAW_LINK" >> "$LOGFILE" 2>&1; then
        ok "chainsaw: ${SIGMA_CHAINSAW_LINK} -> ${bin}"
    else
        warn "chainsaw: could not create symlink ${SIGMA_CHAINSAW_LINK}"
    fi
}

install_hayabusa() {
    header "Hayabusa (one-shot Sigma EVTX timeline)"
    if command -v hayabusa >/dev/null 2>&1; then
        ok "hayabusa: already on PATH ($(command -v hayabusa))"
        return 0
    fi
    "${SUDO[@]}" mkdir -p "$SIGMA_HAYABUSA_DIR" >> "$LOGFILE" 2>&1 \
        || { fail "create $SIGMA_HAYABUSA_DIR"; return 1; }

    if ! command -v unzip >/dev/null 2>&1; then
        fail "hayabusa: unzip not on PATH (BASE_APT should have installed it)"
        return 1
    fi

    local tmp
    tmp=$(mktemp /tmp/hayabusa_XXXXX.zip)
    if ! gh_download "$SIGMA_HAYABUSA_REPO" "$SIGMA_HAYABUSA_ASSET" "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    if ! file "$tmp" 2>/dev/null | grep -qi 'zip archive'; then
        fail "hayabusa: downloaded file is not a zip archive (likely 404 HTML)"
        rm -f "$tmp"; return 1
    fi

    if ! "${SUDO[@]}" unzip -q -o "$tmp" -d "$SIGMA_HAYABUSA_DIR" >> "$LOGFILE" 2>&1; then
        fail "hayabusa: unzip failed"
        rm -f "$tmp"; return 1
    fi
    rm -f "$tmp"

    # Hayabusa 3.x ships its Linux binary as `hayabusa-<ver>-lin-x64-musl`
    # alongside `rules/` and `config/`; older 2.x releases shipped a plain
    # `hayabusa` binary. Match either; prefer ELF executables to avoid
    # picking up rule YAMLs or readme fixtures.
    local cand bin=""
    while IFS= read -r cand; do
        if file "$cand" 2>/dev/null | grep -qi 'ELF.*executable'; then
            bin="$cand"; break
        fi
    done < <(find "$SIGMA_HAYABUSA_DIR" -maxdepth 3 -type f \
                \( -iname 'hayabusa-*-lin-*' -o -iname 'hayabusa' \) 2>/dev/null)
    if [[ -z "$bin" ]]; then
        fail "hayabusa: no ELF binary matching hayabusa-*-lin-* (or 'hayabusa') under ${SIGMA_HAYABUSA_DIR}"
        return 1
    fi
    "${SUDO[@]}" chmod +x "$bin" >> "$LOGFILE" 2>&1 || true

    if [[ -e "$SIGMA_HAYABUSA_LINK" && ! -L "$SIGMA_HAYABUSA_LINK" ]]; then
        warn "${SIGMA_HAYABUSA_LINK} exists and is not a symlink; not overwriting"
    elif "${SUDO[@]}" ln -sfn "$bin" "$SIGMA_HAYABUSA_LINK" >> "$LOGFILE" 2>&1; then
        ok "hayabusa: ${SIGMA_HAYABUSA_LINK} -> ${bin}"
    else
        warn "hayabusa: could not create symlink ${SIGMA_HAYABUSA_LINK}"
    fi
}

install_evtx_dump() {
    header "evtx_dump (Rust EVTX → JSONL dumper)"
    if command -v evtx_dump >/dev/null 2>&1; then
        ok "evtx_dump: already on PATH ($(command -v evtx_dump))"
        return 0
    fi

    # Try apt first — `evtx-tools` is not in jammy/universe today, but a
    # future Ubuntu release may pick it up and apt is cheaper + signed.
    if apt-cache show "$SIGMA_EVTX_APT" >/dev/null 2>&1; then
        if install_one_pkg "$SIGMA_EVTX_APT" optional \
            && command -v evtx_dump >/dev/null 2>&1; then
            return 0
        fi
        warn "${SIGMA_EVTX_APT}: apt did not place evtx_dump on PATH; falling back to GitHub release"
    else
        info "${SIGMA_EVTX_APT}: not in apt index; using omerbenamram/evtx GitHub release"
    fi

    local tmp
    tmp=$(mktemp /tmp/evtx_dump_XXXXX)
    if ! gh_download "$SIGMA_EVTX_REPO" "$SIGMA_EVTX_ASSET" "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    if ! file "$tmp" 2>/dev/null | grep -qi 'ELF.*executable'; then
        fail "evtx_dump: downloaded file is not an ELF binary (likely 404 HTML)"
        rm -f "$tmp"; return 1
    fi

    if "${SUDO[@]}" install -m 0755 "$tmp" "$SIGMA_EVTX_LINK" >> "$LOGFILE" 2>&1; then
        ok "evtx_dump: installed at ${SIGMA_EVTX_LINK}"
    else
        fail "evtx_dump: install to ${SIGMA_EVTX_LINK} failed"
    fi
    rm -f "$tmp"
}

install_sigma_tools() {
    install_chainsaw
    install_hayabusa
    install_evtx_dump
}

print_install_summary() {
    header "Install summary"
    _log "Full log: $LOGFILE"
    if [[ $ERRORS -eq 0 ]]; then
        printf "${GREEN}${BOLD}Install workflow completed with no errors.${NC}\n"
        _log "Result: success"
    else
        printf "${YELLOW}${BOLD}${ERRORS} item(s) had errors.${NC} Review: %s\n" "$LOGFILE"
        _log "Result: ${ERRORS} errors"
    fi

    if [[ -x "$PREFLIGHT_SCRIPT" ]]; then
        _log "Verify with:"
        _log "  bash ${PREFLIGHT_SCRIPT} | tee ./analysis/preflight.md"
    fi
}

# ─── main ────────────────────────────────────────────────────────────────────
main() {
    printf "${BOLD}DFIR Tool Installer — SANS SIFT Workstation${NC}\n"
    printf "Mode: %s\n" "$MODE"
    printf "Log: %s\n" "$LOGFILE"

    if [[ "$MODE" == "check" ]]; then
        run_check_mode
        return $?
    fi

    # Never block on interactive credential prompts when cloning from
    # GitHub etc. — a 404 / private repo should fail fast, not hang.
    export GIT_TERMINAL_PROMPT=0
    export GIT_ASKPASS=/bin/true

    check_network strict || return 1
    # GIFT PPA must be enabled BEFORE the base apt install so that packages
    # available in both jammy/universe and GIFT (ewf-tools, bulk-extractor,
    # libewf, …) resolve to the GIFT version. Without this, `ewf-tools` from
    # jammy/universe pulls in libewf2 and conflicts with the modern libewf
    # already installed by SIFT, and the whole apt install line aborts.
    ensure_gift_ppa || warn "GIFT PPA not added; some packages may install older versions"
    install_apt_base
    install_dotnet
    install_plaso
    install_ez_tools
    install_volatility3
    install_memory_baseliner
    install_python_libs
    install_network_tools
    install_sigma_tools
    print_install_summary

    [[ $ERRORS -eq 0 ]]
}

main "$@"
