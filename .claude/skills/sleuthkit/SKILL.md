# Skill: File System & Carving (The Sleuth Kit / EWF Tools)

## Use this skill when
- You have a disk image (`.E01`, `.dd`, `.raw`) and need to walk the filesystem,
  extract a specific file by inode, or recover deleted entries
- A higher-level skill needs the *raw* artifact (registry hive, EVTX, MFT,
  Prefetch dir, Recycle Bin) extracted from an image before parsing
- The case asks "was this file ever on disk?" / "when was it deleted?" /
  "what's in unallocated?"
- File carving is required (PhotoRec / bulk_extractor)

**Don't reach for this skill when** a parsed, structured answer already exists
elsewhere — e.g., for "did `<binary>` execute" go to `windows-artifacts`
(Prefetch/Amcache); for "what was in memory" go to `memory-analysis`. TSK is
the substrate, not the answer.

## Tool selection — pick by question

| Question | Best tool | Why |
|---|---|---|
| What partitions does this image have? | `mmls <image>.E01` | Cheapest possible read; libewf-backed |
| What filesystem is on partition X? | `fsstat -o <offset> <image>.E01` | Cluster size, MFT offset, volume serial |
| What sector size? | `img_stat <image>.E01` | Catches 4K-sector drives — wrong size = wrong byte offset everywhere downstream |
| Full file listing including deleted | `fls -r -p -o <offset> <image>.E01` | One pass; `*` prefix = deleted |
| Just deleted entries | `fls -r -p -o <offset> <image>.E01 \| grep '^\*'` | Cheap delta |
| Extract one file by inode | `icat -o <offset> <image>.E01 <inode>` | Bypasses OS file locking + VSS |
| Bulk-recover all (alloc + unalloc) | `tsk_recover -e <image>.E01 ./exports/tsk_recover_all/` | Heavy — only when targeted icat won't scale |
| Filesystem MAC-time timeline | `fls -r -m / + mactime -y -z UTC` | Bodyfile feeds Plaso too — never re-derive |
| Carve by signature (deleted images, docs, PE) | `photorec` | Use when MFT entry overwritten |
| Carve indicators (emails, URLs, IPs, BTC) | `bulk_extractor -o ./exports/carved/` | Default 4 threads; fast on multi-core |
| Verify E01 integrity (court-quality) | `ewfverify` (from `libewf-tools`) | Optional — `libewf` alone is enough for analysis; install `libewf-tools` from GIFT PPA when courtroom integrity verification is required |

**Rule of thumb:** if you know which file you want, use `fls + icat`. Reach for
`tsk_recover` only when you actually need everything — the output is large and
slow to triage.

## Overview
Use this skill for disk image analysis, filesystem navigation, file extraction, and
file carving on the SIFT workstation. Evidence images are commonly in E01 (Expert Witness
Format). Always mount read-only to preserve evidence integrity.

## Analysis Discipline

`./analysis/` is not just a bucket for raw tool output. Keep both a terse audit trail and
human-written findings as you work.

- `./analysis/forensic_audit.log` — the action that triggers the entry must append its own UTC
  line describing that exact action, the tool or artifact reviewed, the result, and why it
  matters.
- `./analysis/filesystem/findings.md` — append short notes with the artifact reviewed, finding,
  interpretation, and next pivot.
- `./reports/00_intake.md` or the active case report — update it when a finding changes the
  case narrative.

Use this format for audit entries: `<UTC timestamp> | <action> | <finding/result> | <next step>`.
The `action` field must name the exact step that caused the log entry, such as `fls /Users`,
`MFTECmd $MFT parse`, or `netscan pivot on 10.0.0.5`; never use vague text like `analysis
update` or `progress`.
Never rely on the stop hook alone. If it only writes a timestamp, blank summary, or text that
does not describe the triggering action, add the missing action-specific context manually before
moving on.

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| `ewfinfo` | Display E01 image metadata and embedded hash values |
| `ewfverify` | Verify E01 image integrity against stored hashes |
| `ewfmount` | Mount E01/EWF images as a raw disk device |
| `img_stat` | Display image format and sector size |
| `mmls` | Display partition table (MBR and GPT) |
| `fsstat` | Filesystem metadata (cluster size, MFT location, etc.) |
| `fls` | List files and directories (includes deleted entries) |
| `icat` | Extract file content by inode/MFT number |
| `istat` | Display inode metadata (MAC times, size, allocated blocks) |
| `ffind` | Find filename for an inode |
| `ils` | List inodes (including orphan/deleted) |
| `blkls` | Extract unallocated disk blocks (for carving) |
| `tsk_recover` | Bulk extract all allocated and/or unallocated files |
| `mactime` | Generate timeline from bodyfile |
| `blkcat` | Extract raw data unit content |
| `bulk_extractor` | Carve email addresses, URLs, domains, credit cards, etc. |
| `photorec` | File carving by file signature |

---

## Workflow

> **Before anything:** run `.claude/skills/dfir-bootstrap/preflight.sh` to confirm
> which of `ewfinfo`/`ewfverify`/`ewfmount` are actually present on this SIFT
> instance. The correct package on SIFT is **`libewf-tools` from the GIFT PPA**
> (NOT the stock Ubuntu `ewf-tools` package — that one is built against the old
> `libewf2` and apt will refuse to install it alongside the modern `libewf` that
> SIFT/GIFT ships). On minimal installs only `libewf` is installed, which is
> enough for everything in this skill **except** the optional `ewfinfo` /
> `ewfverify` / `ewfmount` binaries.

### 1. Verify the Image (if libewf-tools is available)

```bash
# Display E01 metadata (acquisition hash, timestamps, notes) — requires libewf-tools
ewfinfo /cases/<casename>/<image>.E01

# Verify integrity — compare computed vs stored hash
ewfverify /cases/<casename>/<image>.E01
```

Record the MD5/SHA1 from `ewfinfo` output in your case notes. `ewfverify` must complete
without errors before any analysis proceeds.

**If `ewfinfo`/`ewfverify` are NOT installed** (preflight reports `libewf-tools: MISSING`):

- You cannot formally verify the E01 against its embedded acquisition hash.
- Document this limitation in `./reports/00_intake.md` and proceed with analysis
  using TSK's direct libewf support (see §2 below).
- Install via `sudo apt install libewf-tools` (requires GIFT PPA;
  `install-tools.sh` configures the PPA) for courtroom-quality integrity
  verification.
  Do NOT `sudo apt install ewf-tools` — that's the stock Ubuntu package and
  apt will remove it again the next time `libewf` gets touched.

### 2. Read E01 (no mount required — TSK uses libewf directly)

**The Sleuth Kit links against libewf and reads `.E01` files directly.** You do NOT need
`ewfmount` to run `mmls`, `fsstat`, `fls`, `icat`, `ils`, `blkls`, `tsk_recover`, or
`mactime` bodyfile generation. Point every TSK command at the `.E01` path directly:

```bash
# Partition table — works on the E01 without any mount
mmls /cases/<casename>/<image>.E01

# Filesystem stats at a specific partition offset (sectors)
fsstat -o 65664 /cases/<casename>/<image>.E01

# Full recursive file listing including deleted entries
fls -r -p -o 65664 /cases/<casename>/<image>.E01 > ./analysis/filesystem/fls.txt

# Extract a file by inode
icat -o 65664 /cases/<casename>/<image>.E01 <inode> > ./exports/files/<name>
```

Use this path by default — it is simpler, has fewer moving parts, and does not require
sudo. Only mount via `ewfmount` + loopback when you need the OS to see the filesystem
as a normal mountpoint (e.g., for `find`, `grep -r`, or to run a Windows binary via WINE
against live files).

**Multi-segment `.E01`:** TSK handles `.E01`/`.E02`/... segmentation automatically when
you give it the first segment path. No special flag needed.

### 2b. Mount E01 via loopback (optional, when TSK-direct is not enough)

```bash
# Only needed when you want the filesystem visible to non-TSK tools
sudo mkdir -p /mnt/ewf /mnt/windows_mount
sudo ewfmount /cases/<casename>/<image>.E01 /mnt/ewf/
ls /mnt/ewf/   # expect: ewf1
```

**Multi-segment E01:** `ewfmount` automatically detects and joins all segments when you
specify the first segment. No glob or special syntax needed.

### 3. Check Sector Size

```bash
# Default is 512 bytes; some modern drives use 4096 (4K) sector size
img_stat /mnt/ewf/ewf1

# Look for "Sector Size" in output — use this value in offset calculations
# If 4096: OFFSET = Start_sector * 4096
```

### 4. Inspect Partition Table

```bash
sudo mmls /mnt/ewf/ewf1
# Note the Start sector and sector size for the target partition (usually the largest NTFS)
```

Example output (512-byte sectors):
```
     Slot    Start        End          Length       Description
00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
01:  -----   0000000000   0000002047   0000002048   Unallocated
02:  000:00  0000002048   0000534527   0000532480   NTFS / exFAT (0x07)
03:  000:01  0000534528   ...          ...          Recovery
```

**GPT disks:** `mmls` handles GPT automatically — look for partition type GUIDs.

### 5. Mount Filesystem (Read-Only)

```bash
# Byte offset = Start_sector * sector_size (usually 512)
OFFSET=$(( 2048 * 512 ))   # adjust sector start and size from mmls output

sudo mount -o ro,loop,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount

# Verify
ls /mnt/windows_mount/
```

**If mount fails (filesystem dirty / hibernation):**
```bash
# Add norecovery for NTFS (no journal replay — preserves evidence state)
sudo mount -o ro,loop,norecovery,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount
```

### 6. Filesystem Metadata

```bash
# Filesystem statistics (NTFS version, cluster size, MFT offset, volume ID)
sudo fsstat /mnt/ewf/ewf1

# With partition offset (if fsstat is run against the raw image directly)
sudo fsstat -o 2048 /mnt/ewf/ewf1
```

### 7. Filesystem Navigation with TSK

```bash
# List all files recursively (includes deleted entries — marked with *)
sudo fls -r -p /mnt/ewf/ewf1 > ./analysis/fls_output.txt

# List with MAC times in bodyfile format (for timeline creation)
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# List a specific directory by inode
sudo fls /mnt/ewf/ewf1 <inode_number>

# List root directory (inode 5 on NTFS; inode 2 on ext)
sudo fls /mnt/ewf/ewf1 5

# Show only deleted entries
sudo fls -r -p /mnt/ewf/ewf1 | grep "^\*"

# With partition offset (bypass filesystem mount)
sudo fls -r -o 2048 /mnt/ewf/ewf1
```

**fls flags:**
| Flag | Description |
|------|-------------|
| `-r` | Recursive |
| `-p` | Full path (vs relative) |
| `-m /` | Bodyfile format (prefix `/` = mount point) |
| `-o <sectors>` | Partition offset in sectors |
| `-f <type>` | Force filesystem type (`ntfs`, `fat32`, `ext4`) |
| `-l` | Long format (include all timestamps) |
| `-d` | Show only deleted entries |
| `-D` | Show only directories |
| `-F` | Show only files (non-dirs) |
| `-h` | Hash file contents (MD5, for use with mactime) |
| `-z ZONE` | Display timestamps in specified timezone (e.g., `UTC`) |

### 8. Extract Files by Inode

```bash
# Get inode metadata (MAC times, allocated blocks, file size)
sudo istat /mnt/ewf/ewf1 <inode_number>

# Extract file content to local path
sudo icat /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract a deleted file (recover from unallocated blocks)
sudo icat -r /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>

# Extract file slack space (data after EOF in last cluster)
sudo icat -s /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>_slack

# Find filename for a known inode
sudo ffind /mnt/ewf/ewf1 <inode_number>

# With partition offset
sudo icat -o 2048 /mnt/ewf/ewf1 <inode_number> > ./exports/files/<filename>
```

### 9. Inode and Block-Level Analysis

```bash
# List all inodes (orphan entries = deleted with no directory entry)
sudo ils /mnt/ewf/ewf1 > ./analysis/ils_output.txt

# List only orphan (unlinked) inodes — deleted files with no directory entry
sudo ils -p /mnt/ewf/ewf1 > ./analysis/ils_orphan.txt

# List all inodes (allocated + unallocated)
sudo ils -e /mnt/ewf/ewf1 > ./analysis/ils_all.txt

# List only allocated inodes
sudo ils -a /mnt/ewf/ewf1 > ./analysis/ils_allocated.txt

# List only unallocated inodes
sudo ils -A /mnt/ewf/ewf1 > ./analysis/ils_unallocated.txt

# Mactime bodyfile format (combine with fls bodyfile for timeline)
sudo ils -m /mnt/ewf/ewf1 > ./analysis/ils_bodyfile.txt

# Extract raw unallocated blocks (for carving on tight storage budgets)
sudo blkls /mnt/ewf/ewf1 > ./analysis/unallocated.raw
# or targeted:
sudo blkls -a /mnt/ewf/ewf1 > ./analysis/allocated.raw     # allocated blocks only
sudo blkls -A /mnt/ewf/ewf1 > ./analysis/unallocated.raw   # unallocated blocks only
sudo blkls -s /mnt/ewf/ewf1 > ./analysis/slack.raw         # file slack space only
sudo blkls -e /mnt/ewf/ewf1 > ./analysis/every.raw         # every block (all types)
```

### 10. Bulk File Recovery

```bash
# Recover all allocated files, preserving directory structure (default)
sudo tsk_recover /mnt/ewf/ewf1 ./exports/tsk_recover/

# Recover allocated files only (explicit)
sudo tsk_recover -a /mnt/ewf/ewf1 ./exports/tsk_recover_alloc/

# Recover ALL files including unallocated/deleted
sudo tsk_recover -e /mnt/ewf/ewf1 ./exports/tsk_recover_all/

# Recover from a specific directory inode only
sudo tsk_recover -d <dir_inode> /mnt/ewf/ewf1 ./exports/tsk_recover_subdir/
```

### 11. Generate Filesystem Timeline

```bash
# Step 1: Create bodyfile
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/bodyfile.txt

# Step 2: Convert to sorted timeline (UTC, default tab-separated)
mactime -b ./analysis/bodyfile.txt -z UTC > ./exports/fs_timeline.txt

# Step 2 (alt): CSV output (easier to open in Timeline Explorer)
mactime -b ./analysis/bodyfile.txt -z UTC -d > ./exports/fs_timeline.csv

# Step 2 (alt): ISO 8601 timestamps (sortable, unambiguous)
mactime -b ./analysis/bodyfile.txt -z UTC -y > ./exports/fs_timeline_iso.txt

# Step 3 (optional): Filter by date range
mactime -b ./analysis/bodyfile.txt -z UTC -d 2023-01-01 2023-12-31 > ./exports/fs_timeline_filtered.txt

# Step 4 (optional): Generate hourly/daily index for large timelines
mactime -b ./analysis/bodyfile.txt -z UTC -i hour ./analysis/timeline_index.txt > ./exports/fs_timeline.txt

# Step 5 (optional): Export as bodyfile for use with log2timeline
# The bodyfile.txt IS the output — pass directly to log2timeline.py as a source
```

**mactime flags:**
| Flag | Description |
|------|-------------|
| `-b <file>` | Input bodyfile |
| `-z ZONE` | Timezone (always use `UTC`) |
| `-d` | CSV output (comma-separated, easier for spreadsheet tools) |
| `-y` | ISO 8601 date format (YYYY-MM-DD) instead of US format |
| `-h` | Add session header with metadata and column names |
| `-i [day\|hour] <file>` | Write hourly/daily index file for navigation |

### 12. Targeted Artifact Extraction

See `reference/extraction-paths.md` for the full set of mount-based extraction
recipes (EVTX, registry hives, NTUSER, UsrClass, Prefetch, MFT, $J, Amcache,
SRUM, browser profiles, Recycle Bin, scheduled tasks, PowerShell transcripts).
For the TSK-direct (no-mount) variants, see `windows-artifacts/SKILL.md` §
"Fallback workflow (Tier 2/3)".

---

## File Carving

### bulk_extractor

```bash
# Full carve from raw image (default: 4 threads in v2.0+)
sudo bulk_extractor -o ./exports/carved/ /mnt/ewf/ewf1

# Targeted feature types only (faster for specific IOC hunting)
sudo bulk_extractor -o ./exports/carved/ -e email -e url -e domain /mnt/ewf/ewf1

# Increase thread count for speed on multi-core SIFT
sudo bulk_extractor -j 8 -o ./exports/carved/ /mnt/ewf/ewf1

# Carve from unallocated space only
sudo blkls -u /mnt/ewf/ewf1 > /tmp/unalloc.raw
sudo bulk_extractor -o ./exports/carved_unalloc/ /tmp/unalloc.raw
```

Output: feature files for email addresses, URLs, domains, credit cards, BTC addresses,
telephone numbers, and more — each with byte offset back to image.

### PhotoRec (Signature-Based File Recovery)

```bash
sudo photorec /mnt/ewf/ewf1
# Interactive: select partition → file types → output directory
# Use ./exports/photorec/ as output directory
```

---

## Hash Verification and Known-File Filtering

```bash
# Compute MD5 hash of an extracted file
md5sum ./exports/files/<filename>

# Generate MD5 hashes of all extracted files for case documentation
find ./exports/files/ -type f -exec md5sum {} \; > ./exports/files/md5_manifest.txt

# Filter against NSRL (known-good software) with hashdeep
# (hashdeep must be installed: apt install hashdeep)
hashdeep -r /mnt/windows_mount/Windows/ -l > ./analysis/windows_hashes.txt
```

---

## Unmounting

```bash
# Always unmount in reverse order (filesystem first, then EWF)
sudo umount /mnt/windows_mount
sudo umount /mnt/ewf
```

---

## Output Paths

Routing follows the canonical layer model in
`.claude/skills/dfir-discipline/DISCIPLINE.md` ("Layer model" subsection):
bytes-as-analytic-unit go under `./exports/<domain>/` (layer 4, hashed by
`audit-exports.sh`); summary CSVs / markdown / `findings.md` stay under
`./analysis/<domain>/` (layer 3, recomputable). Multi-evidence cases
encode the originating EVID per Rule L (e.g. `mft-EV01.csv` or
`exports/registry/EV01/`).

| Output | Path |
|--------|------|
| Bodyfile | `./analysis/` |
| FLS output | `./analysis/fls_output.txt` |
| Filesystem timeline | `./exports/fs_timeline.txt` |
| Extracted files | `./exports/files/` |
| Registry hives | `./exports/registry/` |
| Event logs | `./exports/evtx/` |
| MFT + UsnJrnl | `./exports/mft/` |
| SRUM | `./exports/srum/` |
| Prefetch | `./exports/prefetch/` |
| Carved files | `./exports/carved/` |
| Recovered files (tsk) | `./exports/tsk_recover/` |

---

## Required baseline artifacts

This block is parsed by `.claude/skills/dfir-bootstrap/baseline-check.sh filesystem`.
Missing required artifacts produce a high-priority `L-BASELINE-filesystem-NN`
lead that runs first in the next investigator wave.

<!-- baseline-artifacts:start -->
optional: analysis/filesystem/mmls.txt
optional: analysis/filesystem/fls-root.txt
optional: analysis/filesystem/fsstat.txt
optional: analysis/filesystem/survey-EV01.md
<!-- baseline-artifacts:end -->

---

## Pivots — what to do with what you found here

| Found here | Pivot to | Skill |
|---|---|---|
| Suspicious binary at a path → its inode | Hash it (md5sum) → YARA / VT pivot; check execution evidence | `yara-hunting`, `windows-artifacts` (Prefetch + Amcache) |
| `\$Recycle.Bin` `$I` files | Parse with RBCmd or `parsers/rb_parse.py` for original path + SID + deletion UTC | `windows-artifacts` |
| `Windows\Prefetch\*.pf` extracted | Parse with PECmd or `parsers/prefetch_parse.py` | `windows-artifacts` |
| Registry hives extracted (SYSTEM/SOFTWARE/SAM/NTUSER.DAT/UsrClass.dat/Amcache.hve) | RECmd Kroll batch (Tier 1) or regipy (Tier 2) or `parsers/hive_strings.py` (Tier 3) | `windows-artifacts` |
| EVTX extracted (`Windows\System32\winevt\Logs\*.evtx`) | EvtxECmd `-d` with `--maps` | `windows-artifacts` |
| `$MFT` + `$J` extracted | MFTECmd; cross-reference timeline | `windows-artifacts`, `plaso-timeline` |
| Bodyfile from `fls -m` | Feed to `mactime` AND to Plaso as a source | `plaso-timeline` |
| Carved file of unknown type | YARA scan → if PE, malfind / strings; if doc, oledump / olevba | `yara-hunting` |
| File of interest with no matching MFT entry | Carve unallocated with `photorec`; check `$LogFile` | (deeper TSK) |

## Notes

- **TSK reads `.E01` directly via libewf** — point `mmls`, `fls`, `icat`, `fsstat`,
  `tsk_recover`, `ils`, `blkls` at the `.E01` path itself. `ewfmount` is only needed
  when non-TSK tools must see the filesystem as a loopback mount.
- **`libewf-tools` (GIFT) is the correct apt package** — the stock Ubuntu
  `ewf-tools` is the OLD libewf2 build and conflicts with the modern `libewf`
  shared library. If `ewfinfo`/`ewfverify` are missing, note the inability to
  formally verify the acquisition hash and proceed with TSK-direct reads — do
  NOT attempt to `sudo apt install` from the Claude bash sandbox unless
  preflight confirms `sudo -n` works.
- Never write to `/mnt/` paths — read-only mounts only
- `fls -p` flag shows full paths (more readable than relative paths)
- Deleted files appear with a `*` prefix in `fls` output
- Use `-o <sectors>` flag with all TSK tools when bypassing mount (more reliable than loopback)
- `img_stat` before `mmls` catches 4K sector drives — wrong sector size = wrong byte offset
- `norecovery` mount option prevents NTFS journal replay that could alter analysis
- `icat` is preferred over `cp` for extracting files — bypasses OS file locking and VSS
- The bodyfile from `fls` can be fed directly to `log2timeline.py` as an input source
- VSS (Volume Shadow Copies) can be mounted: use `mmls` on VSS metadata and `icat` with offsets
