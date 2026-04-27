# Memory Baseliner — Reference

Source: `https://github.com/csababarta/memory-baseliner` (csababarta).

**Architecture:** `baseline.py` and `baseline_objects.py` are NOT standalone
scripts — they import Volatility 3 as a library. Per the upstream README the
two files must live INSIDE the volatility3 directory (next to `vol.py`).
`install-tools.sh` clones the repo to `/opt/memory-baseliner`, copies the two
.py files into `/opt/volatility3-<ver>/`, and the `/opt/volatility3` symlink
makes `/opt/volatility3/baseline.py` the stable invocation path.

**Two operating modes:**
- **Comparison mode** — diff one suspect image against one known-good "golden"
  image (or saved JSON baseline) to surface UNKNOWN items. Best when you have
  a clean reference image of the same Windows build.
- **Data-stacking mode** — frequency-of-occurrence analysis across MANY
  images in a directory. Items that appear in only one or two images bubble
  to the top. Best when you don't have a golden image but you have a fleet
  of similar hosts and you want to find outliers.

> Both images should be the same Windows version when possible — the more
> attributes you can confidently compare (`--imphash`, `--cmdline`, `--owner`,
> `--state`), the lower the false-positive rate.

**Output is tab-separated** per upstream README. Files are named `.tsv` so the
extension matches the content; LibreOffice / Excel / Timeline Explorer all
import TSV directly.

```bash
cd /path/to/case/

# Process comparison (-proc) — implicitly also walks DLLs
python3 /opt/volatility3/baseline.py \
  -proc \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/proc_baseline.tsv

# Driver comparison (-drv) — critical for rootkit detection
python3 /opt/volatility3/baseline.py \
  -drv \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/drv_baseline.tsv

# Service comparison (-svc)
python3 /opt/volatility3/baseline.py \
  -svc \
  -i <suspect.img> \
  --loadbaseline \
  --jsonbaseline <baseline.json> \
  -o ./analysis/memory/svc_baseline.tsv
```

> **IMPORTANT:** `--loadbaseline` is a standalone boolean flag. `--jsonbaseline <path>` is the
> separate argument that specifies the JSON file path. They must both be present when loading
> an existing baseline.

**Creating a new JSON baseline from a known-good image:**
```bash
python3 /opt/volatility3/baseline.py \
  -proc \
  -i <clean-baseline.img> \
  --savebaseline \
  --jsonbaseline <output_baseline.json>
```

**Comparison mode flags (what attributes to diff):**
| Flag | Description |
|------|-------------|
| `--imphash` | Also compare import hashes (process/DLL/driver) |
| `--owner` | Also compare process owner (username/SID) — `-proc` and `-svc` |
| `--cmdline` | Also compare full command line — `-proc` |
| `--state` | Also compare service state — `-svc` |
| `--showknown` | Include KNOWN items in the output (default: only UNKNOWN) |

**Data-stacking flags (frequency of occurrence across `-d <dir>`):**

Use these instead of `-proc/-drv/-svc` when you have a directory of multiple
images and want to surface items that appear in only one or two of them.

| Flag | Description |
|------|-------------|
| `-procstack` | Stack-rank processes across all images in `-d` |
| `-dllstack` | Stack-rank DLLs across all images |
| `-drvstack` | Stack-rank drivers (rootkit-detection sweep) |
| `-svcstack` | Stack-rank services |

Stacking example:
```bash
# Process FoO across a fleet of memory images — outliers appear at the top
python3 /opt/volatility3/baseline.py \
  -procstack \
  -d /cases/fleet/memory/ \
  -o ./analysis/memory/proc_stack.tsv

# DLL FoO with import-hash comparison (catches same-name DLL with different
# bytes — classic DLL hijacking / sideloading signature)
python3 /opt/volatility3/baseline.py \
  -dllstack --imphash \
  -d /cases/fleet/memory/ \
  -o ./analysis/memory/dll_stack.tsv
```

**All Baseliner flags:**
| Flag | Description |
|------|-------------|
| `-proc` | Compare processes and loaded DLLs |
| `-drv` | Compare kernel drivers (rootkit detection) |
| `-svc` | Compare services |
| `--loadbaseline` | Load mode (boolean — use with `--jsonbaseline`) |
| `--jsonbaseline <file>` | Path to JSON baseline file (load or save) |
| `--savebaseline` | Save new baseline from this image |
| `--showknown` | Include baseline-matching items (verbose output) |
| `-o <file>` | Output TSV path |
