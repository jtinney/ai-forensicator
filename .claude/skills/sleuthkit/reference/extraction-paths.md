# Targeted Artifact Extraction — Reference

Once an image is mounted (or the `.E01` is being read directly via TSK), use
these recipes to pull artifacts the Windows skill needs as parsed input.
Output goes to `./exports/<artifact-type>/`. Run only what the case asks for —
copying every artifact category on every case wastes time and disk.

```bash
# Windows event logs
sudo find /mnt/windows_mount/Windows/System32/winevt/Logs/ -name "*.evtx" \
  -exec cp {} ./exports/evtx/ \;

# Registry hives
for hive in SYSTEM SOFTWARE SECURITY SAM; do
  sudo cp /mnt/windows_mount/Windows/System32/config/$hive ./exports/registry/
done

# User NTUSER.DAT hives (all users)
sudo find /mnt/windows_mount/Users/ -name "NTUSER.DAT" \
  -exec cp --parents {} ./exports/registry/ \;

# UsrClass.dat (shellbags, file associations — in each user's Local profile)
sudo find /mnt/windows_mount/Users/ -name "UsrClass.dat" \
  -exec cp --parents {} ./exports/registry/ \;

# Prefetch files
sudo mkdir -p ./exports/prefetch/
sudo cp -r /mnt/windows_mount/Windows/Prefetch/ ./exports/prefetch/

# MFT (inode 0 on NTFS)
sudo icat /mnt/ewf/ewf1 0 > ./exports/mft/\$MFT

# UsnJrnl (inode 11 on NTFS) — $J data stream contains the change journal
sudo icat /mnt/ewf/ewf1 11-128-4 > ./exports/mft/\$J 2>/dev/null || \
sudo icat /mnt/ewf/ewf1 11 > ./exports/mft/\$J

# Amcache
sudo cp /mnt/windows_mount/Windows/AppCompat/Programs/Amcache.hve ./exports/registry/

# SRUM database
sudo mkdir -p ./exports/srum/
sudo cp /mnt/windows_mount/Windows/System32/sru/SRUDB.dat ./exports/srum/

# Browser profiles (Chrome/Edge)
sudo find /mnt/windows_mount/Users/ \
  -path "*/Google/Chrome/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;
sudo find /mnt/windows_mount/Users/ \
  -path "*/Microsoft/Edge/User Data/Default/History" \
  -exec cp --parents {} ./exports/browser/ \;

# Recycle Bin
sudo cp -r "/mnt/windows_mount/\$Recycle.Bin/" ./exports/recyclebin/

# Scheduled tasks (XML definitions)
sudo cp -r /mnt/windows_mount/Windows/System32/Tasks/ ./exports/tasks/

# PowerShell transcript logs (if enabled)
sudo find /mnt/windows_mount/Users/ -name "PowerShell_transcript*.txt" \
  -exec cp --parents {} ./exports/pslogs/ \;
```

**Disk-image (TSK-direct, no mount) variants** for the same artifact types
live in `windows-artifacts/SKILL.md` § "Fallback workflow (Tier 2/3)". Use
those when `ewfmount` + loopback aren't available.
