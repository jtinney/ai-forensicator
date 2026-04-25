# Case-specific Suricata / Zeek rules

Drop case-scoped detection rules here so they live under chain-of-custody.

| Filename pattern | Engine | Purpose |
|---|---|---|
| `*.rules` | Suricata | Custom signatures for indicators surfaced in a case |
| `*.zeek` | Zeek | Site policy or detection scripts (loaded with `-i`/`local`) |

**Don't commit third-party rule sets here.** Use `suricata-update` to manage
ET Open / community rules at the system level (`/var/lib/suricata/rules/`)
and keep this directory limited to rules authored *for this case*.

Reference the rules at runtime with explicit paths:

```bash
suricata -r ./evidence/case.pcap \
  -l ./analysis/network/suricata/ \
  -k none \
  -S .claude/skills/network-forensics/rules/case-specific.rules \
  -c /etc/suricata/suricata.yaml

zeek -C -r ./evidence/case.pcap \
  .claude/skills/network-forensics/rules/case-specific.zeek
```
