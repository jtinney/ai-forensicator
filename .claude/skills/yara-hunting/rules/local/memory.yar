// Project-library memory-image rules — tuned for raw memory dumps.
//
// These fire on patterns common to mapped executable regions, injected code,
// and on-host strings that survive in non-paged memory. All are scoped to
// `memory` (do not run on disk dumps unless you understand the FP profile).

import "math"

rule Local_Memory_PE_Header_Signature : memory sev_low pe loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "PE header (MZ + DOS stub + PE signature) — flags every mapped executable region. Use as a region-density indicator, not as a malicious hit."
        severity    = "low"
        scope       = "memory"
        reference   = "in-house"

    strings:
        $mz_pe = { 4D 5A 90 00 03 00 00 00 [60-200] 50 45 00 00 }

    condition:
        $mz_pe
}

rule Local_Memory_RWX_Inj_Stub : memory sev_high implant
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Co-occurrence of MZ header, DOS stub message, and PE\\x00\\x00 signature in close proximity — likely mapped/injected PE in process memory"
        severity    = "high"
        scope       = "memory"
        reference   = "in-house"
        mitre       = "T1055.002"

    strings:
        $mz       = { 4D 5A 90 00 }
        $shell32  = "This program cannot be run in DOS mode"
        $ntstub   = "PE\x00\x00"

    condition:
        $mz and $shell32 and $ntstub
}

rule Local_Memory_HTTP_C2_Indicator_Bundle : memory sev_medium c2
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Two or more HTTP-C2 indicator strings in memory (UA + verb + scheme)"
        severity    = "medium"
        scope       = "memory"
        reference   = "in-house"
        mitre       = "T1071.001"

    strings:
        $ua    = "Mozilla/" nocase wide ascii
        $get   = "GET /"  wide ascii
        $post  = "POST /" wide ascii
        $http  = "http://"  nocase wide ascii
        $https = "https://" nocase wide ascii

    condition:
        2 of them
}

rule Local_Memory_Named_Pipe_Beacon_Like : memory sev_medium c2 family_cobaltstrike
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "SMB-pipe naming pattern resembling default Cobalt Strike beacon pipe names"
        severity    = "medium"
        scope       = "memory"
        reference   = "https://www.cobaltstrike.com/"
        mitre       = "T1071.002,T1572"
        family      = "cobaltstrike"

    strings:
        $p1 = "\\\\.\\pipe\\msagent_"   nocase wide ascii
        $p2 = "\\\\.\\pipe\\status_"    nocase wide ascii
        $p3 = "\\\\.\\pipe\\postex_"    nocase wide ascii
        $p4 = "\\\\.\\pipe\\mojo."      nocase wide ascii

    condition:
        any of them
}

rule Local_Memory_High_Entropy_Block : memory sev_low loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "First 8 KB of a memory page has Shannon entropy > 7.5 — likely packed / encrypted region"
        severity    = "low"
        scope       = "memory"
        reference   = "in-house"
        mitre       = "T1027.002"

    condition:
        filesize > 8192 and math.entropy(0, 8192) > 7.5
}
