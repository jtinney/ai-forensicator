// Project-library network-payload rules — fire on patterns common to PCAP
// payload bodies, raw TCP streams, and L7-extracted blobs (HTTP body, FTP
// data channel, etc).
//
// Provenance: derived from case7 (DEF CON 19 CTF PCAP survey, 2026-04-25)
// rules and refactored to the project metadata convention. Each rule was
// FP-tested against /usr/bin (Ubuntu 22.04 SIFT base) on 2026-04-26.
//
// Scope: most rules here are useful against memory and disk too, but the
// noise profile changes — re-test before pivoting them outside pcap_payload.

rule Local_Network_Shellcode_NOP_Or_AAAA : pcap_payload memory sev_medium loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "NOP sled or AAAA (0x41) padding sled common in exploit payloads"
        severity    = "medium"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1203,T1059"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $aaaa  = { 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }

    condition:
        any of them
}

rule Local_Network_Embedded_PE_Drop : pcap_payload sev_high loader pe
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "PE header + DOS stub message inside a network payload — file transfer or exploit drop"
        severity    = "high"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1105"

    strings:
        $mz      = { 4D 5A 90 00 }
        $pe_stub = "This program cannot be run in DOS mode"

    condition:
        $mz and $pe_stub
}

rule Local_Network_Embedded_ELF_Drop : pcap_payload sev_high loader elf
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "ELF magic anchored at offset 0 of a payload extract — Linux binary transfer"
        severity    = "high"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1105"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0
}

rule Local_Network_Reverse_Shell_Linux : pcap_payload memory sev_high implant
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Linux reverse / bind shell indicator strings"
        severity    = "high"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1059.004"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $sh1 = "/bin/sh"        ascii
        $sh2 = "/bin/bash"      ascii
        $sh3 = "bash -i"        nocase ascii
        $sh4 = "exec /bin/sh"   ascii
        $sh5 = "SHELL=/bin/bash" ascii
        $sh6 = "nc -e /bin/sh"  ascii
        $sh7 = "nc -e /bin/bash" ascii

    condition:
        any of them
}

rule Local_Network_Oneliner_Reverse_Shell : pcap_payload memory sev_high implant
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Scripted reverse-shell one-liners (python / perl / ruby / bash redirect)"
        severity    = "high"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1059.004,T1059.006"

    strings:
        $py1 = "python -c 'import socket"  ascii
        $py2 = "python3 -c 'import socket" ascii
        $pl1 = "perl -e 'use Socket"        ascii
        $rb1 = "ruby -rsocket -e"           ascii
        $sh1 = "bash -i >& /dev/tcp/"       ascii
        $sh2 = "0>&1"                       ascii

    condition:
        any of ($py1, $py2, $pl1, $rb1, $sh1) or
        ($sh2 and any of ($sh1, $py1, $py2))
}

rule Local_Network_Exploit_Return_Address_Patterns : pcap_payload sev_medium loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Classic exploit ROP / format-string payload signatures"
        severity    = "medium"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1203"

    strings:
        $aabb  = { 41 41 41 41 42 42 42 42 }
        $fmt_n = { 25 6E 25 6E 25 6E 25 6E }
        $fmt_x = "%x%x%x%x" ascii
        $fmt_p = "%p%p%p%p" ascii

    condition:
        any of them
}

rule Local_Network_HTTP_Exploit_Patterns : pcap_payload sev_high recon
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Common HTTP-borne exploit patterns — SQLi, path traversal, command injection, LFI"
        severity    = "high"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1190"

    strings:
        $sqli1 = "' OR '1'='1"      nocase ascii
        $sqli2 = "UNION SELECT"      nocase ascii
        $sqli3 = "1=1--"             nocase ascii
        $trav1 = "../../../etc/passwd" ascii
        $trav2 = "....//....//etc/passwd" ascii
        $cmdi1 = ";cat /etc/passwd"  nocase ascii
        $cmdi2 = "|id;"              ascii
        $cmdi3 = "`id`"              ascii
        $lfi1  = "/etc/passwd"       ascii
        $lfi2  = "/etc/shadow"       ascii

    condition:
        any of them
}

rule Local_Network_Distcc_Command_Injection : pcap_payload sev_critical c2 family_distcc
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "distcc ARGV command injection (CVE-2004-2687) — DIST/ARGC/ARGV preamble"
        severity    = "critical"
        scope       = "file"
        reference   = "https://nvd.nist.gov/vuln/detail/CVE-2004-2687"
        mitre       = "T1190"
        family      = "distcc"

    strings:
        $d1 = "DIST"   ascii
        $d2 = "ARGC"   ascii
        $d3 = "ARGV"   ascii
        $d4 = "distcc" nocase ascii

    condition:
        ($d1 and $d2 and $d3) or $d4
}

rule Local_Network_Metasploit_Payload_Strings : pcap_payload memory sev_high implant family_metasploit
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Metasploit payload, stager, or handler strings"
        severity    = "high"
        scope       = "both"
        reference   = "https://github.com/rapid7/metasploit-framework"
        mitre       = "T1071,T1059"
        family      = "metasploit"

    strings:
        $m1 = "Meterpreter"           nocase ascii
        $m2 = "metsrv"                nocase ascii
        $m3 = "EXITFUNC=thread"       nocase ascii
        $m4 = "EXITFUNC=process"      nocase ascii
        $m5 = "/multi/handler"        nocase ascii
        $m6 = "exploit/multi"         nocase ascii
        $m7 = "windows/shell_reverse_tcp" nocase ascii
        $m8 = "linux/x86/shell"       nocase ascii
        $m9 = "linux/x64/shell"       nocase ascii

    condition:
        any of them
}

rule Local_Network_IRC_Botnet_Commands : pcap_payload memory sev_medium c2
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "IRC botnet command verbs (.download / .execute / .flood / .ddos) or 2x channel-traffic markers"
        severity    = "medium"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1071.001,T1059"

    strings:
        $i1 = "PRIVMSG #" ascii
        $i2 = "JOIN #"    ascii
        $i3 = ".download" ascii
        $i4 = ".execute"  ascii
        $i5 = ".flood"    ascii
        $i6 = ".ddos"     ascii

    condition:
        any of ($i3, $i4, $i5, $i6) or (2 of ($i1, $i2))
}

rule Local_Network_DNS_Tunneling_Tools : pcap_payload memory sev_high c2
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "DNS tunneling tool name strings (iodine / dns2tcp / dnscat)"
        severity    = "high"
        scope       = "both"
        reference   = "in-house, case7"
        mitre       = "T1071.004,T1572"

    strings:
        $iodine  = "iodine"  nocase ascii
        $dns2tcp = "dns2tcp" nocase ascii
        $dnscat  = "dnscat"  nocase ascii

    condition:
        any of them
}

rule Local_Network_PCAP_Magic_Bytes : file sev_info
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "PCAP / pcapng magic at offset 0 — sanity rule, confirms a file is a packet capture"
        severity    = "informational"
        scope       = "file"
        reference   = "in-house"

    strings:
        $pcap_le = { D4 C3 B2 A1 }
        $pcap_be = { A1 B2 C3 D4 }
        $pcapng  = { 0A 0D 0D 0A }

    condition:
        $pcap_le at 0 or $pcap_be at 0 or $pcapng at 0
}

rule Local_Network_Heap_Spray_Patterns : pcap_payload memory sev_medium loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Classic heap-spray dword sequences (0x0c0c0c0c, 0xdeadbeef)"
        severity    = "medium"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1203"

    strings:
        $hs_0c = { 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C }
        $hs_de = { DE AD BE EF DE AD BE EF DE AD BE EF DE AD BE EF }

    condition:
        any of them
}
