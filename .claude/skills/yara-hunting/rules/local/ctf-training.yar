// Project-library CTF training rules — fire on common flag formats used in
// capture-the-flag exercises (DEF CON, picoCTF, CCDC, etc).
//
// Use this file ONLY when the case is a CTF / training engagement. It will
// produce false positives on legitimate text containing the literal "flag{".
//
// Provenance: case7 (DEF CON 19 CTF PCAP survey).

rule Local_CTF_Flag_Format : file pcap_payload memory sev_info recon
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Common CTF flag formats (flag{}, ctf{}, key{}, token{}, DEFCON{}, dc{})"
        severity    = "informational"
        scope       = "both"
        reference   = "case7 DC19 CTF; common CTF conventions"

    strings:
        $f1  = "flag{"   nocase ascii
        $f2  = "ctf{"    nocase ascii
        $f3  = "key{"    nocase ascii
        $f4  = "token{"  nocase ascii
        $f5  = "FLAG{"          ascii
        $f6  = "CTF{"           ascii
        $f7  = "DEFCON{" nocase ascii
        $f8  = "dc{"     nocase ascii
        $f9  = "dcf{"    nocase ascii
        $f10 = /flag[_-]?[0-9a-f]{8,}/

    condition:
        any of them
}
