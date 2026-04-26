// Project-library cleartext-exfil rules — credential and shadow-content
// strings observed in unencrypted protocols (Telnet, FTP, plaintext HTTP)
// or staged for exfiltration.
//
// Provenance: derived from case7 (DEF CON 19 CTF PCAP survey, 2026-04-25)
// and refactored to the project metadata convention.

rule Local_Cleartext_Passwd_Or_Shadow_Content : pcap_payload file sev_high credaccess
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "/etc/passwd or /etc/shadow line prefixes — host credential file in transit / on disk in unexpected location"
        severity    = "high"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1003.008"

    strings:
        $pw_root_x = "root:x:0:0" ascii
        $pw_root_s = "root:*:"    ascii
        $pw_root_d = "root:!"     ascii
        $pw_daemon = "daemon:x:1" ascii
        $sh_md5    = "root:$1$"   ascii
        $sh_sha512 = "root:$6$"   ascii
        $sh_yescry = "root:$y$"   ascii

    condition:
        any of them
}

rule Local_Cleartext_Telnet_Login_Traffic : pcap_payload sev_medium credaccess
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Two or more Telnet login-prompt strings — cleartext credential exposure"
        severity    = "medium"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1040"

    strings:
        $t1 = "login: "          ascii
        $t2 = "Password: "       ascii
        $t3 = "Login incorrect"  ascii
        $t4 = "Last login:"      ascii

    condition:
        2 of them
}

rule Local_Cleartext_FTP_Credentials : pcap_payload sev_medium credaccess
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "FTP USER + PASS commands in cleartext"
        severity    = "medium"
        scope       = "file"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1040"

    strings:
        $u = /USER [a-zA-Z0-9_\-\.]{2,32}\r\n/ ascii
        $p = /PASS .{1,64}\r\n/                ascii

    condition:
        $u and $p
}

rule Local_Cleartext_SSH_Brute_Markers : pcap_payload sev_medium credaccess
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "SSH server log strings indicating brute-force activity (Failed password, Invalid user) or scripted-client banners (libssh, paramiko)"
        severity    = "medium"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1110.001,T1110.003"

    strings:
        $s1 = "Failed password for"   ascii
        $s2 = "Accepted password for" ascii
        $s3 = "Invalid user"          ascii
        $s4 = "SSH-2.0-libssh"        ascii
        $s5 = "SSH-2.0-paramiko"      ascii
        $s6 = "SSH-2.0-PUTTY"         nocase ascii

    condition:
        any of them
}

rule Local_Cleartext_Base64_Encoded_Shell_Cmd : pcap_payload memory sev_low loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Common short shell commands in base64 (bash, python, id, /bin/sh)"
        severity    = "low"
        scope       = "both"
        reference   = "case7 DC19 CTF, in-house"
        mitre       = "T1027,T1140"

    strings:
        $b1 = "YmFzaA=="     ascii    // "bash"
        $b2 = "cHl0aG9u"     ascii    // "python"
        $b3 = "aWQ="         ascii    // "id"
        $b4 = "L2Jpbi9zaA==" ascii    // "/bin/sh"

    condition:
        any of them
}
