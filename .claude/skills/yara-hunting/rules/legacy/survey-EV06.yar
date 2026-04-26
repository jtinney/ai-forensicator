// Survey rules for EV06 — WinXP memory image (xp-laptop-2005-07-04-1430.img)
// Targeting cheap, high-signal indicators for common 2004-2006 era threats

rule WinXP_Suspicious_CmdExec
{
    meta:
        description = "Command execution strings typical in backdoors / droppers"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "cmd /c " nocase
        $cmd3 = "/c net user " nocase
        $cmd4 = "net localgroup administrators" nocase ascii wide
        $cmd5 = "at \\\\127.0.0.1" nocase
    condition:
        any of them
}

rule WinXP_Reverse_Shell_Indicators
{
    meta:
        description = "Strings associated with reverse shells or bind shells"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $nc1 = "nc -l -p" nocase
        $nc2 = "netcat" nocase
        $r1  = "SHELL=/bin/sh" nocase
        $r2  = "exec /bin/sh" nocase
        $r3  = "/bin/bash -i" nocase
        $p1  = "WSASocket" nocase
        $p2  = "CreateRemoteThread" nocase ascii wide
    condition:
        any of them
}

rule WinXP_Exploit_Shellcode_Nops
{
    meta:
        description = "NOP sled patterns common in heap/stack shellcode"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $nop32 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop16 = { 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }
    condition:
        any of them
}

rule WinXP_Rootkit_DKOM_Indicators
{
    meta:
        description = "Strings associated with DKOM rootkits common 2004-2006 (Hacker Defender, FU, etc.)"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $h1 = "HackerDefender" nocase
        $h2 = "hxdef" nocase
        $fu = "FU rootkit" nocase
        $d1 = "\\\\Device\\\\PhysicalMemory" nocase wide ascii
        $d2 = "ZwSystemDebugControl" nocase
        $d3 = "PsGetNextProcess" nocase
        $k2 = "DKOM" nocase
        $r1 = "HideProcess" nocase
    condition:
        any of ($h1, $h2, $fu, $d1, $d2, $d3, $k2, $r1)
}

rule WinXP_RAT_Backdoor_Strings
{
    meta:
        description = "RAT / backdoor strings common in 2004-2006 era tools (SubSeven, Poison Ivy, Beast, etc.)"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $s1 = "SubSeven" nocase
        $s2 = "Poison Ivy" nocase
        $s3 = "Beast" nocase
        $s4 = "Bifrost" nocase
        $s5 = "ProRat" nocase
        $s6 = "Optix" nocase
        $s7 = "NetBus" nocase
        $s8 = "BO2K" nocase
        $s9 = "Back Orifice" nocase
        $s10 = "njRAT" nocase
        $d1 = "RECVTIMEOUT" nocase
        $d2 = "SERVER_ID" nocase
        $d3 = "MUTEX_KEY" nocase
    condition:
        any of them
}

rule WinXP_IRC_Bot_Indicators
{
    meta:
        description = "IRC bot command strings (sdbot, rxbot, phatbot era)"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $i1 = "PRIVMSG #" nocase
        $i2 = "JOIN #" nocase
        $i3 = "NICK " nocase
        $i4 = "PASS " nocase
        $b1 = ".advscan" nocase
        $b2 = ".download" nocase
        $b3 = ".execute" nocase
        $b4 = ".flood" nocase
        $b5 = ".ddos" nocase
        $b6 = "phatbot" nocase
        $b7 = "sdbot" nocase
        $b8 = "agobot" nocase
        $b9 = "rxbot" nocase
    condition:
        2 of ($i*) or any of ($b*)
}

rule WinXP_Credential_Theft
{
    meta:
        description = "Password / credential harvesting strings"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $p4 = "pwdump" nocase
        $p5 = "fgdump" nocase
        $p6 = "cachedump" nocase
        $p7 = "gsecdump" nocase
        $p8 = "wce.exe" nocase
        $p9 = "mimikatz" nocase
    condition:
        any of ($p4, $p5, $p6, $p7, $p8, $p9)
}

rule WinXP_Exploit_Tools
{
    meta:
        description = "Known exploit tool strings for WinXP era (Metasploit, MS04/MS05 exploits)"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $m1 = "Metasploit" nocase
        $m2 = "meterpreter" nocase
        $e1 = "ms04-011" nocase
        $e2 = "ms05-039" nocase
        $e3 = "ms03-026" nocase
        $e4 = "LSASS exploit" nocase
        $e5 = "ASN1 exploit" nocase
    condition:
        any of them
}

rule WinXP_Suspicious_NetworkStrings
{
    meta:
        description = "Suspicious outbound network / C2 patterns"
        author = "DFIR-Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV06"
    strings:
        $u1 = "update.php?" nocase
        $u2 = "/gate.php" nocase
        $u3 = "/bot.php" nocase
        $u4 = "/panel/" nocase
        $u5 = "bot_id=" nocase
        $u6 = "GET /cgi-bin/update" nocase
        $p1 = "HTTP/1.0" fullword nocase
        $p2 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" nocase
    condition:
        any of ($u*) or (2 of ($p*))
}
