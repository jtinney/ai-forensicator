// YARA rules for CASE6 EV02 survey sweep — boomer-win2003-2006-03-17.img
// Author: Claude Code DFIR Surveyor
// Date: 2026-04-22

rule Suspicious_CoolCat_IRC_Bot
{
    meta:
        description = "Detects CoolCat IRC bot strings observed in EV02 memory"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $s1 = "coolcat.exe" nocase ascii wide
        $s2 = "CChat.exe" nocase ascii wide
        $s3 = "cchat" nocase ascii wide

    condition:
        any of them
}

rule Suspicious_FTP_Client_In_Memory
{
    meta:
        description = "Detects CuteFTP or generic FTP client strings in memory — potential exfil tool"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $s1 = "cutftp32.exe" nocase ascii wide
        $s2 = "CuteFTP" nocase ascii wide

    condition:
        any of them
}

rule Suspicious_Mobsync_Abuse
{
    meta:
        description = "mobsync.exe in memory — could be LOLBin abuse or persistence masquerading"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $s1 = "mobsync.exe" ascii wide

    condition:
        $s1
}

rule Suspicious_RWX_PE_Injection
{
    meta:
        description = "MZ header in non-standard location — possible injected PE or shellcode loader"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $mz       = { 4D 5A 90 00 }
        $shell32  = "This program cannot be run in DOS mode" nocase
        $ntstub   = "PE\x00\x00" ascii

    condition:
        $mz and $shell32 and $ntstub
}

rule Suspicious_Cmd_Execution_Pattern
{
    meta:
        description = "cmd.exe /c pattern suggesting command execution from unusual context"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $cmd_c  = "cmd.exe /c" nocase ascii wide
        $cmd_k  = "cmd.exe /k" nocase ascii wide
        $cmd_r  = "cmd /c" nocase ascii wide

    condition:
        any of them
}

rule Suspicious_WMPlayer_In_Process_List
{
    meta:
        description = "wmplayer.exe — high frequency in proc strings; may be masquerade or LOLBin"
        author = "DFIR Surveyor"
        date = "2026-04-22"
        reference = "CASE6-EV02 survey"

    strings:
        $s1 = "wmplayer.exe" ascii wide nocase

    condition:
        $s1
}
