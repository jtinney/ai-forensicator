rule Shellcode_NOP_Sled
{
    meta:
        description = "Large NOP sled indicative of shellcode"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule Suspicious_CMD_Strings
{
    meta:
        description = "Suspicious command strings often used by malware"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $cmd1 = "cmd.exe /c" nocase ascii wide
        $cmd2 = "cmd.exe /k" nocase ascii wide
        $nc   = "nc.exe" nocase ascii wide
        $tftp = "tftp " nocase ascii wide
        $ftp_get = "ftp -s:" nocase ascii wide
        $wget = "wget " nocase ascii
        $curl = "curl " nocase ascii
    condition:
        any of them
}

rule Metasploit_Meterpreter_Strings
{
    meta:
        description = "Meterpreter / Metasploit payload strings in memory"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $s1 = "meterpreter" nocase ascii wide
        $s2 = "Meterpreter" ascii
        $s3 = "ReflectiveDll" ascii wide
        $s4 = "PAYLOAD_" ascii
        $s5 = "exploit/multi" ascii
    condition:
        any of them
}

rule Netcat_Reverse_Shell
{
    meta:
        description = "Netcat usage patterns suggesting reverse shell"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $nc1 = "nc -e" nocase ascii
        $nc2 = "nc.exe -l" nocase ascii wide
        $nc3 = "-e cmd.exe" nocase ascii wide
        $nc4 = "-e /bin/sh" nocase ascii
    condition:
        any of them
}

rule Suspicious_Registry_Persistence
{
    meta:
        description = "Common registry autorun paths used for persistence"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $r1 = "CurrentVersion\\Run" ascii wide nocase
        $r2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $r3 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $r4 = "userinit.exe," ascii wide nocase
    condition:
        any of them
}

rule UPX_Packed
{
    meta:
        description = "UPX packer signature in memory"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX2" ascii
        $upx4 = { 55 50 58 21 }
    condition:
        any of ($upx*)
}

rule IRC_Bot_Strings
{
    meta:
        description = "IRC bot command strings often found in botnets"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $irc1 = "PRIVMSG" ascii
        $irc2 = "NICK " ascii
        $irc3 = "JOIN #" ascii
        $irc4 = ".advscan" ascii nocase
        $irc5 = ".portscan" ascii nocase
        $irc6 = ".download" ascii nocase
        $bot1 = "!download" ascii nocase
        $bot2 = "!execute" ascii nocase
    condition:
        2 of them
}

rule Suspicious_Net_Commands
{
    meta:
        description = "Lateral movement / recon commands in memory"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $n1 = "net user /add" nocase ascii wide
        $n2 = "net localgroup administrators" nocase ascii wide
        $n3 = "net share" nocase ascii wide
        $n4 = "ipconfig /all" nocase ascii wide
        $n5 = "whoami" nocase ascii wide
        $n6 = "net view" nocase ascii wide
    condition:
        2 of them
}

rule Base64_Long_Blob
{
    meta:
        description = "Unusually long Base64 blob — possible encoded payload"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        $b64
}

rule LSASS_Credential_Dumping_Strings
{
    meta:
        description = "Strings associated with credential dumping from LSASS"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $s1 = "lsass.exe" nocase ascii wide
        $s2 = "sekurlsa" nocase ascii
        $s3 = "wdigest" nocase ascii
        $s4 = "kerberos" nocase ascii
        $s5 = "mimikatz" nocase ascii wide
        $s6 = "logonpasswords" nocase ascii
    condition:
        2 of them
}

rule Rootkit_Driver_Strings
{
    meta:
        description = "Strings indicative of rootkit or malicious driver activity"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $r1 = "\\Device\\PhysicalMemory" ascii wide
        $r2 = "\\DosDevices\\" ascii wide
        $r3 = "ZwSetSystemInformation" ascii
        $r4 = "PsSetLoadImageNotifyRoutine" ascii
        $r5 = "NtWriteVirtualMemory" ascii
        $r6 = "ObReferenceObjectByName" ascii
    condition:
        2 of them
}

rule Suspicious_Download_URLs
{
    meta:
        description = "HTTP/FTP download URLs in memory"
        author = "DFIR Surveyor"
        date = "2026-04-22"
    strings:
        $u1 = "http://" ascii nocase
        $u2 = "ftp://" ascii nocase
        $u3 = ".exe" ascii nocase
        $u4 = "download" ascii nocase
    condition:
        ($u1 or $u2) and $u3 and $u4
}
