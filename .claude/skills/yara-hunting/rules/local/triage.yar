// Project-library triage rules — broadly reusable across cases.
//
// Each rule conforms to the project metadata convention documented in
// `.claude/skills/yara-hunting/SKILL.md` § Rule conventions.
//
// FP-tested against /usr/bin (Ubuntu 22.04 SIFT base) on 2026-04-26.
// Re-test before promoting any new rule to this file.

rule Local_Triage_Shellcode_NOP_Sled : memory file sev_low loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Long NOP sled common in older shellcode payloads"
        severity    = "low"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1055"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        $nop16
}

rule Local_Triage_Suspicious_CMD_Exec : memory file sev_info script_cmd
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "cmd.exe invocation strings — informational, expect benign hits in dev tooling"
        severity    = "informational"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1059.003"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "cmd.exe /c" nocase wide ascii
        $b = "cmd /c"     nocase wide ascii
        $c = "cmd.exe /k" nocase wide ascii

    condition:
        any of them
}

rule Local_Triage_Powershell_Suspicious : memory file sev_medium script_ps1
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "PowerShell encoded command, download cradle, or IEX invocation"
        severity    = "medium"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1059.001,T1027"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $enc1 = "EncodedCommand" nocase wide ascii
        $enc2 = "-enc "          nocase wide ascii
        $dl1  = "DownloadString" nocase wide ascii
        $dl2  = "IEX"            wide ascii fullword
        $iex  = "Invoke-Expression" nocase wide ascii

    condition:
        any of them
}

rule Local_Triage_Reverse_Shell_Indicators : memory file sev_high implant
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Three or more co-occurring reverse-shell indicator strings"
        severity    = "high"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1059.004"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "socket"   nocase wide ascii
        $b = "connect"  nocase wide ascii
        $c = "/bin/sh"  nocase wide ascii
        $d = "bash -i"  nocase wide ascii
        $e = "nc -e"    nocase wide ascii

    condition:
        3 of them
}

rule Local_Triage_Run_Key_Persistence_Path : memory file sev_low persistence
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Registry Run / Winlogon / Services key paths — informational, expect benign hits in registry hive raw scans"
        severity    = "low"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1547.001"

    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $run2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase wide ascii
        $run3 = "SYSTEM\\CurrentControlSet\\Services" nocase wide ascii

    condition:
        any of them
}

rule Local_Triage_Meterpreter_Indicators : memory file sev_critical implant family_meterpreter
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Metasploit Meterpreter payload indicator strings"
        severity    = "critical"
        scope       = "both"
        reference   = "https://github.com/rapid7/metasploit-payloads"
        mitre       = "T1055,T1059"
        family      = "meterpreter"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "metsrv.dll"        nocase wide ascii
        $b = "meterpreter"       nocase wide ascii
        $c = "ReflectiveLoader"  wide ascii
        $d = "LoadLibraryR"      wide ascii

    condition:
        any of them
}

rule Local_Triage_Process_Injection_Triad : memory file sev_high implant
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Two or more of the classic VirtualAllocEx / WriteProcessMemory / CreateRemoteThread injection triad in proximity"
        severity    = "high"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1055.001,T1055.002"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "VirtualAllocEx"     wide ascii
        $b = "WriteProcessMemory" wide ascii
        $c = "CreateRemoteThread" wide ascii

    condition:
        2 of them
}

rule Local_Triage_Credential_Harvesting_Strings : memory file sev_critical credaccess
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Two or more LSASS / Mimikatz / WDigest credential-harvesting strings"
        severity    = "critical"
        scope       = "both"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        mitre       = "T1003.001,T1003.002"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "sekurlsa"          nocase wide ascii
        $b = "mimikatz"          nocase wide ascii
        $c = "wdigest"           nocase wide ascii
        $d = "NtlmHashProvider"  nocase wide ascii
        $e = "logonPasswords"    nocase wide ascii

    condition:
        2 of them
}

rule Local_Triage_Suspicious_Staging_Path : memory file sev_info persistence
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Execution from Temp / AppData / ProgramData — informational staging-path indicator"
        severity    = "informational"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1074"
        fp_tested   = "2026-04-26"
        fp_target   = "/usr/bin"

    strings:
        $a = "\\Temp\\"                  nocase wide ascii
        $b = "\\AppData\\Roaming\\"      nocase wide ascii
        $c = "\\AppData\\Local\\Temp\\"  nocase wide ascii
        $d = "\\ProgramData\\"           nocase wide ascii

    condition:
        any of them
}

rule Local_Triage_Long_Base64_Blob : memory file sev_low loader
{
    meta:
        author      = "ai-forensicator project library"
        date        = "2026-04-26"
        description = "Base64 string of length 80+ — common in encoded PowerShell, embedded payloads"
        severity    = "low"
        scope       = "both"
        reference   = "in-house"
        mitre       = "T1027,T1140"

    strings:
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/

    condition:
        $b64 and filesize < 200MB
}
