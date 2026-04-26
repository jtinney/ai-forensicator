// Survey triage rules for CASE6 EV04 — Vista Beta 2 memory image
// Cheap, high-signal rules targeting common attacker TTPs in memory

rule Shellcode_NOP_Sled
{
    meta:
        description = "NOP sled pattern common in shellcode"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop
}

rule Suspicious_CMD_Exec
{
    meta:
        description = "Suspicious cmd.exe invocation strings in memory"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "cmd.exe /c" nocase wide ascii
        $b = "cmd /c" nocase wide ascii
        $c = "cmd.exe /k" nocase wide ascii
    condition:
        any of them
}

rule Powershell_Suspicious
{
    meta:
        description = "PowerShell encoded command or download cradle in memory"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $enc   = "EncodedCommand" nocase wide ascii
        $enc2  = "-enc " nocase wide ascii
        $dl    = "DownloadString" nocase wide ascii
        $dl2   = "IEX" wide ascii
        $iex   = "Invoke-Expression" nocase wide ascii
    condition:
        any of them
}

rule Reverse_Shell_Strings
{
    meta:
        description = "Common reverse/bind shell indicator strings"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "socket" nocase wide ascii
        $b = "connect" nocase wide ascii
        $c = "/bin/sh" nocase wide ascii
        $d = "bash -i" nocase wide ascii
        $e = "nc -e" nocase wide ascii
    condition:
        3 of them
}

rule Suspicious_Registry_Persistence
{
    meta:
        description = "Registry run key paths often used for persistence"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
        $run2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase wide ascii
        $run3 = "SYSTEM\\CurrentControlSet\\Services" nocase wide ascii
    condition:
        any of them
}

rule Suspicious_Network_Strings
{
    meta:
        description = "HTTP C2 beacon or download strings in memory"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $ua  = "Mozilla/" nocase wide ascii
        $get = "GET /" wide ascii
        $post = "POST /" wide ascii
        $http = "http://" nocase wide ascii
        $https = "https://" nocase wide ascii
    condition:
        2 of them
}

rule MZ_PE_In_Nonstandard_Location
{
    meta:
        description = "PE header found — match in memory image indicates mapped executable region"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $mz
}

rule Metasploit_Meterpreter_Strings
{
    meta:
        description = "Meterpreter / Metasploit payload indicator strings"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "metsrv.dll" nocase wide ascii
        $b = "meterpreter" nocase wide ascii
        $c = "ReflectiveLoader" wide ascii
        $d = "LoadLibraryR" wide ascii
        $e = "METERPRETER" wide ascii
    condition:
        any of them
}

rule Suspicious_Process_Injection
{
    meta:
        description = "VirtualAllocEx / WriteProcessMemory / CreateRemoteThread pattern — classic DLL injection triad"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "VirtualAllocEx" wide ascii
        $b = "WriteProcessMemory" wide ascii
        $c = "CreateRemoteThread" wide ascii
    condition:
        2 of them
}

rule Base64_Blob
{
    meta:
        description = "Long Base64-encoded string — potential encoded payload or C2 data"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/
    condition:
        $b64
}

rule Credential_Harvesting_Strings
{
    meta:
        description = "LSASS / credential harvesting indicator strings"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "lsass.exe" nocase wide ascii
        $b = "sekurlsa" nocase wide ascii
        $c = "mimikatz" nocase wide ascii
        $d = "wdigest" nocase wide ascii
        $e = "kerberos" nocase wide ascii
        $f = "NtlmHashProvider" nocase wide ascii
    condition:
        2 of them
}

rule Suspicious_Temp_Path
{
    meta:
        description = "Execution from Temp / AppData — common malware staging path"
        author      = "CASE6-surveyor"
        date        = "2026-04-22"
    strings:
        $a = "\\Temp\\" nocase wide ascii
        $b = "\\AppData\\Roaming\\" nocase wide ascii
        $c = "\\AppData\\Local\\Temp\\" nocase wide ascii
        $d = "%TEMP%" nocase wide ascii
    condition:
        any of them
}
