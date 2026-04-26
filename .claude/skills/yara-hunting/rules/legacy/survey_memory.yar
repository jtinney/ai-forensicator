// Survey rules for WinXP memory image — cheap, high-signal
// Author: DFIR Surveyor | Case: CASE6 | Date: 2026-04-22

rule Shellcode_XOR_Decoder {
    meta:
        description = "Common XOR decode loop pattern in shellcode"
        reference   = "CASE6/EV05"
    strings:
        $xor1 = { 30 [1-2] 40 [0-3] 75 }   // xor [reg], reg; inc; jnz
        $xor2 = { 31 [1-2] 83 [1-2] 01 75 } // xor [mem], reg; add; jnz
        $xor3 = { 80 3? ?? 74 ?? 30 ?? 43 } // cmp; jz; xor; inc loop
    condition:
        any of them
}

rule Metasploit_Strings {
    meta:
        description = "Metasploit payload / stager strings in memory"
        reference   = "CASE6/EV05"
    strings:
        $msfpayload  = "msfpayload" nocase ascii wide
        $meterpreter = "meterpreter" nocase ascii wide
        $msf_env     = "PAYLOAD_UUID" ascii wide
        $msf_hdr     = "MSFRE" ascii
        $reverse_tcp = "windows/shell/reverse_tcp" nocase ascii wide
        $bind_tcp    = "windows/shell/bind_tcp" nocase ascii wide
    condition:
        any of them
}

rule Suspicious_Cmd_Strings {
    meta:
        description = "Suspicious cmd execution patterns in memory"
        reference   = "CASE6/EV05"
    strings:
        $net_use   = "net use \\\\" nocase wide ascii
        $net_user  = "net user /add" nocase wide ascii
        $net_admin = "net localgroup administrators" nocase wide ascii
        $tftp      = "tftp -i" nocase wide ascii
        $certutil  = "certutil -decode" nocase wide ascii
        $echo_ps   = "powershell -e" nocase wide ascii
        $vbs_exec  = "wscript.exe" nocase wide ascii
    condition:
        any of them
}

rule Suspicious_Network_Strings {
    meta:
        description = "Embedded IP/URL patterns suggesting C2 or staging"
        reference   = "CASE6/EV05"
    strings:
        $ftp_cmd   = "ftp://" nocase wide ascii
        $http_exe  = /https?:\/\/[^\x00]{4,64}\.(exe|dll|dat|bin|pl|vbs|bat)/  nocase
        $paste_url = /pastebin\.(com|ca)/ nocase
        $ngrok     = "ngrok" nocase wide ascii
        $irc_cmd   = /JOIN\s+#[a-zA-Z0-9_-]{3,30}/ // IRC botnet channel join
        $raw_ip    = /CONNECT\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/
    condition:
        any of them
}

rule Known_RAT_Strings {
    meta:
        description = "Strings associated with common Windows RATs of the 2005 era"
        reference   = "CASE6/EV05"
    strings:
        $beast      = "Beast" wide ascii
        $bifrost    = "Bifrost" nocase wide ascii
        $sub7       = "SubSeven" nocase wide ascii
        $darkcomet  = "DarkComet" nocase wide ascii
        $poison_ivy = "Poison Ivy" nocase wide ascii
        $netbus     = "NetBus" nocase wide ascii
        $back_orf   = "Back Orifice" nocase wide ascii
        $bofs       = "BO2K" wide ascii
        $optix      = "Optix" nocase wide ascii
        $nuclear     = "NuclearRAT" nocase wide ascii
    condition:
        any of them
}

rule Rootkit_Strings {
    meta:
        description = "Rootkit / DKOM / SSDT hook strings in memory"
        reference   = "CASE6/EV05"
    strings:
        $ssdt       = "SSDT" ascii wide
        $dkom       = "DKOM" ascii wide
        $hxdef      = "Hacker Defender" nocase ascii wide
        $hxdef2     = "hxdef" nocase ascii wide
        $fu_rootkit = "\\\\Device\\\\PhysicalMemory" wide
        $iat_hook   = "IAT Hook" nocase ascii
        $nt_hooks   = "NtOpenProcess" ascii wide
    condition:
        2 of them
}

rule WinXP_Suspicious_PE_InMemory {
    meta:
        description = "Possible injected PE in memory (MZ header with suspicious imports)"
        reference   = "CASE6/EV05"
    strings:
        $mz       = { 4D 5A }
        $pe       = { 50 45 00 00 }
        $vprotect = "VirtualProtect" wide ascii
        $valloc   = "VirtualAlloc" wide ascii
        $creatert = "CreateRemoteThread" wide ascii
        $writepvm = "WriteProcessMemory" wide ascii
        $loadlib  = "LoadLibraryA" wide ascii
    condition:
        $mz at 0 and $pe and ($creatert or ($valloc and $writepvm))
}

rule Encoded_Payload_Pattern {
    meta:
        description = "Long base64 blob or hex-encoded payload in memory"
        reference   = "CASE6/EV05"
    strings:
        $b64_long = /[A-Za-z0-9+\/]{100,}={0,2}/
        $hex_blob = /([0-9a-fA-F]{2}){50,}/
    condition:
        $b64_long or $hex_blob
}

rule LSASS_Credential_Dump {
    meta:
        description = "lsass credential dumping strings"
        reference   = "CASE6/EV05"
    strings:
        $mimikatz   = "mimikatz" nocase wide ascii
        $sekurlsa   = "sekurlsa" nocase wide ascii
        $wdigest    = "wdigest" nocase wide ascii
        $kerberos_d = "kerberos::list" nocase wide ascii
        $pwdump     = "pwdump" nocase wide ascii
        $cachedump  = "cachedump" nocase wide ascii
        $fgdump     = "fgdump" nocase wide ascii
    condition:
        any of them
}
