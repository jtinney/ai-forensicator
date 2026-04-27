# Windows Event IDs — Reference

Reach for these tables when filtering EvtxECmd with `--inc <ids>`. The
channels are grouped by the EVTX file they live in. Use `--maps` with EvtxECmd
so payload fields decode into named columns.

## Logon / Authentication (`Security.evtx`)
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon — note LogonType (2=interactive, 3=network, 10=remote interactive) |
| 4625 | Failed logon |
| 4647 | User-initiated logoff |
| 4648 | Logon using explicit credentials (runas, PtH indicator) |
| 4672 | Special privileges assigned at logon (admin session) |
| 4776 | NTLM authentication attempt (NTLM vs Kerberos tells network topology) |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos service ticket request |
| 4771 | Kerberos pre-authentication failed |

## Account & Privilege (`Security.evtx`)
| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 / 4724 | Password change / reset |
| 4726 | User account deleted |
| 4728 / 4732 / 4756 | Member added to global / local / universal privileged group |
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4702 | Scheduled task updated |
| 4703 | Token right adjusted |

## Process / Execution (`Security.evtx`)
| Event ID | Description |
|----------|-------------|
| 4688 | Process created (includes full command line if audit policy enabled) |
| 4689 | Process exited |

## Object Access (`Security.evtx`)
| Event ID | Description |
|----------|-------------|
| 4663 | Attempt to access object (file/key read/write/delete) |
| 4656 | Handle to object requested |
| 4660 | Object deleted |

## PowerShell (`Microsoft-Windows-PowerShell%4Operational.evtx`)
| Event ID | Description |
|----------|-------------|
| 4103 | Module logging (each cmdlet call) |
| 4104 | Script block logging (**full script content — highest value**) |
| 4105 / 4106 | Script start/stop |

## PowerShell (`Windows PowerShell.evtx`)
| Event ID | Description |
|----------|-------------|
| 400 | PowerShell engine started (includes HostApplication = command line) |
| 600 | Provider loaded |
| 800 | Pipeline execution |

## RDP (`Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`)
| Event ID | Description |
|----------|-------------|
| 1149 | RDP authentication success (source IP in event) |
| 4778 | Session reconnected |
| 4779 | Session disconnected |

## Defender (`Microsoft-Windows-Windows Defender%4Operational.evtx`)
| Event ID | Description |
|----------|-------------|
| 1116 | Malware detected |
| 1117 | Malware action taken (quarantine/delete) |
| 1118 / 1119 | Malware remediation started/succeeded |
| 5001 | Real-time protection disabled |

## System (`System.evtx`)
| Event ID | Description |
|----------|-------------|
| 7034 | Service crashed unexpectedly |
| 7035 | Service sent start/stop control |
| 7036 | Service state change |
| 7040 | Service start type changed |
| 7045 | New service installed |

## Scheduled Tasks (`Microsoft-Windows-TaskScheduler%4Operational.evtx`)
| Event ID | Description |
|----------|-------------|
| 106 | Task registered |
| 129 | Task launched |
| 200 | Action started |
| 201 | Action completed |

## WMI (`Microsoft-Windows-WMI-Activity%4Operational.evtx`)
| Event ID | Description |
|----------|-------------|
| 5857 | WMI provider loaded |
| 5858 | WMI error (failed connection — recon indicator) |
| 5860 | Temporary WMI subscription registered |
| 5861 | Permanent WMI subscription registered (**persistence**) |
