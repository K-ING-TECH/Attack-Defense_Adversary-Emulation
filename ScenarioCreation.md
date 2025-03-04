# Threat Event (RDP Brute Force & Credential Dumping)
**Unauthorized Remote Access + LSASS MiniDump**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Port Scanning & Enumeration (Kali Machine)
2. Brute Force Administrator Account using **Hydra**
3. Ran various shell commands to gather system and network details
4. Privilege Escalation & Persistence via account and service creation 
5. Credential Dumping via **rundll32**
6. Log Tampering and clearing to clear IoCs  

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                                                      |
|---------------------|------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceLogonEvents                                                                                   |
| **Info**            | [MS Docs: DeviceLogonEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose**         | Identifies the brute force pattern (repeated failed logins) and successful RDP logon under `administrator`. |

| **Parameter**       | **Description**                                                                                               |
|---------------------|---------------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceProcessEvents                                                                                           |
| **Info**            | [MS Docs: DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**         | Tracks suspicious processes like `rundll32`, password changes (`net.exe`), service creation (`sc.exe`), and RDP-based enumerations. |

| **Parameter**       | **Description**                                                                                                |
|---------------------|----------------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceFileEvents                                                                                               |
| **Info**            | [MS Docs: DeviceFileEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| **Purpose**         | Monitors creation of malicious files (e.g., `C:\lsass.dmp`), credential or text files, and any subsequent deletions. |

| **Parameter**       | **Description**                                                                                                     |
|---------------------|---------------------------------------------------------------------------------------------------------------------|
| **Name**            | DeviceNetworkEvents                                                                                                 |
| **Info**            | [MS Docs: DeviceNetworkEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**         | Detects external connections (e.g., exfiltration or direct attacker IP), including RDP inbound traffic details. |

---

## Related Queries:

```kql
// 1. Detecting repeated RDP login failures and eventual success
DeviceLogonEvents
| where DeviceName == "king-vm"
| where AccountName == "administrator"
| order by Timestamp asc
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP

// 2. Monitoring suspicious processes (e.g., rundll32 dumping LSASS)
DeviceProcessEvents
| where ProcessCommandLine has_any("MiniDump", "comsvcs.dll", "lsass.dmp")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine

// 3. Detecting new local user creation or password changes
DeviceProcessEvents
| where FileName has_any("net.exe", "net1.exe")
| where ProcessCommandLine has_any("net user", "net localgroup", "administrator")
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// 4. Service creation attempts for persistence
DeviceProcessEvents
| where FileName == "sc.exe"
| where ProcessCommandLine has "create"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

// 5. Potential exfiltration or attacker connectivity
DeviceNetworkEvents
| where RemotePort == 3389 // RDP
| where RemoteIP != "" 
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort

// 6. Clearing or altering event logs
DeviceProcessEvents
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has_any("cl", "clear")
| project Timestamp, DeviceName, ActionType, ProcessCommandLine
