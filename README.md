# TryHackMe: Boogeyman 1 - Threat Group Analysis Write-up

## Case Overview

** Objective:**  
Investigate a multi-stage attack—from phishing to command and control—using forensic artifacts and open-source tools.

** Scope:**
- Analyze phishing email (`dump.eml`)
- Investigate PowerShell activity from logs (`powershell.json`)
- Identify anomalies in captured network traffic (`capture.pcapng`)

---

## Tools Used

| Category              | Tools                                                                 |
|-----------------------|-----------------------------------------------------------------------|
| Email Analysis        | Thunderbird                                                          |
| Endpoint Forensics    | jq, grep, LNKParse3, base64, PowerShell event log analysis           |
| Network Forensics     | Wireshark, Tshark                                                     |
| CLI & Scripting       | awk, sed, base64, Linux CLI                                           |

---

## MITRE ATT&CK Mapping (High-Level)

| Phase              | Technique                 | ID        | Summary                                       |
|--------------------|---------------------------|-----------|-----------------------------------------------|
| Initial Access     | Phishing with Attachment  | T1566.001 | Malicious `.eml` delivered obfuscated LNK     |
| Execution          | PowerShell Scripts        | T1059.001 | Base64-encoded dropper executed               |
| C2 Communication   | Encrypted HTTPS Beaconing | T1071.001 | PCAP shows traffic to known malicious IP      |

---

## Deep Dive: Investigation Reports

Each task is documented in detail in its own markdown file inside the `Investigation/` folder:

- 📧 [Task 2: Email Analysis](./Investigation/Task%202%20-%20Email%20Analysis.md)  
- 💻 [Task 3: Endpoint Security](./Investigation/Task%203%20-%20Endpoint%20Security.md)  
- 🌐 [Task 4: Network Traffic Analysis](./Investigation/Task%204%20-%20Network%20Traffic%20Analysis.md)

---

## Lessons Learned

- Correlating artifacts across email, endpoint, and network reveals full kill chain visibility.
- Learned how to decode PowerShell payloads and trace encoded commands back to attacker intent.
- Reinforced MITRE ATT&CK as a structured way to document adversary behavior.

---

## 🔗 Connect With Me

- 📧 ezrapark.security@gmail.com  
- 💼 [LinkedIn](https://www.linkedin.com/in/ezra-park-779325330)

---

