# TryHackMe: Boogeyman 1 - Threat Group Analysis Write-up

## Room Overview

This repository documents my investigation and analysis for the "The Boogeyman" room on TryHackMe. This challenge focuses on a realistic scenario where the primary task is to analyze the **Tactics, Techniques, and Procedures (TTPs)** executed by a simulated threat group. The investigation covers the entire attack lifecycle, from initial access to achieving the group's ultimate objective.

---

## Prerequisites & Recommended Knowledge

Successfully completing this room requires a foundational understanding of various cybersecurity concepts and tools. It is highly recommended to have familiarity with the following topics:

* **Phishing Analysis Fundamentals:** Understanding phishing techniques and indicators.
* **Phishing Analysis Tools:** Proficiency with email analysis tools.
* **Windows Event Logs:** Knowledge of Windows logging mechanisms and how to interpret them.
* **Wireshark: Traffic Analysis:** Skills in network packet capture analysis.
* **Tshark: The Basics:** Command-line network analysis.
* **Basic Command-Line Operations:** Familiarity with Linux commands (`grep`, `sed`, `awk`, `base64`).

---

## Investigation Platform & Environment

The challenge is conducted within a dedicated virtual machine (VM) provided by TryHackMe, accessible via a split-screen view. This VM is pre-configured with the necessary environment and tools for the investigation.

---

## Provided Artifacts for Analysis

For the investigation, the following key artifacts are provided, simulating real-world forensic evidence:

* **`dump.eml`**: A copy of the phishing email, crucial for initial access analysis.
* **`powershell.json`**: PowerShell logs extracted from Julianne's (the victim workstation) `evtx` file, formatted in JSON. These logs are vital for understanding command execution and script activity.
* **`capture.pcapng`**: A packet capture from Julianne's workstation, providing network traffic data for deep analysis.

These files are typically located in the `/home/ubuntu/Desktop/artefacts` directory within the provided VM.

---

## Tools at Disposal

The provided VM includes a suite of essential tools to effectively parse and analyze the artifacts:

* **Thunderbird:** A free and open-source cross-platform email client, great for examining the `dump.eml` file.
* **LNKParse3:** A Python package for forensic analysis of binary files with the `.LNK` extension, useful for shortcut file analysis.
* **Wireshark:** A GUI-based packet analyzer, allowing for detailed network traffic inspection of the `capture.pcapng`.
* **Tshark:** The command-line interface (CLI) version of Wireshark, enabling scriptable network analysis.
* **jq:** A lightweight and flexible command-line JSON processor, for parsing and filtering the `powershell.json` file.
* **Built-in Command-Line Tools:** Standard Linux utilities such as `grep` (for pattern matching), `sed` (for stream editing), `awk` (for text processing), and `base64` (for encoding/decoding data) are also available and crucial for efficient data manipulation.

---

## Starting the Hunt

This repository will detail my step-by-step approach, findings, and solutions as I embark on hunting "The Boogeyman."

## Connect

Feel free to connect with me on [LinkedIn](https://www.linkedin.com/in/ezra-park-779325330) if you have any questions or feedback.


---

## 📌 Case Overview

**🎯 Objective:**  
Investigate a multi-stage attack—from phishing to command and control—using forensic artifacts and open-source tools.

**🛠 Scope:**
- Analyze phishing email (`dump.eml`)
- Investigate PowerShell activity from logs (`powershell.json`)
- Identify anomalies in captured network traffic (`capture.pcapng`)

---

## 🧰 Tools Used

| Category              | Tools                                                                 |
|-----------------------|-----------------------------------------------------------------------|
| Email Analysis        | Thunderbird                                                          |
| Endpoint Forensics    | jq, grep, LNKParse3, base64, PowerShell event log analysis           |
| Network Forensics     | Wireshark, Tshark                                                     |
| CLI & Scripting       | awk, sed, base64, Linux CLI                                           |

---

## 🗺️ MITRE ATT&CK Mapping (High-Level)

| Phase              | Technique                 | ID        | Summary                                       |
|--------------------|---------------------------|-----------|-----------------------------------------------|
| Initial Access     | Phishing with Attachment  | T1566.001 | Malicious `.eml` delivered obfuscated LNK     |
| Execution          | PowerShell Scripts        | T1059.001 | Base64-encoded dropper executed               |
| C2 Communication   | Encrypted HTTPS Beaconing | T1071.001 | PCAP shows traffic to known malicious IP      |

---

## 📂 Deep Dive: Investigation Reports

Each task is documented in detail in its own markdown file inside the `Investigation/` folder:

- 📧 [Task 2: Email Analysis](./Investigation/Task%202%20-%20Email%20Analysis.md)  
- 💻 [Task 3: Endpoint Security](./Investigation/Task%203%20-%20Endpoint%20Security.md)  
- 🌐 [Task 4: Network Traffic Analysis](./Investigation/Task%204%20-%20Network%20Traffic%20Analysis.md)

---

## 🧠 Lessons Learned

- Correlating artifacts across email, endpoint, and network reveals full kill chain visibility.
- Learned how to decode PowerShell payloads and trace encoded commands back to attacker intent.
- Reinforced MITRE ATT&CK as a structured way to document adversary behavior.

---

## 🔗 Connect With Me

- 📧 ezrapark.security@gmail.com  
- 💼 [LinkedIn](https://www.linkedin.com/in/ezra-park-779325330)

---

