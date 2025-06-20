# TryHackMe: Boogeyman 1 - Threat Group Analysis Write-up

## Room Overview

This repository documents my investigation and analysis for the "The Boogeyman" room on TryHackMe. This challenge focuses on a realistic scenario where the primary task is to analyze the **Tactics, Techniques, and Procedures (TTPs)** executed by a simulated threat group. The investigation covers the entire attack lifecycle, from initial access to achieving the group's ultimate objective.

---

## Prerequisites & Recommended Knowledge

Successfully completing this room requires a foundational understanding of various cybersecurity concepts and tools, often gained from the TryHackMe SOC L1 Pathway. It is highly recommended to have familiarity with the following topics:

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

* **Thunderbird:** A free and open-source cross-platform email client, ideal for examining the `dump.eml` file.
* **LNKParse3:** A Python package for forensic analysis of binary files with the `.LNK` extension, useful for shortcut file analysis.
* **Wireshark:** A GUI-based packet analyzer, indispensable for detailed network traffic inspection of the `capture.pcapng`.
* **Tshark:** The command-line interface (CLI) version of Wireshark, enabling powerful scriptable network analysis.
* **jq:** A lightweight and flexible command-line JSON processor, perfect for parsing and filtering the `powershell.json` file.
* **Built-in Command-Line Tools:** Standard Linux utilities such as `grep` (for pattern matching), `sed` (for stream editing), `awk` (for text processing), and `base64` (for encoding/decoding data) are also available and crucial for efficient data manipulation.

---

## Starting the Hunt

This repository will detail my step-by-step approach, findings, and solutions as I embark on hunting "The Boogeyman."

## Connect

Feel free to connect with me on [LinkedIn](www.linkedin.com/in/ezra-park-779325330) if you have any questions or feedback.
