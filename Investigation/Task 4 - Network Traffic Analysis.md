# Task 4: Network Traffic Analysis

## Scenario: Understanding Network Activities

Based on our investigation of the PowerShell logs, we have gained a comprehensive understanding of the attack's impact:

* The threat actor was able to read and exfiltrate two potentially sensitive files (`protected_data.kdbx` and `plum.sqlite`).
* The attacker's domains (`cdn.bpakcaging.xyz`, `files.bpakcaging.xyz`) and specific ports (`8080`) used for C2 and file hosting, along with the tool used for exfiltration (`nslookup`), were discovered.

With these findings, we can now complete the investigation by diving into the network traffic captured during the attack. This will provide definitive evidence of communication and data exfiltration.

---

## Investigation Guide: Analyzing `capture.pcapng`

Our final phase of investigation focuses on the `capture.pcapng` file from Julianne's workstation.

**Key Objectives:**

* **Utilize Previous Findings:** Apply the domains and ports discovered from the PowerShell logs to filter network traffic efficiently.
* **Correlate Commands:** All commands executed by the attacker and their outputs were logged and potentially transmitted via the C2 channel, as captured in the packet capture. Follow the network streams corresponding to notable commands identified in the PowerShell logs.
* **Reconstruct Exfiltrated Data:** Based on our understanding of how the `protected_data.kdbx` file was encoded (hexadecimal) and extracted (via DNS exfiltration using `nslookup`), we should be able to retrieve and potentially reconstruct the exfiltrated data from the `pcapng` file.

---

## Questions and Analysis

Please provide your findings and explanations for the following questions based on your network traffic analysis:

### 1. What software is used by the attacker to host its presumed file/payload server?



![image](https://github.com/user-attachments/assets/f1f47358-b88a-491a-abf9-cfd47a99e332)

![image](https://github.com/user-attachments/assets/acfa2c29-e79b-468c-a20a-2048ab11c8f1)

**Hint:** Look at the HTTP server headers or banner information related to the file download requests.

---

### 2. What HTTP method is used by the C2 for the output of the commands executed by the attacker?

From the `powershell.json` log, we know that the attacker was using `Invoke-Request` to transmit the command's results. When we look closer, we can see that the HTTP Method is explicitly defined.

![image](https://github.com/user-attachments/assets/b9d19314-55ed-4d4f-bdb5-c61b7e7ab6c7)

Answer: POST

---

### 3. What is the protocol used during the exfiltration activity?

We arrived at this conclusion in Task 3.

Answer: DNS

---

### 4. What is the password of the exfiltrated file?

Based off the attackers tools and TTPs, we can assume that the password is not located within the file itself. The `protected_data.kdbx` file is a .kdbx file, which is a KeePass database or a single, encrypted container. Instead, the attacker likely obtained the password from the system using `Seatbelt.exe`, their enumeration tool. 

**Hint:** This information might be found within the exfiltrated data itself or revealed through subsequent attacker actions visible in the network traffic.

---

### 5. What is the credit card number stored inside the exfiltrated file?

**Your Answer:**

**Hint:** You will need to successfully extract and decode the exfiltrated data from the packet capture to find this sensitive information.

---
