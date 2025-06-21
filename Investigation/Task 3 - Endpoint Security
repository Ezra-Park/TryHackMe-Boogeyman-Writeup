# Task 3: Endpoint Security - PowerShell Log Analysis

## Scenario: Payload Execution & Endpoint Activities

Based on our initial findings from the email analysis (Task 2), we discovered how the malicious attachment compromised Julianne's workstation:

* A PowerShell command was executed.
* Decoding the initial payload revealed the starting point of subsequent endpoint activities.

With these crucial discoveries, our next step is to analyze the PowerShell logs to uncover the potential impact of the attack and trace the attacker's actions on the compromised system.

---

## Investigation Guide: Analyzing PowerShell Logs with `jq`

We will continue our analysis by searching the `powershell.json` logs for the execution of the initial payload and subsequent activities. Since the provided data is in JSON format, we can efficiently parse and filter it using the `jq` command-line tool.

**Note:** Some logs may be redundant or not contain critical information; focus on entries that indicate suspicious or malicious activity.

### `jq` Cheatsheet

`jq` is a lightweight and flexible command-line JSON processor. This tool is invaluable for working with structured log data and can be used in conjunction with other text-processing commands. Familiarity with the existing fields in a single log entry will be beneficial for effective parsing.

| **Command Description** | **`jq` Command Example** |
| :-------------------------------------------------------- | :----------------------------------------------------- |
| Parse all JSON into beautified output                     | `cat powershell.json | jq`                                   |
| Print all values from a specific field (without field name)| `cat powershell.json | jq '.FieldName'`                       |
| Print all values from a specific field (with field name)  | `cat powershell.json | jq '{FieldName}'`                     |
| Print values from multiple fields                         | `cat powershell.json | jq '{Field1, Field2}'`                |
| Sort logs based on their Timestamp                        | `cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'` |
| Sort logs based on Timestamp and print multiple fields    | `cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {Field1, Field2}'` |

You may continue learning this tool via its [official documentation](https://stedolan.github.io/jq/manual/).

---

## Questions and Analysis

Please provide your findings and explanations for the following questions based on your PowerShell log analysis:

### 1. What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

**Your Answer:**

---

### 2. What is the name of the enumeration tool downloaded by the attacker?

**Your Answer:**

**Hint:** Look for common reconnaissance tools or unusual executable downloads.

---

### 3. What is the file accessed by the attacker using the downloaded `sq3.exe` binary? Provide the full file path with escaped backslashes.

**Your Answer:**

**Hint:** This binary is often used to interact with a specific type of database file.

---

### 4. What is the software that uses the file in Q3?

**Your Answer:**

---

### 5. What is the name of the exfiltrated file?

**Your Answer:**

---

### 6. What type of file uses the `.kdbx` file extension?

**Your Answer:**

---

### 7. What is the encoding used during the exfiltration attempt of the sensitive file?

**Your Answer:**

---

### 8. What is the tool used for exfiltration?

**Your Answer:**

---
