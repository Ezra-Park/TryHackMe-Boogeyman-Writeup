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
| Parse all JSON into beautified output                     | `cat powershell.json \| jq`                                   |
| Print all values from a specific field (without field name)| `cat powershell.json \| jq '.FieldName'`                       |
| Print all values from a specific field (with field name)  | `cat powershell.json \| jq '{FieldName}'`                     |
| Print values from multiple fields                         | `cat powershell.json \| jq '{Field1, Field2}'`                |
| Sort logs based on their Timestamp                        | `cat powershell.json \| jq -s -c 'sort_by(.Timestamp) \| .[]'` |
| Sort logs based on Timestamp and print multiple fields    | `cat powershell.json \| jq -s -c 'sort_by(.Timestamp) \| .[] \| {Field1, Field2}'` |

You may continue learning this tool via its [official documentation](https://stedolan.github.io/jq/manual/).

---

## Questions and Analysis

Please provide your findings and explanations for the following questions based on your PowerShell log analysis:

### 1. What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

First, we want to parse through the json file by using the following command

![image](https://github.com/user-attachments/assets/22755e1a-5d62-4289-bd31-eb76516a03bd)

The output gives us

![image](https://github.com/user-attachments/assets/7fa4fa67-7f5f-4f30-a685-d57d4b6714e8)

This is a lot of data! To find our answer with more ease, we should seek to simplify our output by narrowing our fields. In particular, the ScriptBlockText field looks interesting. We can filter the powershell.json file by entering `cat ~/Desktop/artefacts/powershell.json | jq '{ScriptBlockText}'` into the terminal. Scrolling through the output, we find the following

![image](https://github.com/user-attachments/assets/31833ac8-30ca-4629-9a38-b6507627be94)

In this powershell command, we find our two domains & our answer: cdn.bpakcaging.xyz, files.bpakcaging.xyz

---

### 2. What is the name of the enumeration tool downloaded by the attacker?

From we can scroll through our most recent query to find the results.

![image](https://github.com/user-attachments/assets/a77471f3-a677-4d77-aa1c-79484762bb2b)

Answer: Seatbelt

---

### 3. What is the file accessed by the attacker using the downloaded `sq3.exe` binary? Provide the full file path with escaped backslashes.

![image](https://github.com/user-attachments/assets/4b18ea79-ccdb-49d7-8121-d2d7869670cd)

This command shows `sq3.exe` (presumably `.\Music\sq3.exe` if executed from the current working directory) being run. Notably, it's followed by a file path:
`AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`

To find the full file path, there are a couple considerations. First, `AppData` is a hidden directory that's usually found under a user's profile directory. In a Windows machine, we typically find the following structure `C:\Users\<username>\AppData`. Second, we can use the context clues from previous commands to find the user's profile. 

![image](https://github.com/user-attachments/assets/3901735a-4356-47a8-b3ea-85048c654bf2)

![image](https://github.com/user-attachments/assets/741fc67d-8a1b-4aee-8c9b-bd4232a1979a)

From the highlighted commands above, we can see that the attacker is operating within the `j.westcott` profile.

Together, this allows us to put the full file path together, as `C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`.

For our answer, we need to include escaped backslashes: `C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite`


---

### 4. What is the software that uses the file in Q3?

The taking a look at the first photo in Q3 gives us the answer: Microsoft Sticky Notes

---

### 5. What is the name of the exfiltrated file?

![image](https://github.com/user-attachments/assets/d8a1516a-5947-45f3-9359-a547b683c548)

Answer: protected_data.kdbx

---

### 6. What type of file uses the `.kdbx` file extension?

A quick Google search shows the answer: KeePass

---

### 7. What is the encoding used during the exfiltration attempt of the sensitive file?

![image](https://github.com/user-attachments/assets/65d99a39-4759-4ad8-8776-1d27c4785df4)

Answer: Hex

We can see from this command that data stored in the `$hex` variable is being split into chunks that are 50 characters in length. Each chunk is then used as a subdomain in a DNS query using the nslookup tool (Answer to Q8). This suggests that the data in the file is stored in an encoded format that is suitable for use in DNS subdomains, as DNS subdomains typically have restrictions on the usage of characters. This bit of evidence along with the variable name give strong indications that the data is encoded in hexidecimal or a similar format. 

---

### 8. What is the tool used for exfiltration?

![image](https://github.com/user-attachments/assets/5375f840-8a84-4772-adb0-60517119331f)

Answer: nslookup

See explanation from Q7.

---


