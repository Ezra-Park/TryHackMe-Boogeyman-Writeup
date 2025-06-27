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

From our prior analysis, we know the domain that hosts the payloads. If we filter the HTTP requests to the packets containing the name of this domain, we can find more information on its servers by taking a look at the HTTP server headers. 

![image](https://github.com/user-attachments/assets/f1f47358-b88a-491a-abf9-cfd47a99e332)

![image](https://github.com/user-attachments/assets/acfa2c29-e79b-468c-a20a-2048ab11c8f1)

By following the conversation, we find that the server is hosted using Python/3.10.7.

Our answer is: Python

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

Based off the attackers tools and TTPs, we can assume that the password is not located within the file itself. The `protected_data.kdbx` file is a .kdbx file, which is a KeePass database or a single, encrypted container. Instead, the attacker likely obtained the password from the system using `Seatbelt.exe`, their enumeration tool. When inspecting the `powershell.json` file for a bigger hint, we find an indication where the password might be in the following line.

![image](https://github.com/user-attachments/assets/7f3413ce-aafc-4062-bbcd-5c5257767ce2)

`".\\Music\\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite \"SELECT * from NOTE limit 100\";pwd"`

In this line, we see `sq3.exe`, a CL utility for interacting with SQLite databases, is executed to run against a specific file - a local database file in this case - used by Microsoft Sticky Notes. What follows is a SQL query into the plum.sqlite database, asking to retrieve 100 rows from the NOTE table. It is likely that sensitive information, including passwords, are stored in the NOTE table, meaning it is a prime target for our investigation. 

Applying the appropriate filter to WireShark, we get the following.

![image](https://github.com/user-attachments/assets/4d3005e9-dea3-4f12-8cd3-da8a2587f8ef)

Here we see the exact command mentioned earlier. To see the response, we need to follow the stream.

![image](https://github.com/user-attachments/assets/1af9f756-55a9-4869-ba98-0488e5901809)

![image](https://github.com/user-attachments/assets/d9fa7339-e07f-492f-a95a-c2c4339a6605)

To see the response, we need to click on the next stream (#750).

![image](https://github.com/user-attachments/assets/38a98c22-deea-45f0-b539-9ae7bab43669)

To decode the response, I used cyberchef, a free online tool.

![image](https://github.com/user-attachments/assets/0298b8f4-cc21-4228-b415-c985578bc238)

We can see the password in the decoded response: %p9^3!lL^Mz47E2GaT^y

---

### 5. What is the credit card number stored inside the exfiltrated file?

We know that `protected_data.kdbx` is being extruded via DNS exfiltration. After tampering with some WireShark filters to remove copies and extraneous packets, we can finally see the data. 

![image](https://github.com/user-attachments/assets/3ca8e48c-3205-422c-a821-13d0dcc4f205)

`dns and dns.flags.response == 0 and dns.qry.name contains "bpakcaging.xyz" and ip.dst == 167.71.211.113 and !dns.qry.name contains "eu-west-1"`

There are a couple ways to transfer this data to a file. To work with efficiency, let's use TShark.

Our TShark command will be `tshark -r ./Desktop/artefacts/capture.pcapng -Y 'dns and dns.flags.response == 0 and dns.qry.name contains "bpakcaging.xyz" and ip.dst == 167.71.211.113 and !dns.qry.name contains "eu-west-1"' -T fields -e dns.qry.name | sed 's/\.bpakcaging\.xyz$//' > hex_strings_only.txt`.

The first part will filter the `capture.pcapng` file so we get the same output as the wireshark query above. The second part is a substitution command. 

-The `sed` command is used for searching and replacing string characters.

-`s/` is for "substitute"

-`\.bpakcaging\.xyz$` is the regular expression we want to search for. The `\` escapes the periods (so they are treated as literal characters), and `$` anchors the search to the end of the line, ensuring that we only remove the suffix.

-`//` is the replacement string (in this case, nothing).

![image](https://github.com/user-attachments/assets/5f2c9cbb-4b5b-4d23-a8d1-fdd4cc4d679c)

The final part of the filter saves the output (which will be the hex encoded version of the `protected_data.kbdx` file) into a new text document. 

![image](https://github.com/user-attachments/assets/f7c184b5-013e-46d4-b3ad-bbee42865c7a)

Now there should only be 1 step remaining before we can access the file, which is to convert the hex encoded data to plain text. To do so, we can use the following command:

`cat hex_strings_only.txt | tr -d '\n' | xxd -r -p > protected_data.kdbx`

-`cat hex_strings_only.txt`: This reads the content our hex file.

-`| tr -d '\n'`: The pipe (`|`) sends the output to the next command. `tr` is a utility for translating characters. The `-d '\n'` part deletes all newline characters (\n), joining all the hex chunks into a continuous string.

-`| xxd -r -p`: The output is piped to `xxd`.

-`-r`: Tells xxd to perform a reverse operation, converting hex back to binary.

-`-p`: Specifies the "plain" hex dump format, which is a continuous string of hex characters without any offsets or other formatting. This is the exact format of our input.

-`> protected_data.kdbx`: The final output of the xxd command (the binary data) is redirected (>) to a new file named protected_data.kdbx.

![image](https://github.com/user-attachments/assets/d5b9d5c1-bd6a-485e-baa3-19d269906d5e)

All that's left to do is to use the master password we found earlier to decrypt the file and find our answer. 

![image](https://github.com/user-attachments/assets/d39008ca-e7d7-49bf-966f-c13b86f309e9)

![image](https://github.com/user-attachments/assets/087d0bd7-69ab-41d5-a1e7-b13409fbb22d)

Answer: 4024007128269551

---
