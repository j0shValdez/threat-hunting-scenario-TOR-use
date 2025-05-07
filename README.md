<p align="center">
  <img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>
</p>


# Threat Hunt Report: Unauthorized TOR Usage (**IN PROGRESS**)

_**Project Overview**_:

In this threat hunting project, I investigated a simulated insider threat scenario where an employee attempted to bypass enterprise network controls using the Tor browser. To emulate realistic malicious behavior, I designed and executed a threat scenario in which a user silently installed the Tor browser, accessed the dark web, created a “shopping list” with illicit items, and attempted to cover their tracks.

Using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL), I conducted a step-by-step investigation via to detect Indicators of Compromise (IoCs). The analysis revealed installation, execution, and network activity consistent with Tor browser usage. My investigation confirmed that the user silently installed tor-browser-windows-x86_64-portable-14.5.1.exe, launched firefox.exe, and made network connections to known Tor entry ports (e.g., 9001).

This project demonstrates my ability to craft realistic threat scenarios, simulate attacker behavior, and perform advanced endpoint threat hunting using KQL and Microsoft Defender in a cloud lab environment.


- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)



## Tecnology, Platforms, and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Checked `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Checked `DeviceProcessEvents`** for any signs of installation or usage.
- **Checked `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

To begin my investigation, I performed a broad search across the **DeviceFileEvents** table for any file name containing the string **"tor"**. This helped me cast a wide net to identify any potentially suspicious activity related to the **Tor browser** or its installation. From this initial search, I noticed several file operations tied to the user "`joshvlab`" on the machine "`jv-windows-targ`", including the appearance of a file called "`tor-shopping-list.txt`" at `2025-05-06T19:35:56.8012213Z`, a file `tor-browser-windows-x86_64-portable-14.5.1.exe` located in the downlaods folder, and multiple Tor-related files being written to the Desktop . These findings suggested that Tor may have been installed and possibly used, which warranted further investigation into this user’s activity. The evetns began at `2025-05-06T19:12:56.287056Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jv-windows-targ"
| where InitiatingProcessAccountName == "joshvlab"
| where FileName startswith "tor"
| where Timestamp >= datetime(2025-05-06T19:12:56.287056Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
 > `DeviceName` and `InitiatingProcessAccountName` were filtered to isolate actions by the specific user on the target system.`FileName startswith "tor"`
> narrowed the focus to files directly related to Tor.`Timestamp` was used to ensure we only viewed activity from the start of the suspicious events
> onward. The `project` statement selected relevant columns to highlight file operations, hash values, and user identity.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/360c7a19-ee29-4f00-b5cc-125045a86451">

---

### 2. Searched the `DeviceProcessEvents` Table

Based on the first step, we know that user "`joshvlab`" downlaoded file `tor-browser-windows-x86_64-portable-14.5.1.exe`on machine "`jv-windows-targ`". But did they install it?
To determine whether any Tor-related files were executed, I began by briefly inspecting the `DeviceProcessEvents`. 

Using a targeted KQL query, I searched for any instance where the `ProcessCommandLine` contained that specific filename. The results showed that at `2025-05-06T19:22:48.3035661Z`, the user account `joshvlab` on the target machine `jv-windows-targ` executed the file from their Downloads folder. The `ProccessCommandLine` included the parameter `/S` that indicated a **silent installation**, confirming the executable was run without user interface prompts.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "jv-windows-targ"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
  > The query filters the `DeviceProcessEvents` table to identify any process execution activity involving the Tor browser installer. It begins by narrowing the results to the target device (`jv-windows-targ`) and then searches for any command line executions that contain the specific installer filename (`tor-browser-windows-x86_64-portable-14.5.1.exe`). The `project` statement is used to display key fields such as the timestamp of execution, device name, user account, action type, file name, file path, file hash, and the full process command line—providing context around how the executable was run.


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/09b1849d-89c9-4637-b9e1-5ac0bda4ca86">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

After confirming the installation of the Tor browser, the next step was to determine whether the user actually opened browser itself. During the investigation, I found that the file `firefox.exe` (Tor's browser executable) was located at `C:\Users\JoshVlab\Desktop\Tor Browser\Browser\firefox.exe`. 

A query against the `DeviceProcessEvents` table revealed that user `joshvlab` opened the Tor browser at `2025-05-06T19:23:39.2017858Z`. Additional instances of `firefox.exe` and `tor.exe` execution followed, suggesting continued browser activity, likely via the installed Tor software.


**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
  > The query scans the `DeviceProcessEvents` table to identify any executions of Tor-related executables by filtering for file names typically associated with Tor (`tor.exe`, `firefox.exe`, and `tor-browser.exe`). It then orders the results by time in descending order and selects relevant fields to display, such as the timestamp, user account, file path, and hash—helping confirm both usage and authenticity of the application.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/1ff0b96e-0d31-4559-a0e6-8b0fbe91046a">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

The next phase of the investigation focused on verifying whether the Tor Browser was actually used to establish outbound network connections. Using the `DeviceNetworkEvents` table, I searched for activity involving ports commonly associated with Tor communications: `9001`, `9030`, `9040`, `9050`, `9051`, and `9150`. 

The query revealed that at `2025-05-06T19:23:50.9490815Z`, the user account `joshvlab` on device `jv-windows-targ` made a network connection to IP address `116.203.17.238` over port `9001`. The connection was initiated by the process `tor.exe`, which was located in the expected installation path for the Tor Browser:
`C:\Users\joshvlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. 

This strongly suggests that the Tor Browser was actively used to browse the internet, most likely to anonymize network activity or access hidden services.



**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jv-windows-targ"
| where InitiatingProcessAccountName == "joshvlab"
| where RemotePort in ("9001","9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
  > This query examines the `DeviceNetworkEvents` table for any outbound connections initiated by the user `joshvlab` from the target system. It filters for known Tor-related ports and selects key fields including timestamp, IP address, port, and initiating process details. Sorting results by timestamp helps identify the timing and context of potential Tor usage.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/09017825-0128-4fc2-87c4-78c4bf601be2">


  > Below, you can observe multiple successful network connections made using other known Tor-related ports, further supporting evidence of Tor Browser activity

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/73cc3aa6-4f9b-4ede-a506-e796d6736f91">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-06T19:12:48.287056Z`
- **Event:** The user `joshvlab` downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\JoshVlab\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-06T19:22:48.3035661Z`
- **Event:** The user `joshvlab` executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode (`/S`), initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\JoshVlab\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-06T19:23:39.2017858Z`
- **Event:** User `joshvlab` opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\JoshVlab\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-06T19:23:50.9490815Z`
- **Event:** A network connection to IP `2025-05-06T19:23:50.9490815Z` on port `9001` by user `joshvlab` was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\JoshVlab\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-06T19:24:02.3691952Z` - Connected to `155.4.74.117` on port `9001`.
  - `2025-05-06T19:24:11.4888008Z` - Connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "joshvlab" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-06T19:35:56.8012213Z`
- **Event:** The user `joshvlab` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\joshvlab\Desktop\tor-shopping-list.txt`

---

## Summary

The user `joshvlab` on the `jv-windows-targ` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jv-windows-targ` by the user `joshvlab`. The device was isolated (via MDE), and the user's direct manager was notified.

---
