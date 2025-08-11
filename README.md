# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Sanjayjr3/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string “tor” in it and discovered what looks like the user “spartanuser” downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called “tor-shopping-list.txt” on the desktop at '2025-08-09T20:27:46.6589332Z'. These events began at:2025-08-09T20:02:23.1568761Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "spartanuser-thr"
| where InitiatingProcessAccountName == "spartanuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-09T20:02:23.1568761Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1287" height="420" alt="Screenshot 2025-08-11 at 3 27 36 PM" src="https://github.com/user-attachments/assets/6fba2a64-7126-46d8-b541-ce440e16db72" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.5.5.exe”. Based on the logs returned, at 2025-08-09T20:02:23.1568761Z, an employee on the "spartanuser-thr" device ran the file tor-browser-windows-x86_64-portable-14.5.5.exe from the Downloads folder, using a command that triggered a silent installation. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "spartanuser-thr"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1286" height="124" alt="Screenshot 2025-08-11 at 3 46 22 PM" src="https://github.com/user-attachments/assets/84422fbd-bc14-4704-b241-f943d5a3d10c" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user “spartanuser” actually opened the TOR browser. There was evidence that they did open it at 2025-08-09T20:07:33.2504416Z. There were several other instances of ‘firefox.exe’ (TOR) as well as ‘tor.ex’ spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "spartanuser-thr"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1282" height="384" alt="Screenshot 2025-08-11 at 3 58 08 PM" src="https://github.com/user-attachments/assets/81bcae0e-7d1e-4336-b1e2-021268158a89" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish connection using any of the known TOR ports. At ‘2025-08-09T20:08:05.9450288Z’, an employee on the "spartanuser-thr" device successfully established a connection to the remote IP address ‘127.0.0.1’ on port ‘9150’. The connection was initiated by the process ‘tor.exe’, located in the folder ‘c:\users\spartanuser\desktop\tor browser\browser\firefox.exe’. There were a few other connections to sites over port ‘443’.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1283" height="234" alt="Screenshot 2025-08-11 at 4 05 54 PM" src="https://github.com/user-attachments/assets/d3d21126-3ec9-426f-b545-8a2f56642d19" />
---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-09T20:02:23.1568761Z`
- **Event:** The user "spartanuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\spartanuser\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-09T20:02:23.1568761Z`
- **Event:** The user "spartanuser" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\spartanuser\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-09T20:07:33.2504416Z`
- **Event:** User "spartnuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\spartanuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-09T20:08:05.9450288Z’`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "spartanuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\spartanuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-09T20:08:11.994783Z` - Connected to `198.98.59.102` on port `443`.
  - `2025-08-09T20:08:05.9450288Z` - Local connection to `127.0.0.1` on port `9150`.
  - '2025-08-09T20:07:47.5184001Z' - Connected to '64.65.0.75' on port '443'
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-09T20:27:46.6589332Z`
- **Event:** The user "spartanuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\sparanuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "spartanuser" on the 'spartanuser-thr' device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint 'spartanuser-thr' by the user `spartanuser`. The device was isolated, and the user's direct manager was notified.

---
