# 🛡️ Azure Sentinel (SIEM) & RDP Threat Mapping Lab

![Azure Sentinel Attack Map](https://github.com/jeloa/Azure-Portfolio/Security-Engineer/screenshots/sentinel_map.png)
*Figure 1: Real-time global heat map of RDP brute-force attacks captured by the honeypot.*

## 📖 Project Overview
This project demonstrates the deployment of a cloud-native **SIEM (Microsoft Sentinel)** linked to a live **Windows Honeypot**. The objective was to observe real-world RDP brute-force attacks from global sources and visualize the threat landscape in real-time.

By intentionally exposing a Windows VM to the internet and disabling its local firewall, this lab captures failed login attempts, extracts geographical metadata from IP addresses via PowerShell, and plots them on a global heat map using **Kusto Query Language (KQL)**.

### 🎯 Key Learning Objectives
* **SIEM Implementation:** Configuring Microsoft Sentinel and Log Analytics Workspaces (LAW).
* **Security Automation:** Utilizing PowerShell to automate geolocation data extraction from Windows Event Logs.
* **Threat Visualization:** Engineering custom Workbooks to map cyber attacks geographically.
* **Incident Response:** Analyzing `Event ID 4625` (Failed Logon) to understand adversary patterns.

---

## 🛠️ Tech Stack & Architecture
* **Cloud Platform:** Microsoft Azure
* **SIEM:** Microsoft Sentinel
* **Log Management:** Log Analytics Workspace
* **Honeypot:** Windows 10 Virtual Machine
* **Scripting:** PowerShell (for API-based Geolocation extraction)
* **Data Language:** Kusto Query Language (KQL)
* **External API:** [ipgeolocation.io](https://ipgeolocation.io/)

---

## 🚀 Execution Steps

### 1. Infrastructure Deployment
- Created a dedicated **Resource Group** in Azure.
- Deployed a Windows 10 VM with a **Network Security Group (NSG)** configured to allow all inbound traffic (`ANY` to `ANY`).

### 2. Log Analytics & Sentinel Setup
- Provisioned a **Log Analytics Workspace**.
- Onboarded **Microsoft Sentinel** to the workspace.
- Configured **Microsoft Defender for Cloud** to collect "All Events" from the VM.

### 3. Honeypot Configuration & Automation
- Logged into the VM and disabled **Windows Defender Firewall** for all profiles.
- Deployed a custom PowerShell script that monitors the `Security` event log for failed RDP logins.
- The script uses the `ipgeolocation.io` API to convert the attacker's IP address into Latitude, Longitude, and Country data.

![PowerShell Script In Action](https://github.com/jeloa/Azure-Portfolio/Security-Engineer/screenshots/powershell_running.png)
*Figure 2: Custom PowerShell script extracting geolocation data from failed RDP login attempts.*

### 4. Custom Log Parsing & Visualization
- Configured a **Custom Log (DCR)** in Azure to ingest the specialized data produced by the PowerShell script.
- Created a **Sentinel Workbook** using KQL to visualize the attack data on a world map.

---

## 🔍 Data Analysis with KQL
The following Kusto Query was used to parse the custom log data and generate the geographical visualization:

```kusto
FAILED_RDP_WITH_GEO_CL 
| extend latitude = extract(@"latitude:([0-9\.-]+)", 1, RawData),
         longitude = extract(@"longitude:([0-9\.-]+)", 1, RawData),
         destinationhost = extract(@"destinationhost:([^,]+)", 1, RawData),
         username = extract(@"username:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData)
| summarize event_count=count() by sourcehost, latitude, longitude, country, label, destinationhost
```

---

###  Project Insights
- Immediate Exposure: Brute-force attempts began within 10-15 minutes of the VM being live.

- Global Threat Landscape: Captured thousands of login attempts from IPs worldwide, primarily targeting the Administrator account with common passwords.

- SIEM Efficiency: Demonstrated the power of SIEM in transforming massive volumes of raw security data into actionable intelligence.

---

###  Disclaimer
For Educational Purposes Only. This project involves intentionally weakening security for research. Ensure you work in an isolated environment and delete all resources after the lab to prevent unexpected Azure costs.

