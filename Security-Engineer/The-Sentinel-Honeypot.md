#  Azure Sentinel (SIEM) & RDP Threat Mapping Lab

[![Azure](https://img.shields.io/badge/Azure-0089D6?style=for-the-badge&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/)
[![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/en-us/services/microsoft-sentinel/)
[![KQL](https://img.shields.io/badge/KQL-Kusto-orange?style=for-the-badge)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

##  Project Overview
This project involves the deployment of a cloud-native **SIEM (Microsoft Sentinel)** linked to a live **Windows Honeypot**. The goal is to observe real-world RDP brute-force attacks from global sources and visualize the threat landscape in real-time.

By intentionally exposing a Windows VM to the internet and disabling its local firewall, this lab captures failed login attempts, extracts geographical metadata from IP addresses, and plots them on a global heat map using **Kusto Query Language (KQL)**.

###  Key Learning Objectives
* **SIEM Implementation:** Configuring Microsoft Sentinel and Log Analytics Workspaces (LAW).
* **Security Automation:** Utilizing PowerShell scripts to automate geolocation data extraction from Windows Event Logs.
* **Threat Visualization:** Creating custom Workbooks to map cyber attacks geographically.
* **Incident Response:** Analyzing `Event ID 4625` (Failed Logon) to understand attack patterns.

---

##  Tech Stack & Architecture
* **Cloud Platform:** Microsoft Azure
* **SIEM:** Microsoft Sentinel
* **Log Management:** Log Analytics Workspace
* **Honeypot:** Windows 10 Virtual Machine
* **Scripting:** PowerShell (for API-based Geolocation extraction)
* **Data Language:** Kusto Query Language (KQL)
* **External API:** [ipgeolocation.io](https://ipgeolocation.io/)

---

##  Execution Steps

### 1. Infrastructure Deployment
- Created a dedicated **Resource Group** in Azure.
- Deployed a Windows 10 VM.
- Configured the **Network Security Group (NSG)** to allow all inbound traffic (`ANY` to `ANY`) to attract global botnet activity.

### 2. Log Analytics & Sentinel Setup
- Provisioned a **Log Analytics Workspace**.
- Onboarded **Microsoft Sentinel** to the workspace.
- Configured **Microsoft Defender for Cloud** to collect "All Events" from the VM.

### 3. Honeypot Configuration
- Logged into the VM and disabled **Windows Defender Firewall** for all profiles.
- Deployed a custom PowerShell script that monitors the `Security` event log for failed RDP logins.
- The script uses the `ipgeolocation.io` API to convert the attacker's IP address into Latitude, Longitude, and Country data.

### 4. Custom Log Parsing & Visualization
- Configured a **Custom Log** in Azure to ingest the specialized data produced by the PowerShell script.
- Created a **Sentinel Workbook** using a custom KQL query to visualize the attack data on a world map.

---

##  KQL Attack Map Query
This query was used to parse the custom logs and generate the geographical visualization:

```kusto
FAILED_RDP_WITH_GEO_CL 
| extend latitude = extract(@"latitude:([0-9\.-]+)", 1, RawData),
         longitude = extract(@"longitude:([0-9\.-]+)", 1, RawData),
         destinationhost = extract(@"destinationhost:([^,]+)", 1, RawData),
         username = extract(@"username:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
```

---

###  Project Insights
Attack Speed: Brute-force attempts began within 10-15 minutes of the VM being live.

Global Reach: Captured thousands of failed login attempts from IPs worldwide, specifically targeting the Administrator account.

Visualization Value: Demonstrated how SIEM tools turn massive amounts of raw log data into actionable security intelligence.

---

###  Disclaimer
For Educational Purposes Only. This project involves intentionally weakening security for research. Ensure you work in an isolated environment and delete all resources after the lab to prevent unexpected Azure costs.


