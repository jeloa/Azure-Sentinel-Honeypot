# Azure Sentinel Honeypot Lab 

> **An end-to-end SOC-focused honeypot deployment using Microsoft Sentinel (SIEM) to detect and investigate real-world attack activity in Azure.**

This project demonstrates hands-on experience with **Azure security monitoring, log ingestion, KQL analysis, and incident response**, aligned with **Junior SOC / Cyber Defense Analyst** responsibilities.

---

##  Project Overview

This lab deploys an intentionally exposed Windows virtual machine in Azure to act as a **honeypot**. Attack telemetry (primarily RDP brute-force attempts) is collected via **Azure Monitor Agent**, ingested into **Log Analytics**, and analyzed in **Microsoft Sentinel**.

The goal is to simulate real-world attacker behavior and practice **threat detection, investigation, and alerting**.

---

##  Objectives

* Deploy a honeypot VM with exposed RDP
* Ingest Windows security logs into Microsoft Sentinel
* Detect brute-force activity using KQL
* Create Sentinel analytics rules and incidents
* Perform basic SOC-style investigation

---

##  Architecture

```
Internet
   ↓
[Attacker IPs]
   ↓
[Azure VM (Windows Honeypot)]
   ↓
[Azure Monitor Agent]
   ↓
[Log Analytics Workspace]
   ↓
[Microsoft Sentinel]
```

---

##  Technologies Used

* Microsoft Azure
* Microsoft Sentinel (SIEM)
* Log Analytics Workspace
* Azure Monitor Agent (AMA)
* Windows Server 2019
* Kusto Query Language (KQL)

---

##  Security Disclaimer

This lab **intentionally weakens security controls** for learning purposes:

* Public IP exposure
* Open RDP (3389) to the internet
* Windows Firewall disabled

 **Do NOT use production credentials** and **delete all resources after completion**.

---

##  Deployment Steps

###  Create Resource Group

* Name: `rg-sentinel-honeypot`
* Region: East US (or preferred region)

 **Screenshot:** Resource group overview page

---

###  Create Log Analytics Workspace

* Name: `law-sentinel-honeypot`
* Same region as resource group

 **Screenshot:** Log Analytics workspace overview

---

###  Enable Microsoft Sentinel

* Attach Sentinel to `law-sentinel-honeypot`

 **Screenshot:** Microsoft Sentinel overview dashboard

---

###  Deploy Honeypot Virtual Machine

**Configuration:**

* OS: Windows Server 2019 Datacenter
* Size: Standard B1s
* Authentication: Username + Password

 **Screenshot:** VM overview (show public IP, OS, status)

---

###  Configure Network Security Group (Critical)

Allow inbound RDP from **Any source**:

* Port: 3389
* Protocol: TCP

 **Screenshot:** NSG inbound rule showing RDP open to Any

---

###  Disable Windows Firewall (Inside VM)

* Turn OFF firewall for Domain, Private, and Public profiles

 **Screenshot:** Windows Defender Firewall disabled screen

---

###  Connect VM to Log Analytics

* Install **Azure Monitor Agent (AMA)**
* Link VM to Log Analytics workspace

 **Screenshot:** VM extensions showing Azure Monitor Agent installed

---

###  Enable Security Event Collection

* Sentinel → Data Connectors
* Enable **Security Events via AMA**
* Collect **All Security Events**

 **Screenshot:** Data connector status showing VM connected

---

##  Attack Simulation

The VM is left running and exposed to the internet. Within minutes to hours, automated attackers attempt RDP brute-force logins.

No manual attack simulation is required.

---

##  Log Analysis (KQL)

### Failed Login Attempts (Event ID 4625)

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress, Account
| order by Attempts desc
```

 **Screenshot:** Log Analytics results showing multiple attacker IPs

---

### Successful Logins (Event ID 4624)

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, IpAddress, LogonType
```

---

### Brute-Force Detection Logic

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| where Attempts > 10
```

---

##  Incident Creation

A scheduled analytics rule is created in Sentinel to detect excessive failed login attempts.

* Trigger: More than 10 failures from a single IP
* Entity mapping: IP Address

 **Screenshot:** Analytics rule configuration

 **Screenshot:** Generated Sentinel incident

---

##  SOC Investigation Workflow

Within Microsoft Sentinel:

* Review incident timeline
* Investigate attacking IP entity
* Analyze frequency and patterns of attempts
* Validate detection logic

 **Screenshot:** Incident investigation graph view

---



##  Resume-Ready Bullet

* Built an Azure-based Windows honeypot with exposed RDP and ingested security events into Microsoft Sentinel to detect brute-force attacks, create SIEM analytics rules, and investigate incidents using KQL.

---

##  Cleanup

Delete the resource group after completing the lab to avoid unnecessary charges:

```
rg-sentinel-honeypot
```


---

##  Microsoft Sentinel Workbook (SOC Dashboard)

This section documents the creation of a **custom Microsoft Sentinel Workbook** to visualize honeypot activity. Workbooks are heavily used by SOC teams for **monitoring, triage, and reporting**, making this a strong portfolio signal.

---

###  Workbook Objectives

* Visualize brute-force activity at a glance
* Identify top attacker IPs and targets
* Track attack volume over time
* Support rapid SOC triage

---

###  Create a New Workbook

1. Microsoft Sentinel → **Workbooks**
2. Click **Add workbook**
3. Select **Blank workbook**
4. Click **Edit**
5. Set title:

   ```
   Azure Honeypot – RDP Brute Force Monitoring
   ```

 **Screenshot:** Blank workbook in edit mode

---

###  Workbook Visualization Panels

####  Panel 1: Failed RDP Logins Over Time (Time Chart)

**Purpose:** Detect spikes in brute-force activity

**Query:**

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by bin(TimeGenerated, 1h)
```

**Visualization:** Time chart

 **Screenshot:** Time-based attack trend

---

####  Panel 2: Top Attacking IP Addresses (Bar Chart)

**Purpose:** Identify most aggressive attacker sources

**Query:**

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| order by Attempts desc
```

**Visualization:** Bar chart

 **Screenshot:** Top attacking IPs bar chart

---

####  Panel 3: Targeted User Accounts (Table)

**Purpose:** Identify which accounts are being targeted

**Query:**

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by Account
| order by Attempts desc
```

**Visualization:** Grid / Table

 **Screenshot:** Targeted accounts table

---

####  Panel 4: Successful Logins (High-Risk Event)

**Purpose:** Quickly identify potential compromise

**Query:**

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, IpAddress, LogonType
```

**Visualization:** Table

 **Screenshot:** Successful login events

---

###  Save the Workbook

* Click **Done Editing**
* Save workbook to the resource group

 **Screenshot:** Saved workbook overview

---

##  MITRE ATT&CK Mapping

Mapping detections to **MITRE ATT&CK** demonstrates structured threat analysis and is highly valued in SOC environments.

---

###  Relevant ATT&CK Techniques

| Tactic            | Technique ID | Technique Name       | Evidence                           |
| ----------------- | ------------ | -------------------- | ---------------------------------- |
| Credential Access | T1110        | Brute Force          | Repeated RDP login failures (4625) |
| Initial Access    | T1078        | Valid Accounts       | Successful RDP login (4624)        |
| Lateral Movement  | T1021.001    | Remote Services: RDP | RDP-based access attempts          |

---

###  Detection-to-ATT&CK Alignment

**Analytics Rule:** RDP Brute-Force Detection

* **ATT&CK Technique:** T1110 – Brute Force
* **Data Source:** Windows Security Events
* **Signal:** Excessive failed authentication attempts from a single IP

This mapping can be added directly in Sentinel analytics rules under **MITRE ATT&CK tactics and techniques**.

 **Screenshot:** Analytics rule showing MITRE ATT&CK mapping

---

##  Resume-Ready Enhancements

You can now truthfully state:

* Built custom Microsoft Sentinel workbooks to visualize brute-force activity and map detections to MITRE ATT&CK techniques for SOC monitoring and incident response.

---

##  Cleanup

Delete the resource group after completing the lab to avoid unnecessary charges:

```
rg-sentinel-honeypot
```

---


##  Future Improvements

* Automation playbooks (Logic Apps)
* Alert enrichment with GeoIP
* Linux SSH honeypot expansion
* Threat intelligence feeds

---

**Author:** Jelo Abejero
**Focus:** SOC Analyst | Cyber Defense | Cloud Security
