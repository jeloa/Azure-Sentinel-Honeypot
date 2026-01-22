# Azure Sentinel (SIEM) Honeypot Home Lab

## 🔐 Azure Sentinel Honeypot Homelab

This project is a hands-on walkthrough for building an **Azure-based Honeypot SIEM lab** using **Microsoft Sentinel**.  
The goal is to simulate real-world attacks, collect telemetry, analyze logs, and visualize attacker activity across the globe.

Honeypots are intentionally vulnerable systems designed to attract malicious traffic. Combined with a **SIEM (Security Information and Event Management)** solution like **Microsoft Sentinel**, they provide deep visibility into attacker behavior, techniques, and patterns.

This lab demonstrates how cybersecurity, cloud, and automation come together in a real SOC-style environment.

---

## 🎯 Learning Objectives

By completing this lab, you will gain experience in:

- Deploying Azure infrastructure (VMs, Log Analytics, Sentinel)
- Using Microsoft Sentinel as a SIEM platform
- Collecting and analyzing Windows Security Event Logs
- Writing and using **Kusto Query Language (KQL)**
- Integrating **third-party APIs** for data enrichment
- Building **Sentinel Workbooks** with an interactive world attack map
- Understanding real-world SOC workflows

---

## 🛠 Technologies & Requirements

### Cloud & Security
- Microsoft Azure Account
- Microsoft Sentinel (SIEM)
- Azure Log Analytics Workspace
- Microsoft Defender for Cloud
- Azure Virtual Machines (Windows)
- Network Security Groups (NSG)
- Sentinel Workbooks

### Tools & Languages
- PowerShell
- Kusto Query Language (KQL)
- Remote Desktop Protocol (RDP)

### Third-Party
- **ipgeolocation.io** (IP geolocation API)
- Custom PowerShell script authored by **Josh Madakor**

---

## 🧱 Architecture Overview

- Azure Resource Group
- Vulnerable Windows VM (Honeypot)
- Network Security Group (Open inbound access)
- Log Analytics Workspace
- Microsoft Sentinel
- Custom Logs with Geo-enriched data
- Sentinel Workbook (World Attack Map)

---

## 🚀 Step-by-Step Deployment Guide

---

### Step 1: Create a Microsoft Azure Account

Microsoft provides **$200 of free Azure credit for 30 days** for new users.

Sign up at:
- https://azure.microsoft.com

---

### Step 2: Deploy the Honeypot Virtual Machine

#### Create Virtual Machine
- Go to **Azure Portal** → search for **Virtual Machines**
- Click **Create → Azure Virtual Machine**

#### Project Details
- Resource Group: `honeypot-lab`

#### Instance Details
- VM Name: `honeypot-vm`
- Region: `(US) West US 3`
- Availability: No infrastructure redundancy required
- Security Type: Standard
- Image: Windows 10 Pro (22H2) x64 Gen2
- Size: `Standard_D2s_v3` (2 vCPU, 8 GB RAM)

#### Administrator Account
- Create a username and password  
⚠️ Save these credentials — they are required for RDP access.

#### Inbound Port Rules
- Allow selected ports
- RDP (3389)

---

### Step 3: Configure Network Security Group (NSG)

- NIC Network Security Group: **Advanced → Create New**
- Remove default inbound rule (allow-rdp)
- Add new inbound rule:
  - Destination Port: `*`
  - Protocol: Any
  - Action: Allow
  - Priority: `100`
  - Name: `allow-any-inbound`

This intentionally exposes the VM to attract attackers.

---

### Step 4: Create Log Analytics Workspace

- Search for **Log Analytics Workspaces**
- Create a new workspace:
  - Name: `honeypot-law`
  - Resource Group: `honeypot-lab`
  - Region: `West US 3`

This workspace collects Windows Event Logs and custom logs.

---

### Step 5: Enable Microsoft Defender for Cloud

- Search for **Microsoft Defender for Cloud**
- Go to **Environment Settings**
- Select your subscription → `honeypot-law`

#### Defender Plans
- Foundational CSPM: ON
- Servers: ON
- SQL Servers: OFF

#### Data Collection
- Select **All Events**
- Save settings

---

### Step 6: Connect VM to Log Analytics

- Go to **Log Analytics Workspaces → honeypot-law**
- Select **Virtual Machines**
- Choose `honeypot-vm`
- Click **Connect**

---

### Step 7: Enable Microsoft Sentinel

- Search for **Microsoft Sentinel**
- Click **Create**
- Select `honeypot-law`
- Click **Add**

Sentinel is now active as your SIEM.

---

### Step 8: Disable Windows Firewall (Honeypot)

#### Test Connectivity
From your local machine:

```bash
ping <VM_PUBLIC_IP>
```

Disable Firewall Inside VM
- RDP into the VM
- Search wf.msc
- Open Windows Defender Firewall Properties
-Turn OFF:
  - Domain Profile
  - Private Profile
  - Public Profile

Re-test ping — it should now succeed.

⚠️ Do this ONLY in a lab environment.

---

### Step 9: Automate Security Log Export (PowerShell)

### Inside the VM:
- Open PowerShell ISE
- Paste the custom PowerShell script (Josh Madakor)
- Save as `log_exporter.ps1`

### API Setup
- Create an account at ipgeolocation.io
- Copy API key
- Paste into script:

```
$API_KEY = "<YOUR_API_KEY>"
```
### Run the script to continuously generate logs.

- Logs are written to:
```
C:\ProgramData\failed_rdp.log
```

---

### Step 10: Create Custom Log in Log Analytics

- Copy contents of `failed_rdp.log`
- Save locally as `failed_rdp.log` (TXT format)
- Go to Log Analytics Workspace → Custom Logs
- Add custom log:
  - Name: `FAILED_RDP_WITH_GEO`
  -  Path: `C:\ProgramData\failed_rdp.log`

 ---

### Step 11: Query & Extract Logs Using KQL
```
Paste into Log Analytics → Logs:
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```

### Step 12: Build World Attack Map (Sentinel Workbook)
- Microsoft Sentinel → Workbooks → Add Workbook → Edit
- Remove default widgets
- Add Query:
```
FAILED_RDP_WITH_GEO_CL
| parse RawData with * "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" Sourcehost ",state:" State ", country:" Country ",label:" Label ",timestamp:" Timestamp
| where DestinationHost != "samplehost"
| where Sourcehost != ""
| summarize event_count=count() by Sourcehost, Latitude, Longitude, Country, Label, DestinationHost
```
### Visualization Settings
- Visualization: Map
- Location: Latitude / Longitude
- Size by: event_count
- Coloring: Heatmap
- Metric Label: label

Save as:
Failed RDP International Map

---

## What This Lab Demonstrates
- SIEM fundamentals
- SOC analyst workflows
- Cloud security monitoring
- Threat detection & analysis
- KQL log querying
- Data enrichment & visualization

---

### Shut Down Resources (CRITICAL)

To avoid charges:
- Go to Resource Groups
- Select `honeypot-lab`
- Click Delete
- Confirm resource group name
- Enable Force delete

---

## Disclaimer

This project is for educational purposes only.
Never deploy insecure configurations in production environments.

---
