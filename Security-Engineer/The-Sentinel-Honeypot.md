# Azure Sentinel Honeypot Lab (End-to-End)

> **Goal:** Deploy a vulnerable honeypot VM in Azure, collect attack telemetry, and analyze it using **Microsoft Sentinel** (SIEM) with **Log Analytics**.

This lab is beginner-friendly, SOC-oriented, and **resume/GitHub ready**.

---

## 🧠 What You Will Learn

* Azure resource deployment (VM, NSG, Log Analytics)
* Microsoft Sentinel setup
* Honeypot concept using exposed services (RDP)
* Log ingestion and analytics
* Basic KQL for SOC analysis
* Incident investigation workflow

---

## 🧱 Architecture Overview

```
Internet
   ↓
[Attacker]
   ↓
[Azure VM (Honeypot)] -- NSG (Open RDP)
   ↓
[Log Analytics Workspace]
   ↓
[Microsoft Sentinel]
```

---

## ⚠️ Important Notes (Read First)

* This lab **intentionally exposes a VM** to the internet
* **DO NOT** reuse passwords
* Delete resources after testing to avoid charges
* Azure Free Tier / $200 credit is sufficient

---

## 🛠️ Prerequisites

* Azure account
* Basic understanding of cloud concepts
* Browser access (no local tools required)

---

## STEP 1: Create a Resource Group

1. Azure Portal → **Resource Groups**
2. Click **Create**
3. Configure:

   * Name: `rg-sentinel-honeypot`
   * Region: `East US` (or any preferred region)
4. Click **Review + Create**

---

## STEP 2: Create a Log Analytics Workspace

1. Azure Portal → **Log Analytics Workspaces** → Create
2. Configure:

   * Name: `law-sentinel-honeypot`
   * Resource Group: `rg-sentinel-honeypot`
   * Region: Same as resource group
3. Create

---

## STEP 3: Enable Microsoft Sentinel

1. Azure Portal → **Microsoft Sentinel**
2. Click **Create**
3. Select:

   * Workspace: `law-sentinel-honeypot`
4. Add

✔ Sentinel is now active

---

## STEP 4: Create the Honeypot Virtual Machine

### 4.1 VM Basics

1. Azure Portal → **Virtual Machines** → Create
2. Configuration:

   * Name: `vm-honeypot`
   * Image: `Windows Server 2019 Datacenter`
   * Size: `Standard B1s`
   * Authentication: Password
   * Username: `adminuser`
   * Password: (Strong but disposable)

---

### 4.2 Networking (Critical Step)

1. Public IP: **Enabled**
2. NIC Network Security Group:

   * Allow **RDP (3389)** from **Any source**

⚠️ This is intentional for honeypot behavior

---

## STEP 5: Disable Windows Defender Firewall (Inside VM)

> This increases visibility of attack traffic

1. RDP into the VM
2. Open **Windows Defender Firewall**
3. Turn **OFF** firewall for:

   * Domain
   * Private
   * Public

---

## STEP 6: Connect VM to Log Analytics

1. Azure Portal → VM → **Extensions + Applications**
2. Add extension:

   * **Azure Monitor Agent (AMA)**
3. Connect to:

   * Workspace: `law-sentinel-honeypot`

---

## STEP 7: Enable Security Event Logs

1. Microsoft Sentinel → **Data connectors**
2. Open **Security Events via AMA**
3. Configure:

   * Select subscription
   * Add VM
   * Collect: **All Security Events**

---

## STEP 8: Wait for Attacks ⏳

* Leave VM running for **30 minutes – 24 hours**
* RDP brute-force attempts usually appear quickly

---

## STEP 9: Analyze Logs Using KQL

### 9.1 Failed Login Attempts

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress, Account
| order by count_ desc
```

---

### 9.2 Successful Logins

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, IpAddress, LogonType
```

---

### 9.3 Top Attacking Countries

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by Country
| order by count_ desc
```

---

## STEP 10: Create an Incident Rule

1. Sentinel → **Analytics** → Create Rule
2. Type: Scheduled
3. Query:

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| where Attempts > 10
```

4. Map entities:

   * IP → `IpAddress`
5. Enable rule

---

## STEP 11: Incident Investigation

1. Sentinel → **Incidents**
2. Open generated incident
3. Review:

   * Timeline
   * IP entity
   * Related alerts

---

## 🧹 Cleanup (VERY IMPORTANT)

Delete the entire resource group:

```
rg-sentinel-honeypot
```

This stops all billing.

---





