# Azure Sentinel Honeypot Project  

> **A complete, beginner-friendly, end‑to‑end Microsoft Sentinel project that simulates real-world attacks, detects them using SIEM analytics, visualizes activity with workbooks, and maps detections to MITRE ATT&CK.**


---

##  What This Project Proves

By completing this project, we demonstrate:

* Real Azure hands-on experience
* SIEM fundamentals (Microsoft Sentinel)
* Log ingestion and analysis
* KQL querying
* Incident detection and investigation
* Threat modeling using MITRE ATT&CK
* Professional documentation

This is **not just a lab** — this mirrors real SOC workflows.

---

##  We will:

1. Create a **Windows virtual machine** and expose it to the internet
2. Let real attackers attempt to log in (honeypot)
3. Collect Windows security logs
4. Analyze those logs in **Microsoft Sentinel**
5. Detect brute-force attacks
6. Visualize attacks using a **Sentinel Workbook**
7. Map attacker behavior to **MITRE ATT&CK**

---

##  Architecture Overview

```
Internet
   ↓
[Attacker IPs]
   ↓
[Windows VM (Honeypot)]
   ↓
[Azure Monitor Agent]
   ↓
[Log Analytics Workspace]
   ↓
[Microsoft Sentinel]
```

---

## Important Security Warning

This project **intentionally weakens security**:

* Public IP enabled
* RDP (3389) open to the internet
* Firewall disabled

✔ Use fake credentials
✔ Delete resources after finishing
❌ Never do this in production

---

## Prerequisites

* Azure account
* No prior Sentinel experience required
* Basic understanding of Windows

---

# COMPLETE STEP-BY-STEP GUIDE (BEGINNER FRIENDLY)

---

## STEP 1 Create a Resource Group

**Why:** This keeps all resources together so we can delete everything safely later.

1. Go to **Azure Portal**
2. Search for **Resource groups**
3. Click **+ Create**
4. Fill in:

   * Subscription: Default
   * Resource group name: `rg-sentinel-honeypot`
   * Region: Choose any (East US recommended)
5. Click **Review + Create** → **Create**

 Screenshot: Resource group overview

---

## STEP 2 Create a Log Analytics Workspace

**Why:** This is where logs are stored before Sentinel analyzes them.

1. Search **Log Analytics workspaces**
2. Click **+ Create**
3. Configure:

   * Resource group: `rg-sentinel-honeypot`
   * Name: `law-sentinel-honeypot`
   * Region: Same as resource group
4. Click **Review + Create** → **Create**

 Screenshot: Log Analytics workspace overview

---

## STEP 3 Enable Microsoft Sentinel

**Why:** Sentinel is the SIEM that will analyze the logs.

1. Search **Microsoft Sentinel**
2. Click **+ Create**
3. Select workspace: `law-sentinel-honeypot`
4. Click **Add**

 Screenshot: Sentinel overview dashboard

---

## STEP 4 Create the Honeypot Virtual Machine

**Why:** This VM will intentionally attract attackers.

1. Search **Virtual Machines** → **+ Create**
2. Basics tab:

   * Resource group: `rg-sentinel-honeypot`
   * VM name: `vm-honeypot`
   * Region: Same region
   * Image: **Windows Server 2019 Datacenter**
   * Size: **Any available size** (1–2 vCPU, 2–4 GB RAM)
   * Authentication: Password
   * Username: `adminuser`
   * Password: Strong but disposable

 Screenshot: VM basics configuration

---

## STEP 5 Configure Networking (Very Important)

**Why:** Attackers need access to the VM.

1. Networking tab:

   * Public IP: Enabled
   * NIC Network Security Group: Basic
   * Allow inbound port: **RDP (3389)**
   * Source: **Any**
2. Click **Review + Create** → **Create**

 Screenshot: NSG rule showing RDP open to Any

---

## STEP 6 Disable Windows Firewall (Inside VM)

**Why:** Allows better visibility of attack attempts.

1. Connect to VM using **RDP**
2. Open **Windows Defender Firewall**
3. Click **Turn Windows Defender Firewall on or off**
4. Turn OFF:

   * Domain
   * Private
   * Public

 Screenshot: Firewall disabled

---

## STEP 7 Install Azure Monitor Agent (AMA)

**Why:** This sends logs from the VM to Log Analytics.

1. Go to VM → **Extensions + applications**
2. Click **+ Add**
3. Select **Azure Monitor Agent**
4. Click **Create**

 Screenshot: AMA installed

---

## STEP 8 Enable Security Event Collection

**Why:** Sentinel needs Windows security logs.

1. Microsoft Sentinel → **Data connectors**
2. Open **Security Events via AMA**
3. Click **Open connector page**
4. Configure:

   * Subscription: Your subscription
   * Add VM: `vm-honeypot`
   * Event collection: **All Security Events**
5. Click **Apply**

 Screenshot: Security Events connector connected

---

## STEP 9 Wait for Real Attacks

* Leave VM running **30 minutes to 24 hours**
* Automated attackers will attempt RDP logins

 Screenshot: SecurityEvent logs with Event ID 4625

---

## STEP 10 Analyze Logs with KQL

### Failed Login Attempts

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress, Account
| order by Attempts desc
```

 Screenshot: Failed login KQL results

---

## STEP 11 Create an Analytics Rule (Detection)

**Why:** SOC teams rely on alerts, not manual searching.

1. Sentinel → **Analytics** → **Create** → **Scheduled rule**
2. Query:

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| where Attempts > 10
```

3. Set rule name: `RDP Brute Force Detection`
4. Map entity: IP Address
5. Enable rule

 Screenshot: Analytics rule configuration

---

## STEP 12 Investigate Sentinel Incidents

1. Sentinel → **Incidents**
2. Open generated incident
3. Review timeline and IP entity

 Screenshot: Sentinel incident investigation

---

# STEP 13 Build a Microsoft Sentinel Workbook

**Why:** SOC analysts monitor dashboards, not raw logs.

1. Sentinel → **Workbooks** → **Add workbook**
2. Choose **Blank workbook** → **Edit**
3. Title:

```
Azure Honeypot – RDP Brute Force Dashboard
```

---

### Workbook Panels

**Panel 1: Failed Logins Over Time**

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 1h)
```

Visualization: Time chart

**Panel 2: Top Attacking IPs**

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress
| order by count_ desc
```

Visualization: Bar chart

**Panel 3: Targeted Accounts**

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by Account
```

Visualization: Table

 Screenshot: Complete workbook dashboard

---

#  STEP 14 Attacker Geo Map (World Map Visualization)

**Why this matters (Beginner explanation):**
SOC analysts don’t just look at logs — they need to quickly understand **where attacks are coming from**. A geo map helps identify attack concentration, scanning behavior, and high-risk regions.

This map is built using a **Microsoft Sentinel Workbook** with **GeoIP enrichment**.

---

## STEP 14.1 Open Your Sentinel Workbook

1. Go to **Microsoft Sentinel**
2. Click **Workbooks**
3. Open your existing honeypot workbook
4. Click **Edit**
5. Click **Add** → **Add query**

📸 Screenshot: Workbook in edit mode

---

## STEP 14.2 Use This KQL Query (GeoIP Enrichment)

Paste this query into the workbook query editor:

```kql
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize Attempts = count() by IpAddress
| evaluate geo_info_from_ip_address(IpAddress)
| project IpAddress, Attempts, Country, Region, City, Latitude, Longitude
```

**What this query does (simple explanation):**

* Collects failed login attempts
* Groups them by attacker IP
* Converts IP addresses into geographic locations
* Outputs coordinates needed for a map

---

## STEP 14.3 Configure the Map Visualization 

1. Under **Visualization**, select **Map**
2. Set:

   * Latitude field: `Latitude`
   * Longitude field: `Longitude`
   * Size by: `Attempts`
   * Location info: `Country`
3. Click **Apply**

 You should now see a **world map with attacker locations**

 Screenshot: World map showing attacker IP locations

---

## STEP 14.4 Save the Workbook

1. Click **Done Editing**
2. Save the workbook to your resource group

 Screenshot: Saved workbook with geo map panel

---

#  STEP 15 MITRE ATT&CK Mapping

**Why:** Shows structured threat understanding.

| Tactic            | Technique ID | Technique      |
| ----------------- | ------------ | -------------- |
| Credential Access | T1110        | Brute Force    |
| Initial Access    | T1078        | Valid Accounts |
| Lateral Movement  | T1021.001    | RDP            |

Add MITRE mapping directly in the analytics rule.

 Screenshot: Analytics rule with MITRE ATT&CK mapping

---

##  Lessons Learned (What Makes This Project Unique)

* Real attackers appear within hours
* Brute-force attempts are noisy
* Threshold tuning is important
* Workbooks simplify SOC monitoring
* MITRE mapping improves alert context




---

##  Cleanup (VERY IMPORTANT)

Delete the resource group to stop billing:

```
rg-sentinel-honeypot
```



---

**Author:** Jelo Abejero
**Focus:** SOC Analyst | Cyber Defense | Cloud Security
