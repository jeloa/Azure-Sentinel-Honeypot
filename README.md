# Azure Sentinel (SIEM) Honeypot & Threat Mapping

##  Objective
The goal of this project was to deploy a cloud-native SIEM (Microsoft Sentinel) and connect it to a live virtual machine acting as a "honeypot." By intentionally exposing the VM to the internet, I observed real-world brute-force attacks (RDP) from global IP addresses and used KQL to analyze the threat landscape.

##  Technologies & Tools Used
- **Microsoft Azure** (Cloud Provider)
- **Microsoft Sentinel** (SIEM)
- **Log Analytics Workspace** (Log Management)
- **Kusto Query Language (KQL)** (Data Analysis)
- **Windows 10 Pro** (Virtual Machine)

##  Architecture Overview
1. **Exposure:** A Windows 10 VM was deployed with all ports open to the public internet to attract attackers.
2. **Ingestion:** Security event logs (Event ID 4625 - Failed Logons) were ingested into a Log Analytics Workspace via the Azure Monitor Agent (AMA).
3. **Detection:** Microsoft Sentinel was used to query these logs and visualize the volume and origin of the attacks.

---

##  Lab Results & Analysis

### 1. The Trap (Network Security Configuration)
I configured a Network Security Group (NSG) with an "Allow All" inbound rule. Within minutes of deployment, automated bots began scanning the IP.
> *[INSERT SCREENSHOT 1 HERE]*

### 2. Log Ingestion (The Pipeline)
Using the Windows Security Events connector, I streamed live telemetry to Sentinel. 
> *[INSERT SCREENSHOT 2 HERE]*

### 3. Threat Hunting with KQL
I utilized the following KQL query to identify the most persistent attackers:

```kusto
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress, Computer, TargetUserName
| sort by count_ desc
