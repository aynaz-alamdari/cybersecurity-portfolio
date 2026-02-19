# 🛡️ Microsoft Sentinel – Brute Force Login Detection

## Overview
This project demonstrates detection of brute-force login attempts using Microsoft Sentinel.  
A Windows VM sends Security Event logs (Event ID 4625 – failed login) to a Log Analytics Workspace via **Azure Monitor Agent (AMA)** and **Data Collection Rules (DCR)**. Sentinel then generates alerts based on multiple failed login attempts.

---

## Key Steps
1. Deploy Windows VM in Azure  
2. Install Azure Monitor Agent (AMA)  
3. Configure Data Collection Rule (DCR) to collect Security Event logs  
4. Verify log ingestion in Log Analytics Workspace  
5. Create an analytic rule in Sentinel to alert on multiple failed logins  
6. Test detection by performing failed RDP login attempts  

---

## Technologies Used
- Microsoft Sentinel  
- Azure Monitor Agent (AMA)  
- Data Collection Rules (DCR)  
- Log Analytics Workspace  
- Kusto Query Language (KQL)  

---

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access  
- **Technique:** T1110 – Brute Force  

---

## Screenshots

### Log Ingestion Verification
![Log Ingestion](./images/log_ingestion.png)

### Analytic Rule Setup
![Analytic Rule](./images/analytic_rule.png)

### Alert Trigger / Incident
![Incident Trigger](./images/incident_trigger.png)

### Sentinel Workbook / Dashboard
![Dashboard](./images/dashboard.png)

---

## Key Takeaway
Proper configuration of AMA + DCR enables Windows Security events to be ingested into Sentinel, allowing SOC teams to detect and respond to suspicious activity.
