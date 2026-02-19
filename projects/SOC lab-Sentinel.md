# SOC Lab – Microsoft Sentinel Setup

## Lab Objective

This lab demonstrates how to:

- Deploy a Windows VM in Azure  
- Connect it to **Microsoft Sentinel** via **Log Analytics Workspace**  
- Collect and verify real logs (Heartbeat, SecurityEvent)  
- Create **KQL queries** and **alert rules**  
- Set up **workbooks/dashboards** for SOC monitoring  

---

## 1️⃣ Environment Setup

| Resource | Name / Type |
|----------|------------|
| Subscription | Pay-As-You-Go (Owner) |
| Resource Group | SOC-Lab-RG |
| VM | Windows Server 2016 |
| Log Analytics Workspace | SOCLabWorkspace |
| VM Identity | System-Assigned Managed Identity Enabled |

**Screenshot Placeholder:**  
![Lab_Setup](images/Lab_Setup.png)
---

## 2️⃣ Enable Log Collection

### Step 1 – Enable Managed Identity

1. Go to **Virtual Machine → Identity → System Assigned → On**  
2. Click **Save**  

**Screenshot Placeholder:**  
`![Enable Managed Identity](./screenshots/managed_identity.png)`

---

### Step 2 – Assign Log Analytics Contributor Role

1. Go to **Log Analytics Workspace → Access control (IAM) → + Add → Add role assignment**  
2. Role: **Log Analytics Contributor**  
3. Assign access to: **Managed identity → Select your VM**  
4. Click **Review + Assign**

**Screenshot Placeholder:**  
`![Role Assignment](./screenshots/role_assignment.png)`

---

### Step 3 – Create Data Collection Rule (DCR)

1. Search **Data Collection Rules → + Create**  
2. **Basics:**  
   - Platform Type: `Windows`  
   - Subscription: Your Pay-As-You-Go  
   - Resource Group: Same as VM  
   - Name: `SOC-DCR`  
3. **Data Sources:** Add Windows Event Logs:  
   - Security  
   - System  
   - Application  
4. **Destination:** Your Log Analytics Workspace  
5. **Resources:** Add your **VM**  
6. Click **Review + Create → Create**

**Screenshot Placeholder:**  
`![Data Collection Rule](./screenshots/dcr_creation.png)`

---

## 3️⃣ Verify Logs

Run queries in **Log Analytics Workspace → Logs** using KQL:

**Heartbeat Logs**

```kusto
Heartbeat
| sort by TimeGenerated desc
| take 10

Security Events

SecurityEvent
| sort by TimeGenerated desc
| take 10


Screenshot Placeholder:
![Log Verification](./screenshots/log_verification.png)

## 4️⃣ Create Analytic Rules (Alerts)
Alert 1 – Multiple Failed Logins

Query:
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedLogins=count() by Account, bin(TimeGenerated, 1h)
| where FailedLogins >= 5


Severity: Medium

MITRE Tactic: Credential Access

Frequency: Run every 5 minutes

Lookback: Last 5 minutes

Screenshot Placeholder:
![Failed Logins Alert](./screenshots/alert_failed_logins.png)

Alert 2 – High-Privilege Account Usage

Query:

SecurityEvent
| where EventID in (4670, 4672)


Severity: High

MITRE Tactic: Privilege Escalation

Screenshot Placeholder:
![High Privilege Alert](./screenshots/alert_high_privilege.png)

Alert 3 – Service Stops/Starts

Query:

SecurityEvent
| where EventID == 7036
| summarize count() by EventData, bin(TimeGenerated, 1h)


Severity: Medium

MITRE Tactic: Defense Evasion

Screenshot Placeholder:
![Service Alert](./screenshots/alert_service.png)

## 5️⃣ Dashboard / Workbook Setup

Go to Microsoft Sentinel → Workbooks → + Create new workbook

Add sections:

VM Heartbeat (Time chart)

Top Failed Logins by Account (Bar chart)

Privileged Account Activity (Table)

Service Events Over Time (Line chart)

Screenshot Placeholder:
![Workbook Dashboard](./screenshots/workbook_dashboard.png)

## 6️⃣ Triggering Alerts (For Lab Testing)

Failed Login Alert: Log in to the VM with an incorrect password multiple times

High-Privilege Alert: Run a task as Administrator (EventID 4672)

Service Alert: Stop/start a Windows service manually

Check Microsoft Sentinel → Incidents to see alerts appear.

Screenshot Placeholder:
![Alert Trigger](./screenshots/alert_trigger.png)

## 7️⃣ Lessons Learned

Modern Azure portal no longer shows old MMA agent menus

Workspace Keys are deprecated → use Managed Identity + DCR

Third-party extensions (e.g., Xitoring) do not send logs to Sentinel

The DCR approach ensures secure, scalable log ingestion

Using KQL queries and analytic rules, a SOC team can detect suspicious activity in near real-time

## 8️⃣ References

Microsoft Sentinel Documentation

Azure Monitor Agent & Data Collection Rules

Kusto Query Language (KQL) Reference
