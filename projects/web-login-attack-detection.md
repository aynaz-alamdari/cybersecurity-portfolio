# Website Defacement – Root Cause Analysis

## 1. Incident Summary
A public-facing website was reported as defaced, displaying unauthorized content.
An investigation was conducted to determine how the attacker gained access and
to identify the root cause of the compromise.

---

## 2. Investigation Objectives
- Identify when the defacement occurred
- Determine how the attacker gained access
- Identify indicators of compromise (IOCs)
- Provide remediation and prevention recommendations

---

## 3. Data Sources
- HTTP access logs
- Web server logs
- SIEM platform (Splunk)
- Sourcetype: http / web / stream:http

---

## 4. Investigation Timeline

### Step 1: Reconnaissance Phase
The investigation began by searching for the domain that the website has changed to imreallynotbatman.com
so to investigate and reconnaissance we do a search in the index file as shown in the 
../images/Defacing_Reconnaissance.png

![Description](images/Defacing_Reconnaissance.png)


