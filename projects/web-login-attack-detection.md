# Website Defacement – Root Cause Analysis

## Lab Context

This project is based on a simulated incident scenario and log data provided by the TryHackMe platform.  
All activity, IP addresses, and infrastructure are part of a controlled lab environment used for educational purposes.

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

### Step 1: Reconnaissance Phase: Identify defaced domain activity
The investigation began by searching for the domain **imreallynotbatman.com**, which the website had been redirected to. This search was performed across the web log index to identify related HTTP activity and establish a starting point for reconnaissance.


![Defacing_Reconnaissance](images/Defacing_Reconnaissance.png)

The next step was to identify the source IP address responsible for reconnaissance activity against the web server.

![Identify_reconnaissance_source_IP](images/Identify_reconnaissance_source_IP.png)

The source IP address was validated through analysis of Suricata-generated IDS/IPS alerts.
```spl 
index="botsv1" sourcetype=suricata imreallynotbatman src_ip="40.80.148.xx" 
```

![Validate_IP_By_Suricata](images/Validate_IP_By_Suricata.png)

### Step 2: Exploitation Phase

**Objective:** Analyze potential exploitation attempts to determine if the attacker gained access.  

1. Count the number of occurrences for each source IP address:

![Search_Query_Number_of_ip_Addresses](images/Search_Query_Number_of_ip_Addresses.png)

2. Enumerate source IP addresses associated with inbound HTTP traffic:

![IP_Http_Traffic_To_Webserver.png](images/IP_Http_Traffic_To_Webserver.png)

3. Analyze HTTP methods observed during communications:

![Http_Methods_For_Webserver.png](images/Http_Methods_For_Webserver.png)

The results showed that POST requests were generated exclusively by two source IP addresses. This query was used to filter POST activity:

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.xx" http_method=POST
```
The web server is running **Joomla CMS**, with the administrative login page located at:
```php
/joomla/administrator/index.php
```
Traffic targeting this endpoint was analyzed to detect potential malicious activity, including brute-force login attempts.
![Joomla_BruteForce.png](images/Joomla_BruteForce.png)

**Findings:**

- IP `23.22.63.114` performed a sustained brute-force attack, repeatedly trying different passwords.  
- IP `40.80.148.42` made a single login attempt using the password `"batman"` via a Mozilla browser.

### Step 3: Installation Phase

The investigation revealed that **iamreallynotbatman.com** was compromised via a brute-force attack conducted using an automated Python script. Two separate IP addresses were involved: 

- One carried out the password-guessing attack.  
- The other accessed the server after successful authentication.  

This phase focused on identifying malicious files or payloads uploaded following the compromise.

---

**Malicious File Identification:**

An `.exe` file was found on the server, traced back to one of the malicious IP addresses discovered earlier:

![ExeFile_Source.png](images/ExeFile_Source.png)

Host-centric logs confirmed that the file **`3791.exe`** was executed on the server.

---

**Outbound Traffic Analysis:**

Suricata network logs were analyzed to detect suspicious communications originating from the compromised server. Outbound connections are unusual for this server, so any such traffic was considered potentially malicious.

```spl
index=botsv1 src=192.168.250.70 sourcetype=suricata
```
This query revealed two suspicious destination IP addresses. One of these was 23.22.63.114, which was investigated further:
```spl
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```

While reviewing events for this IP, a suspicious image file was observed in the URL field. To trace its origin and determine whether it was involved in the defacement:
```spl
index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70"
| table _time src dest_ip http.hostname url
```

The query confirmed that the image was externally sourced and likely related to the website defacement:
![MaliciousPicture.png](images/MaliciousPicture.png)

Dynamic DNS Usage:

Before defacing the website, the attacker uploaded a malicious file using a Dynamic DNS service to mask the true source of the attack. Instead of communicating directly with a fixed IP, the server resolved a domain name controlled by the attacker, which dynamically pointed to different IP addresses.

### Step 4: Weaponization Phase

**Objective:** Identify the actual IP address that the attacker’s malicious domain resolved to during the attack and gather intelligence about potential indicators of compromise (IOCs).

**Investigation Steps:**

- Analyzed suspicious IPs and domains identified in previous phases.  
- Used **Robtex** to gather DNS and network information for these domains.  
- Checked the same IPs and domains in **VirusTotal** to detect any known malicious activity.  
- Documented all findings to support the subsequent phases of incident handling.

**Findings:**

- The attacker used a **Dynamic DNS domain** to mask the true source of the attack.  
- By analyzing DNS-related traffic, the actual IP address that the domain resolved to at the time of the file upload was identified.  
- This helped uncover the true origin of the malicious activity.

![DynamicDNS.png](images/DynamicDNS.png)


### Step 5: Delivery Phase

**Objective:** Use the intelligence gathered from previous phases to perform proactive threat hunting and identify associated malware and infrastructure.

**Investigation Steps:**

- Leveraged known Indicators of Compromise (IOCs), including IP addresses, domains, and file hashes.  
- Conducted proactive searches across multiple **Threat Intelligence** and **OSINT** platforms.  
- Correlated findings to identify malware samples and infrastructure linked to the threat actor.  

**Findings:**

- Successfully identified additional malicious infrastructure controlled by the attacker.  
- Confirmed connections between the compromised server, uploaded malicious files, and external attacker-controlled domains.  
- Documented all relevant IOCs for potential remediation and future monitoring.

After authentication, the attacker uploaded and executed a malicious payload, communicated with external infrastructure using Dynamic DNS, and ultimately defaced the website.

## Conclusion

In this lab exercise, as a SOC Analyst, we investigated a cyber-attack in which the attacker defaced the website **`imreallynotbatman.com`** of Wayne Enterprises. The attacker’s activities were mapped to the **7 phases of the Cyber Kill Chain**. Below is a recap of the key findings from each phase:

---

### Reconnaissance Phase

**Objective:** Identify the attacker’s initial scanning and information-gathering activity.

**Findings:**

- IP `40.80.148.42` was scanning the web server.  
- The attacker used **Acunetix** as a web scanner.

---

### Exploitation Phase

**Objective:** Analyze attempts to exploit the server and gain access.

**Findings:**

- Brute-force attacks originated from IP `23.22.63.114`.  
- Access was ultimately achieved via IP `40.80.148.42`.  
- **142 brute-force attempts** were made, with **one successful login**.

---

### Installation Phase

**Objective:** Determine if the attacker uploaded any malicious files after gaining access.

**Findings:**

- Malicious executable **`3791.exe`** was uploaded by the attacker.  
- Sysmon logs confirmed the MD5 hash of the file.

---

### Action on Objective

**Objective:** Identify the outcome of the attacker’s compromise.

**Findings:**

- The attacker defaced the web server.  
- Logs revealed the file responsible for the defacement.

---

### Weaponization Phase

**Objective:** Investigate the attacker’s infrastructure and supporting tools.

**Information Available:**

- Domain: `prankglassinebracket.jumpingcrab.com`  
- IP Address: `23.22.63.114`  

**Findings:**

- Multiple masquerading domains were associated with the attacker’s IPs.  
- Email **`Lillian.rose@po1s0n1vy.com`** was linked to the attacker’s infrastructure.

---

### Delivery Phase

**Objective:** Identify additional malware and secondary attack vectors used by the adversary.

**Findings:**

- Malware **`MirandaTateScreensaver.scr.exe`** was associated with the attacker.  
- MD5 hash of the malware: `c99131e0169171935c5ac32615ed6261`.
  
## Remediation Recommendations

- Enforce strong password policies and account lockout to prevent brute-force attacks.  
- Keep Joomla CMS and all plugins up to date.  
- Monitor outbound connections from web servers for unusual traffic.  
- Implement web application firewalls (WAF) and IDS/IPS rules to block known malicious IPs.  
- Perform regular malware scans and review file integrity.
