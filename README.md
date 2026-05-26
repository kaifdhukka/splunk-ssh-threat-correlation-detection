# Multi-Stage SSH Attack Detection and Threat Correlation using Splunk Enterprise Security

## Project Overview

This project demonstrates advanced SSH brute-force attack detection and threat correlation using Splunk Enterprise Security.

A multi-stage attack scenario was simulated from a Kali Linux attacker machine against an Ubuntu target system. Linux authentication telemetry was ingested into Splunk, where custom SPL correlation rules detected brute-force authentication anomalies and visualized attack behavior through an interactive threat monitoring dashboard.

---

## Lab Architecture

* **Attacker Machine:** Kali Linux
* **Target Machine:** Ubuntu
* **SIEM Platform:** Splunk Enterprise
* **Log Source:** `/var/log/auth.log`

---

## Attack Simulation Workflow

### Phase 1: Brute-Force Authentication Attempts

Generated repeated failed SSH login attempts from Kali Linux.

### Phase 2: Successful Authentication

Performed successful login after multiple failed attempts.

### Phase 3: Post-Compromise Enumeration

Executed reconnaissance commands:

```bash
whoami
hostname
pwd
ls -la
cat /etc/passwd
ps aux
```

---

## Detection Logic

Custom SPL correlation identified:

* Multiple failed SSH login attempts
* Successful authentication following repeated failures
* Source IP anomaly correlation
* Authentication pattern deviations

---

## SPL Correlation Query

```spl
source="/var/log/auth.log" ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "for (?<user>\w+)"
| eval status=if(searchmatch("Failed password"),"Failed","Success")
| stats count(eval(status="Failed")) as failed_attempts count(eval(status="Success")) as successful_logins by src_ip user
| where failed_attempts >=5 AND successful_logins >=1
```

---

## Dashboard Components

### Top Attacking IPs

Visualized source IPs generating excessive failed login attempts.

### SSH Attack Timeline

Displayed temporal attack progression.

### Authentication Correlation Alerts

Detected failed-to-success authentication sequences.

### Targeted Accounts

Analyzed attacker account targeting patterns.

---

## Investigation Findings

The correlation engine successfully detected:

* Brute-force activity from attacker IP addresses
* Successful authentication after repeated failures
* Authentication anomalies indicating compromise risk

---

## Skills Demonstrated

* Splunk Enterprise Security
* SPL Query Engineering
* SSH Brute-Force Detection
* Event Correlation
* Threat Hunting
* Incident Investigation
* Linux Log Analysis
* SOC Monitoring

---

## Key Outcome

Successfully engineered and validated a Splunk-based multi-stage SSH threat detection pipeline capable of identifying brute-force compromise patterns in real-time.
