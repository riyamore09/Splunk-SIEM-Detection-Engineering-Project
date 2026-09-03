# Splunk SIEM Detection Engineering Project

Development and testing of custom Splunk correlation rules for detecting **credential stuffing**, **DNS tunnelling**, and **suspicious PowerShell execution** — built and tested end-to-end in a controlled Splunk Enterprise lab.

![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black?logo=splunk)
![SPL](https://img.shields.io/badge/Language-SPL-blue)
![MITRE ATT%26CK](https://img.shields.io/badge/Mapped-MITRE%20ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## Overview

This project demonstrates practical SIEM detection engineering: taking three common attack techniques, identifying the log sources and indicators that reveal them, writing and tuning custom SPL detection logic, converting that logic into alerts, and validating everything against controlled test data.

| Technique | Detection Focus | Main Log Source | MITRE ATT&CK |
|---|---|---|---|
| Credential Stuffing | Repeated auth failures across multiple accounts from one source | Authentication logs | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) |
| DNS Tunnelling | Abnormal DNS query volume, length, and uniqueness | DNS logs | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| PowerShell Attack | Suspicious command-line indicators and risk scoring | Windows / Sysmon / PowerShell logs | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |

> ⚠️ All testing was performed using simulated/synthetic log data in a controlled lab environment. No attacks were performed against external or unauthorized systems.

---

## Architecture

```text
                    LAB
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
 Authentication      DNS          Windows/Sysmon
    Logs             Logs            Logs
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                    SPLUNK
                       │
              ┌────────┴────────┐
              ▼                 ▼
        Detection Rules      Dashboard
              │
              ▼
           Alerts
              │
              ▼
       SOC Investigation
```

---

## Detection Rules

### 1. Potential Credential Stuffing
```spl
index=auth status=failed
| stats count AS failed_attempts dc(user) AS unique_users values(user) AS targeted_users BY src_ip
| where failed_attempts >= 10 AND unique_users >= 5
| sort -failed_attempts
```
Flags a single source IP generating **10+ failed logins** against **5+ distinct accounts**.

### 2. Potential DNS Tunnelling
```spl
index=dns
| eval query_length=len(query)
| stats count AS dns_requests
    avg(query_length) AS avg_query_length
    dc(query) AS unique_queries
    BY src_ip
| where dns_requests > 100
    AND avg_query_length > 50
    AND unique_queries > 50
| sort -unique_queries
```
Flags a host with high DNS volume, long average query length, and a high number of unique queries — combined, not individually.

### 3. Suspicious PowerShell Execution
```spl
index=windows
| search process_name="powershell.exe"
| search CommandLine="*-EncodedCommand*"
    OR CommandLine="*-enc*"
    OR CommandLine="*ExecutionPolicy Bypass*"
    OR CommandLine="*-WindowStyle Hidden*"
```
A weighted **risk-scoring** variant is also included, assigning points per suspicious indicator (`-EncodedCommand`, `ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `DownloadString`, `Invoke-WebRequest`) rather than alerting on a single keyword.

Full queries, tuning notes, and time-windowed variants are in [`detection-rules/`](./detection-rules).

---

## Alert Configuration

| Detection | Schedule | Lookback | Severity |
|---|---:|---:|---|
| Credential Stuffing | 5 min | 10 min | High |
| DNS Tunnelling | 5 min | 5 min | Medium/High |
| Suspicious PowerShell | 5 min | 10 min | High |

---

## Testing Summary

| Test | Expected Result | Actual Result |
|---|---|---|
| Normal login | No alert | No alert |
| Multiple failures against one account | Low/no alert | Tuned threshold |
| Multiple failures against many accounts | Alert | ✅ Triggered |
| Normal DNS activity | No alert | ✅ No alert |
| High-volume long DNS queries | Alert | ✅ Triggered |
| Normal PowerShell administration | No alert | ✅ No alert |
| Suspicious PowerShell parameters | Alert | ✅ Triggered |

All three rules were also checked for false-positive causes (shared NAT IPs, CDN/telemetry DNS traffic, legitimate admin PowerShell use) and tuned accordingly — see [`documentation/detection-test-results.md`](./documentation/detection-test-results.md).

---

## Project Structure

```text
Splunk-SIEM-Detection-Project/
│
├── README.md
│
├── report/
│   ├── Splunk_SIEM_Detection_Report.docx          # Full design report
│   └── SIEM_Lab_Implementation_Report.docx        # Hands-on build & test log
│
├── detection-rules/
│   ├── credential-stuffing.spl
│   ├── dns-tunnelling.spl
│   └── powershell-detection.spl
│
├── test-data/
│   ├── authentication-test.csv
│   ├── dns-test.csv
│   └── powershell-test.csv
│
├── screenshots/
│   ├── credential-stuffing/
│   ├── dns-tunnelling/
│   ├── powershell/
│   └── dashboard/
│
└── documentation/
    └── detection-test-results.md
```

---

## Getting Started

1. **Install Splunk Enterprise** and log in at `http://localhost:8000`.
2. **Create three indexes**: `auth`, `dns`, `windows` (`Settings → Indexes → New Index`).
3. **Upload the sample data** from [`test-data/`](./test-data) (`Settings → Add Data → Upload`), matching each CSV to its index.
4. **Run the detection searches** from [`detection-rules/`](./detection-rules) against the uploaded data.ww
5. **Save each search as an alert** using the schedule/severity table above.
6. **Build the SOC dashboard** with panels for total alerts, credential-stuffing sources, DNS activity, PowerShell activity, and alert severity.


---

## Dashboard Panels

| Panel | SPL |
|---|---|
| Credential Stuffing Sources | `index=auth status=failed \| stats count dc(user) AS unique_users BY src_ip \| sort -count` |
| DNS Activity | `index=dns \| stats count dc(query) AS unique_queries BY src_ip \| sort -count` |
| PowerShell Activity | `index=windows process_name="powershell.exe" \| stats count BY host user \| sort -count` |
| Alert Severity | `index=_alerts \| stats count BY severity` |

---

## Limitations

- Static thresholds are lab-derived and must be re-baselined for any real environment.
- DNS query length/volume alone does not *prove* tunnelling — it flags anomalous behavior for investigation.
- PowerShell is widely used legitimately; detections rely on combined indicators and risk scoring, not single keywords.
- Credential-stuffing detection by source IP alone is weaker behind shared NAT/corporate proxies.

---

## Skills Demonstrated

Splunk · SPL · SIEM · SOC Operations · Detection Engineering · Log Analysis · Event Correlation · Windows Security Monitoring · PowerShell Monitoring · DNS Security Monitoring · Authentication Monitoring · Alert Triage · False-Positive Analysis · Detection Tuning · MITRE ATT&CK Mapping · Incident Investigation

---

## Author

**Riya More**
BCA (Cloud Computing & Cybersecurity), Sri Balaji University Pune
GitHub: [@riyamore09](https://github.com/riyamore09)
