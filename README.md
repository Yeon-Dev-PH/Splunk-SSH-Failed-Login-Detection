# Splunk SSH Failed Login Detection

## Project Overview

This project demonstrates a small Security Information and Event Management (SIEM) lab using Splunk Enterprise on Kali Linux.

The project focuses on detecting repeated failed SSH authentication attempts by analyzing Linux authentication logs. Splunk is used to ingest authentication events, identify source IP addresses with more than five failed login attempts, generate an alert, and visualize the results through a dashboard.

## Objectives

- Set up and run Splunk Enterprise on Kali Linux.
- Ingest Linux SSH authentication log events.
- Use Splunk Search Processing Language (SPL) to detect repeated failed SSH logins.
- Extract source IP addresses from authentication events.
- Identify IP addresses with more than five failed login attempts.
- Create a Splunk alert for suspicious SSH authentication activity.
- Create a dashboard to visualize failed login activity.
- Document the detection process and results.

## Tools and Technologies

- Kali Linux
- Splunk Enterprise 10.4.4
- Splunk Search Processing Language (SPL)
- Linux SSH authentication logs
- Synthetic/mock authentication data

## Detection Scenario

The lab simulates repeated failed SSH login attempts from multiple source IP addresses.

The detection rule considers an IP address suspicious when it generates more than five failed SSH authentication attempts within the searched dataset.

> **Note:** The IP addresses used in this project are synthetic/private lab addresses and do not represent real-world attackers.

## SPL Detection Query

The following SPL query searches for failed SSH password authentication events, extracts the source IP address, counts failed attempts by IP, and displays IPs exceeding the threshold.

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| where failed_attempts > 5
| sort - failed_attempts
```

### Detection Logic

1. Search the `main` index for events containing `Failed password`.
2. Extract the source IP address from each authentication event.
3. Count failed authentication attempts for each source IP.
4. Filter results to IPs with more than five failed attempts.
5. Sort the results from the highest number of failed attempts to the lowest.

## Detection Results

The SPL detection identified the following source IP addresses exceeding the configured threshold:

| Source IP | Failed Attempts |
|-----------|----------------:|
| 10.10.10.25 | 18 |
| 10.10.10.31 | 11 |
| 10.10.10.44 | 7 |

These addresses are private/synthetic addresses used for the controlled lab environment.

## Alert

A Splunk alert named:

**SSH Brute Force Detection**

was created using the failed SSH login detection logic.

The alert provides a notification signal when the configured failed-login condition is triggered.

The alert evidence is shown in `03.png`.

## Dashboard

A Splunk dashboard named:

**SSH Authentication Threat Monitor**

was created to visualize the detection results.

The dashboard contains:

- **Top Attacking IPs** table
- **Failed Attempts by IP** bar chart

The dashboard provides a quick overview of which source IPs generated the highest number of failed SSH authentication attempts.

## Evidence

The `screenshots` folder contains the project evidence:

- `01.png` — Splunk setup and running status
- `02.png` — SPL detection query and detection results
- `03.png` — Splunk alert evidence
- `04.png` — Splunk dashboard
- `05.png` — Raw SSH authentication events ingested into Splunk

## Security Significance

Repeated failed SSH authentication attempts can be associated with password guessing, brute-force activity, or other unauthorized access attempts.

A SIEM such as Splunk can help security analysts identify these patterns by collecting authentication logs, applying detection rules, generating alerts, and presenting the results through dashboards.

The detection in this project is intended as an initial security signal and does not by itself prove that an attack or system compromise has occurred.

## Project Workflow

```text
SSH Authentication Logs
          │
          ▼
     Splunk Ingestion
          │
          ▼
      SPL Detection
          │
          ▼
 Extract Source IP
          │
          ▼
 Count Failed Attempts
          │
          ▼
 Threshold > 5 Attempts
          │
     ┌────┴────┐
     ▼         ▼
   Alert    Dashboard
```

## Limitations

This project is a controlled proof-of-concept using synthetic authentication data.

The threshold of more than five failed attempts is a demonstration rule and should not be treated as a universal indicator of malicious activity.

A production detection environment would require additional tuning, including:

- Time-based detection windows
- Allowlisting of legitimate administrative systems
- Account and authentication context
- Source reputation
- False-positive analysis
- Correlation with successful logins and other security events

## Conclusion

This project demonstrates a basic SIEM workflow using Splunk Enterprise:

**Log Ingestion → Detection → Alerting → Visualization**

The lab successfully identified repeated failed SSH authentication attempts, extracted the source IP addresses, counted failed attempts, generated an alert, and displayed the results through a Splunk dashboard.

The project provides a practical example of how SIEM tools can be used for basic security monitoring and detection of suspicious authentication activity.
