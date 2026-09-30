# Splunk SSH Failed Login Detection

## Project Overview

This project demonstrates a small Security Information and Event
Management (SIEM) lab using Splunk Enterprise on Kali Linux.

The goal is to ingest mock Linux SSH authentication logs, identify
source IP addresses with more than five failed SSH login attempts,
create an alert, and visualize attacking IP activity in a Splunk
dashboard.

## Objectives

-   Install and run Splunk Enterprise on Kali Linux.
-   Ingest mock SSH authentication log data.
-   Use Splunk Search Processing Language (SPL) to detect repeated
    failed SSH logins.
-   Identify source IP addresses with more than five failed attempts.
-   Create a Splunk alert for suspicious SSH authentication activity.
-   Create a dashboard named **SSH Authentication Threat Monitor**.
-   Document the proof of concept and findings.

## Tools

-   Kali Linux
-   Splunk Enterprise 10.4.4
-   Splunk Search Processing Language (SPL)
-   Mock SSH `auth.log` data

## Detection Logic

The primary detection searches for failed SSH password authentication
events, extracts the source IP address, counts failed attempts by IP,
and returns IPs with more than five attempts.

``` spl
index=main "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| where failed_attempts > 5
| sort - failed_attempts
```

## Observed Results

The lab data used for the dashboard produced the following top attacking
IP results:

  Source IP       Failed Attempts
  ------------- -----------------
  10.10.10.25                  18
  10.10.10.31                  11
  10.10.10.44                   7

These addresses are synthetic/private lab addresses and are not
presented as real-world attackers.

## Alert

A Splunk alert was created for the failed SSH login detection. The alert
is intended to identify source IPs exceeding the configured failed-login
threshold.

## Dashboard

The dashboard is named:

**SSH Authentication Threat Monitor**

The dashboard includes a **Failed Attempts by IP** visualization and a
**Top Attacking IPs** table.

## Evidence

The screenshots folder contains the available project evidence:

- `01.png` — Splunk setup and running status
- `02.png` — SPL detection query and failed-login detection results
- `03.png` — Splunk alert evidence
- `04.png` — Splunk dashboard showing failed attempts by IP
- `05.png` — Raw SSH authentication events ingested into Splunk

## Security Significance

Repeated failed SSH authentication attempts can indicate password
guessing, brute-force activity, or other unauthorized access attempts. A
SIEM can help analysts identify these patterns by aggregating
authentication events and applying detection rules.

## Limitations

This is a controlled proof-of-concept using synthetic log data. The
threshold of more than five attempts is a lab rule and should not be
treated as a universal indicator of malicious activity. Production
detection should consider time windows, legitimate administrative
activity, account context, source reputation, and false positives.

## Conclusion

The project demonstrates the basic SIEM workflow of log ingestion,
SPL-based detection, alerting, and dashboard visualization for SSH
authentication activity.
