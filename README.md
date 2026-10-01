# Splunk SSH Failed Login Detection

A small SIEM lab that uses **Splunk Enterprise** on **Kali Linux** to detect repeated failed SSH logins, raise an alert, and show the results on a dashboard.

**Workflow:** Log Ingestion → Detection → Alerting → Visualization

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Tools and Technologies](#tools-and-technologies)
3. [Step-by-Step Guide](#step-by-step-guide)
4. [Detection Results](#detection-results)
5. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
6. [Evidence](#evidence)
7. [Security Significance](#security-significance)
8. [Limitations](#limitations)
9. [Skills Demonstrated](#skills-demonstrated)
10. [Conclusion](#conclusion)

---

## Project Overview

Repeated failed SSH logins can be a sign of password guessing or brute-force activity. This project shows how a SIEM can catch that pattern.

Splunk ingests Linux SSH authentication events, finds source IPs with **more than 5 failed logins**, creates an alert, and shows the top offenders on a dashboard.

**Objectives**

- Set up and run Splunk Enterprise on Kali Linux
- Ingest SSH authentication log events
- Write an SPL query to detect repeated failed logins
- Extract source IP addresses from the events
- Create an alert for suspicious SSH activity
- Build a dashboard of failed login activity
- Document the process and results

---

## Tools and Technologies

| Tool | Purpose |
|------|---------|
| Kali Linux (VirtualBox) | Lab machine |
| Splunk Enterprise 10.4.4 | SIEM platform |
| Splunk SPL | Search and detection language |
| Synthetic `auth.log` | Mock SSH authentication data |

> **Note:** All IP addresses are synthetic private lab addresses. They are not real attackers.

---

## Step-by-Step Guide

Run every command in the Kali terminal unless the step says Splunk Web.

### Step 1: Update Kali

**Why:** Starts the lab from a clean, up-to-date system.

```bash
sudo apt update
```

### Step 2: Download Splunk Enterprise

**Why:** Gets the installer file (`.deb`) for Kali.

1. Open the download page in the Kali browser: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Sign in (a free Splunk account is needed).
3. Choose **Linux** and download the **.deb** package.

Check that the file is in Downloads:

```bash
cd ~/Downloads
ls splunk-*.deb
```

### Step 3: Install Splunk

**Why:** Installs Splunk into `/opt/splunk`.

```bash
sudo dpkg -i splunk-*-linux-amd64.deb
```

### Step 4: Start Splunk and create the admin account

**Why:** Starts the service. The first start asks you to accept the license and create an admin login.

```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

Type an admin username and password when asked. Remember them.

### Step 5: Check that Splunk is running

**Why:** Confirms the service is up before using it.

```bash
sudo /opt/splunk/bin/splunk status
```

Expected: `splunkd is running`.

Open Splunk Web in the browser and log in:

```
http://127.0.0.1:8000
```

> Screenshot: `01.png` (Splunk setup and running status)

### Step 6: Create the mock SSH log

**Why:** Makes fake failed-login events so the detection has data to find.

```bash
mkdir -p ~/splunk-lab && cd ~/splunk-lab
rm -f auth.log

gen_failed() {
  for i in $(seq 1 "$2"); do
    printf 'Oct  1 10:%02d:%02d kali sshd[%d]: Failed password for root from %s port %d ssh2\n' \
      "$3" "$i" $((2000 + RANDOM % 900)) "$1" $((40000 + RANDOM % 20000))
  done
}

gen_failed 10.10.10.25 18 10 >> auth.log
gen_failed 10.10.10.31 11 20 >> auth.log
gen_failed 10.10.10.44 7 30 >> auth.log
gen_failed 10.10.10.60 3 40 >> auth.log
echo 'Oct  1 10:50:05 kali sshd[3100]: Accepted password for admin from 10.10.10.5 port 51234 ssh2' >> auth.log
```

### Step 7: Check the mock log

**Why:** Confirms the numbers before ingesting. `10.10.10.60` has only 3 failures, so it should not be flagged.

```bash
wc -l auth.log
grep "Failed password" auth.log | grep -o "from [0-9.]*" | sort | uniq -c | sort -rn
```

Expected:

```
     18 from 10.10.10.25
     11 from 10.10.10.31
      7 from 10.10.10.44
      3 from 10.10.10.60
```

### Step 8: Ingest the log into Splunk

**Why:** Loads the events into the `main` index so Splunk can search them.

```bash
sudo /opt/splunk/bin/splunk add oneshot ~/splunk-lab/auth.log -index main -sourcetype linux_secure
```

Enter your Splunk admin username and password when asked.

### Step 9: View the raw events

**Why:** Proves the data arrived in Splunk.

In Splunk Web, open **Search & Reporting**, set the time range to **All time**, and run:

```spl
index=main sourcetype=linux_secure
```

Expected: 40 events.

> Screenshot: `05.png` (raw SSH authentication events)

### Step 10: Run the detection query

**Why:** Finds IPs with more than 5 failed logins.

```spl
index=main "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count as failed_attempts by src_ip
| where failed_attempts > 5
| sort - failed_attempts
```

**What each line does**

| Line | Purpose |
|------|---------|
| `index=main "Failed password"` | Finds failed SSH login events |
| `rex ...` | Pulls out the source IP address |
| `stats count ... by src_ip` | Counts failures per IP |
| `where failed_attempts > 5` | Keeps only IPs over the threshold |
| `sort - failed_attempts` | Shows the highest count first |

Expected: 3 rows (see [Detection Results](#detection-results)).

> Screenshot: `02.png` (SPL query and results)

### Step 11: Create the alert

**Why:** Gets Splunk to notify you when the pattern appears.

With the detection query results on screen, click **Save As → Alert** and fill in:

| Setting | Value |
|---------|-------|
| Title | `SSH Brute Force Detection` |
| Alert type | Scheduled |
| Run every | Hour |
| Time range | All time (the lab data is fixed, so this keeps it visible) |
| Trigger alert when | Number of Results is greater than `0` |
| Trigger | Once |
| Trigger actions | Add to Triggered Alerts |

Click **Save**.

> Screenshot: `03.png` (alert evidence)

### Step 12: Build the dashboard

**Why:** Shows the top attacking IPs at a glance.

**Panel 1: Top Attacking IPs (table)**

1. Run the detection query from Step 10 again.
2. Click **Save As → Dashboard Panel**.
3. Choose **New** and name the dashboard `SSH Authentication Threat Monitor`.
4. Pick **Classic Dashboards**.
5. Set the panel title to `Top Attacking IPs`, then click **Save to Dashboard**.

**Panel 2: Failed Attempts by IP (bar chart)**

1. Run the detection query again.
2. Open the **Visualization** tab and choose **Bar Chart**.
3. Click **Save As → Dashboard Panel**.
4. Choose **Existing** and select `SSH Authentication Threat Monitor`.
5. Set the panel title to `Failed Attempts by IP`, then click **Save to Dashboard**.

Open the dashboard from **Dashboards** to check both panels.

> Screenshot: `04.png` (dashboard)

### Step 13: Save the evidence

**Why:** Keeps proof of each stage in the repo.

```bash
mkdir -p ~/splunk-lab/screenshots
cp ~/splunk-lab/auth.log ~/splunk-lab/sample-auth.log
ls ~/splunk-lab
```

Place `01.png` to `05.png` in the `screenshots` folder.

---

## Detection Results

| Source IP | Failed Attempts |
|-----------|-----------------|
| 10.10.10.25 | 18 |
| 10.10.10.31 | 11 |
| 10.10.10.44 | 7 |

`10.10.10.60` (3 failures) stays below the threshold and is not flagged.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 Brute Force |
| Sub-technique | T1110.001 Password Guessing |

The detection looks for many failed password attempts from one source, which is the behavior this technique describes.

---

## Evidence

| File | What it shows |
|------|---------------|
| `screenshots/01.png` | Splunk setup and running status |
| `screenshots/02.png` | SPL detection query and results |
| `screenshots/03.png` | Splunk alert |
| `screenshots/04.png` | Dashboard |
| `screenshots/05.png` | Raw SSH events in Splunk |

---

## Security Significance

Repeated failed SSH logins can point to password guessing, brute-force activity, or other unauthorized access attempts.

A SIEM like Splunk helps analysts spot this by collecting logs, applying detection rules, raising alerts, and showing results on dashboards.

This detection is an early warning signal. It does not prove an attack or compromise on its own.

---

## Limitations

This is a proof of concept with synthetic data. The threshold of 5 is a demo value, not a universal rule.

A real environment would also need:

- Time-based detection windows
- Allowlisting of legitimate admin systems
- Account and authentication context
- Source IP reputation
- False-positive tuning
- Correlation with successful logins and other events

---

## Skills Demonstrated

- SIEM setup and log ingestion (Splunk)
- SPL queries: `rex`, `stats`, `where`, `sort`
- Alert creation and dashboard building
- Mapping detections to MITRE ATT&CK
- Security documentation

---

## Conclusion

This lab walks through a basic SIEM workflow in Splunk Enterprise: **ingest logs, detect, alert, and visualize**. It found repeated failed SSH logins, counted them per source IP, raised an alert, and displayed the results on a dashboard.
