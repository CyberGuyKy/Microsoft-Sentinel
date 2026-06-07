# Microsoft Sentinel Lab: Brute Force Detection Exercise

## Overview

This exercise demonstrates a full SOC analyst workflow using Microsoft Sentinel and Microsoft Defender XDR. Starting from raw log ingestion through detection, investigation, and incident resolution, this lab covers the core skills referenced in SC-200 and most SOC job descriptions.

📸 **Full screenshot walkthrough:** [Microsoft Defender and Sentinel Exercise Wiki](https://github.com/CyberGuyKy/Microsoft-Sentinel/wiki/Micorosft-Defender-and-Sentinel-Exercise)

---

## Environment

| Component | Value |
|---|---|
| Tenant | kyledhughes86gmail.onmicrosoft.com |
| Log Analytics Workspace | kynetlogs (East US) |
| Resource Group | KyNetPrimary |
| Entra ID License | P2 Trial |
| Sentinel Status | Enabled and connected to Defender XDR |

---

## Objectives

- Connect Entra ID sign-in logs to Microsoft Sentinel
- Write a KQL analytics rule to detect a brute force pattern
- Trigger the rule with a simulated attack
- Investigate and resolve the resulting incident using SOC best practices
- Document actions using professional incident management procedures

---

## Step 1: Verify Data Connector

**Microsoft Sentinel → Data connectors → Microsoft Entra ID**

Confirmed the Entra ID data connector was active and streaming `SigninLogs` to the `kynetlogs` Log Analytics workspace. This is the data source all detection rules in this exercise rely on.

> **Note:** Microsoft has migrated the Analytics rules interface from the Sentinel portal directly into the **Microsoft Defender XDR portal**. All rule creation and incident management was performed there.

---

## Step 2: Create the Analytics Rule

**Defender Portal → Microsoft Sentinel → Analytics → Create → Scheduled query rule**

### General Settings

| Field | Value |
|---|---|
| Name | Multiple Failed Logins Followed by Success |
| Description | Detects brute force pattern - 5+ failed logins followed by a successful login from the same user within 20 minutes |
| Severity | Medium |
| MITRE ATT&CK Tactic | Credential Access |
| MITRE ATT&CK Technique | T1110 - Brute Force |
| Status | Enabled |

### KQL Detection Query

```kql
let failureThreshold = 5;
let timeWindow = 20m;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize FailureCount = count(), LastFailure = max(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, timeWindow)
| where FailureCount >= failureThreshold
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == "0"
) on UserPrincipalName
| project UserPrincipalName, IPAddress, FailureCount, LastFailure
```

**Query logic:** Looks back 1 hour for any user who accumulated 5 or more failed sign-ins (`ResultType != "0"`) within a 20-minute window, then confirms a successful login (`ResultType == "0"`) occurred from the same account — the classic brute force success pattern.

### Query Scheduling

| Setting | Value |
|---|---|
| Run query every | 5 Minutes |
| Lookup data from last | 1 Hour |

---

## Step 3: Simulate the Attack

To trigger the rule, failed logins were generated against a test user account from a private browser session, followed by a successful authentication. This replicates the pattern a threat actor would produce after a brute force attempt.

**Result:** The rule fired and detected activity against `dominic.toretto@kyledhughes86gmail.onmicrosoft.com` — 15 failed logins from IP `65.30.200.27` followed by a successful login. This confirmed the rule was working correctly against real `SigninLogs` data.

---

## Step 4: Incident Investigation

**Defender Portal → Incidents → ID 1: Multiple Failed Logins Followed by Success**

### Incident Details

| Field | Value |
|---|---|
| Incident ID | 1 |
| Title | Multiple Failed Logins Followed by Success |
| Severity | Medium |
| Status | Active |
| MITRE ATT&CK | Credential Access / T1110 |
| Detection Source | Scheduled Detection / Microsoft Sentinel |
| First Activity | Jun 7, 2026 7:26 AM |
| Last Activity | Jun 7, 2026 8:26 AM |
| Affected User | dominic.toretto@kyledhughes86gmail.onmicrosoft.com |
| Source IP | 65.30.200.27 |
| Failure Count | 15 |

### SOC Investigation Checklist

A real SOC analyst would work through the following questions before taking any action:

- Is the affected user known, and is this activity expected? (travel, password reset, new device)
- Does the source IP geolocate to a known or trusted location?
- Did the successful login result in any suspicious post-authentication activity?
- Are other accounts being targeted from the same IP? (password spray indicator)
- Has MFA been challenged and passed, or bypassed?

---

## Step 5: Incident Task (Delegation)

A task was created inside the incident to document and delegate the required containment action:

**Task Title:** Reset credentials and revoke sessions - dominic.toretto

**Task Description:**
```
Incident ID: 1
Detection: Multiple Failed Logins Followed by Success
User: dominic.toretto@kyledhughes86gmail.onmicrosoft.com
Source IP: 65.30.200.27
Failure Count: 15
First Activity: Jun 7, 2026 7:26 AM
Last Activity: Jun 7, 2026 8:26 AM

Required Actions:
1. Reset password for dominic.toretto in Entra ID
2. Revoke all active sessions for dominic.toretto
3. Confirm with user whether login attempts were legitimate
4. Document outcome in incident comments upon completion

Priority: Medium
Assigned by: KyNet Admin
```

> In a production environment this task would be assigned to a Tier 2 analyst or Identity team member. Enterprise SOCs typically also open a linked ticket in ServiceNow or Jira at this stage.

---

## Step 6: Incident Resolution

### Closing Comment (added before closing)

> *"Investigation complete. 15 failed logins from IP 65.30.200.27 against dominic.toretto confirmed as lab simulation. No unauthorized access occurred. No production systems affected. Closing as Benign Positive - Test/Lab Activity."*

### Resolution Settings

| Field | Value |
|---|---|
| Status | Closed |
| Classification | Benign Positive |
| Determination | Security testing |

---

## Skills Demonstrated

| Skill | Details |
|---|---|
| KQL query writing | Custom brute force detection logic against SigninLogs |
| Sentinel analytics rules | Scheduled query rule with MITRE ATT&CK mapping |
| Incident investigation | Reviewed alert details, entities, query results |
| SOC documentation | Professional task creation with structured incident data |
| Incident management | Status tracking, classification, and closure with comment trail |
| SOAR awareness | Task delegation workflow; playbook integration planned |

---

## Next Steps

- [ ] Build a Logic App playbook to auto-notify via email when this incident type fires
- [ ] Add an automation rule to auto-assign Medium+ incidents
- [ ] Create a second detection rule (e.g. impossible travel or MFA fatigue)
- [ ] Document findings in GitHub wiki with full screenshot evidence

---

*Lab environment: Microsoft Entra ID P2 Trial | Microsoft Sentinel on Log Analytics workspace kynetlogs | Microsoft Defender XDR unified portal*
