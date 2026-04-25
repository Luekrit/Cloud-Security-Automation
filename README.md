# Cloud Security Automation & Remediation

**AWS | Terraform | IAM | EventBridge | Lambda | CloudTrail | SNS | Python**

A cloud security engineering project demonstrating **event-driven detection, alerting, and governance-aware remediation decision logic** using Terraform and AWS native services.

This project simulates how modern cloud environments detect risky IAM privilege escalation activity, notify security teams, evaluate approved exceptions, and support safe remediation through a **dry-run-first** approach.

---

# Project Overview

This project implements a **self-healing cloud security architecture** that detects high-risk IAM policy attachment activity in near real time.

Instead of relying on manual incident response, the system:

- Monitors AWS API activity using CloudTrail
- Detects security-relevant events using EventBridge
- Triggers response logic using Lambda
- Sends security alerts using SNS email
- Evaluates governance-aware exceptions using IAM tags
- Supports automated remediation in a controlled manner

The current implementation focuses on **AdministratorAccess attachment detection** for IAM users and validates the control through **dry-run testing** before enabling real enforcement.

---

# Architecture Diagram

```mermaid
graph TD
    classDef trigger fill:#ed2c13,stroke:#333,stroke-width:2px;
    classDef logic fill:#326ee6,stroke:#333,stroke-width:2px;
    classDef action fill:#d4772a,stroke:#333,stroke-width:2px;
    classDef final fill:#7330e6,stroke:#333,stroke-width:2px,stroke-dasharray: 5 5;

    subgraph Detection_Layer [1. Detection]
        A[<b>IAM / Security Events</b><br/>AttachUserPolicy]:::trigger --> B[<b>AWS CloudTrail</b><br/>Records API Activity]
    end

    subgraph Routing_Layer [2. Filtering]
        B --> C[<b>Amazon EventBridge</b><br/>Matches Security Event Patterns]:::logic
    end

    subgraph Logic_Layer [3. Logic Engine]
        C --> D[<b>AWS Lambda</b><br/><i>remediate.py</i>]:::logic
        D --> D1[Parse Event Metadata]
        D --> D2[Evaluate Risk]
        D --> D3[Check Governance Exceptions]
        D --> D4[Decide Remediate or Skip]
    end

    subgraph Response_Layer [4. Response]
        D4 --> E[<b>SNS Email Alert</b><br/>Structured Security Notification]:::action
        D4 --> F[<b>CloudWatch Logs</b><br/>Audit Trail and Debugging]:::action
        D4 --> G[<b>IAM Remediation</b><br/>Detach Policy in Enforcement Mode]:::action
    end

    subgraph Outcome [5. Desired State]
        G --> H[<b>Least Privilege Preserved</b>]:::final
        E --> H
        F --> H
    end
```
---

---

# Key Security Capabilities

## Event-Driven Threat Detection

The system currently monitors IAM-related API activity, with the main validated use case focused on:

- AttachRolePolicy  

EventBridge filters matching CloudTrail events in real time and invokes the Lambda response workflow.

---

## Governance-Aware Response Logic

The Lambda response engine:

- Parses incoming CloudTrail event metadata
- Identifies targeted IAM users and risky policy attachments
- Evaluates whether remediation is in scope
- Checks approved exception tags such as:
  - `SecurityApproved=true`
- Decides whether to remediate or skip

This creates a more realistic security control by combining technical detection with **governance-aware exception handling**.

---

## SNS Alerting

When a risky IAM event is detected, the system sends a structured SNS email alert containing:

- Event name
- Actor ARN
- Target user
- Policy ARN
- Dry-run status
- Remediation decision
- Reason for approval or skip

This improves operational visibility before full enforcement is enabled.

---

## Dry-Run Safety Mode

The control currently operates in **dry-run mode**.

This means:

- Risky activity is still detected
- Alerts are still sent
- Decisions are still logged
- but no actual IAM detachment is performed yet

This allows safe validation before enabling live remediation.

---

## Security Logging & Visibility

All remediation actions are logged to:

- **Amazon CloudWatch Logs**

This provides:

- Audit trail for security actions  
- Debugging capability  
- Operational visibility
- Evidence for validation and testing

---

# Attack Simulation

To validate the system, the following scenario is tested:

1. A user or role is granted the **AdministratorAccess** policy  
2. CloudTrail records the IAM policy change  
3. EventBridge detects the matching event  
4. Lambda evaluates the event
5. SNS sends a structured security alert  
6. Lambda either:  
    - approves remediation in dry-run mode, or
    - skips remediation if an approved exception tag is present

---
# Terraform Infrastructure

Infrastructure is deployed using **Terraform with secure best practices**.

---
## Infrastructure Design
```mermaid
graph TD
    %% Define Styles
    classDef tool fill:#742fba,stroke:#fff,stroke-width:2px,color:#fff;
    classDef iam fill:#f6a800,stroke:#333,stroke-width:2px;
    classDef aws fill:#232f3e,stroke:#fff,stroke-width:2px,color:#fff;
    classDef storage fill:#3b48cc,stroke:#fff,stroke-width:2px,color:#fff;

    A[<b>Terraform CLI</b><br/>Local Machine / CI/CD]:::tool -->|sts:AssumeRole| B[<b>TerraformExecutionRole</b><br/>IAM Role]:::iam
    
    B -->|Provision Resources| C[<b>AWS Infrastructure</b><br/>VPC, Lambda, EventBridge]:::aws
    
    subgraph Remote_Backend [Remote State Management]
        D[<b>S3 Bucket</b><br/>Remote State Storage]:::storage
        E[<b>DynamoDB Table</b><br/>State Locking]:::storage
        
        D ---|Stores| F(<b>terraform.tfstate</b>):::storage
        E ---|Prevents| G(<b>Concurrent Runs</b>):::storage
    end

    C -.->|Update State| D
    A <-->|Check/Update Lock| E
```

---

## Key Infrastructure Features

- Modular Terraform architecture  
- Secure access using **AssumeRole (no long-term credentials)**  
- Remote state storage in **S3**  
- State locking using **DynamoDB**  
- Reusable modules for IAM, Lambda, EventBridge, SNS, CloudTrail, and S3
- Separate global path in us-east-1 for IAM event handling

---

# Validation Results

This phase validated the end-to-end detection, alerting, and governance-aware exception handling of the project in **dry-run mode**.

## Test Scenario A — Unapproved AdministratorAccess attachment

**Objective:** Confirm that the control detects a high-risk IAM policy attachment, sends an alert, and approves remediation when no exception applies.

**Test action**
- Attached `AdministratorAccess` to `iam-test-user`

**Expected behavior**
- CloudTrail records the IAM API event
- EventBridge matches the event
- Lambda is invoked in `us-east-1`
- SNS email alert is sent
- Remediation is approved
- Because `DRY_RUN=true`, no actual detach occurs

**Observed result**
- Lambda logs showed:
  - `Security detection triggered`
  - `Parsed event`
  - `SNS alert processed`
  - `Dry run enabled - remediation skipped`
- SNS email alert showed:
  - `approved_for_remediation: true`
  - `decision_reason: "Approved for remediation"`

**Evidence**

**Figure 1. Test A — CloudWatch log showing detection, SNS alerting, and dry-run remediation approval**  
![Test A CloudWatch Logs](https://github.com/Luekrit/Cloud-Security-Automation/blob/5a6adbb0da548bb17a2074b219dda3021f854f92/diagrams/Screenshot%20test%20A%20log%20Event.png)

**Figure 2. Test A — SNS email alert showing remediation approved**  
![Test A SNS Email Alert](https://github.com/Luekrit/Cloud-Security-Automation/blob/main/diagrams/Screenshot%20SNS%20notifications%20for%20Test%20A.png)

**Outcome**
- Detection worked
- Alerting worked
- Remediation decision logic worked
- Dry-run safety control worked

---

## Test Scenario B — Approved exception using IAM tag

**Objective:** Confirm that the control still detects and alerts on the risky IAM event, but skips remediation when the target user has an approved exception tag.

**Test action**
- Added IAM user tag:
  - `SecurityApproved = true`
- Attached `AdministratorAccess` to `iam-test-user`

**Expected behavior**
- CloudTrail records the IAM API event
- EventBridge matches the event
- Lambda is invoked in `us-east-1`
- SNS email alert is sent
- Remediation is **not** approved because the target user has an approved exception tag
- Lambda logs the skip reason clearly

**Observed result**
- Lambda logs showed:
  - `Security detection triggered`
  - `Parsed event`
  - `SNS alert processed`
  - `No remediation performed`
- SNS email alert showed:
  - `approved_for_remediation: false`
  - `decision_reason: "User has approved exception tag: SecurityApproved=true"`

**Evidence**

**Figure 3. Test B — CloudWatch log showing alerting and exception-based remediation skip**  
![[Test B CloudWatch Logs](screenshots/test-b-cloudwatch.png)](https://github.com/Luekrit/Cloud-Security-Automation/blob/main/diagrams/Screenshot%20Log%20Event%20for%20Test%20B.png)

**Figure 4. Test B — SNS email alert showing approved exception decision**  
![[Test B SNS Email Alert](screenshots/test-b-email.png)](https://github.com/Luekrit/Cloud-Security-Automation/blob/main/diagrams/Screenshot%20SNS%20notification%20for%20test%20B.png)

**Outcome**
- Detection worked
- Alerting worked
- Governance-aware exception handling worked
- Approved exceptions were skipped correctly

---

## Validation Summary

These tests confirmed that the control can:

- detect risky IAM policy attachment events
- alert security teams through SNS email
- support safe rollout using dry-run mode
- apply governance-aware exception handling using IAM user tags

This phase demonstrates a more realistic security engineering workflow:

**CloudTrail → EventBridge → Lambda → SNS alert → Dry-run remediation decision**

# Security Principles Demonstrated

This project applies core cloud security engineering practices:

- **Least Privilege Access Control**  
- **Event-Driven Security Automation**  
- **Infrastructure as Code (IaC) Security**  
- **Automated Incident Response**  
- **Cloud Identity Protection**  

---

# Technologies Used

- Terraform  
- AWS IAM  
- AWS CloudTrail  
- Amazon EventBridge  
- AWS Lambda  
- Amazon CloudWatch Logs
- Amazon SNS  
- Python  

---

# Why This Project Exists

This project was inspired by a security lesson learned during earlier development, where improper credential handling highlighted how easily cloud misconfigurations can introduce risk.

The goal of this project is to demonstrate how **automation and security engineering practices can prevent those risks from persisting in real environments**.

---

# Future Improvements

- Add detection for additional IAM abuse scenarios  
- Integrate alerting via **SNS / Slack notifications**  
- Expand remediation logic for broader security events  
- Integrate with **AWS Security Hub or SIEM tools**  
- Add anomaly detection for unusual API behavior  

---
