# Self-Healing Cloud Security Automation (AWS | Terraform | IAM)

A cloud security engineering project demonstrating **Policy-as-Code identity governance, automated privilege remediation, and security guardrails** using **Terraform, AWS IAM, AWS Config, and AWS Lambda**.

The project simulates how enterprise cloud environments enforce **least privilege access and automatically remediate privilege escalation attempts**.

---

# Project Overview

This project implements a **self-healing cloud security architecture** that detects and automatically remediates unauthorized privilege changes in AWS.

Instead of relying on manual intervention, the system continuously monitors IAM policy changes and automatically restores the environment to a secure baseline.

Key security objectives:

- Enforce **Principle of Least Privilege**
- Implement **Policy-as-Code governance**
- Detect unauthorized admin privileges
- Automatically remediate security violations
- Prevent disabling of critical security services

---

# Key Security Capabilities

## Policy-as-Code IAM Framework

- Built reusable **Terraform IAM modules** for role provisioning
- Supports onboarding of **50+ IAM roles with a single deployment**
- Standardized naming and tagging for governance
- Permission boundaries prevent privilege escalation

---

## Automated Privilege Remediation

A **serverless remediation pipeline** ensures privileged access cannot persist.

Security workflow:

1. AWS Config detects a non-compliant IAM policy attachment  
2. EventBridge generates an event  
3. Lambda function executes remediation  
4. AdministratorAccess policy is automatically removed  

This creates a **self-healing identity security model**.

---

## Governance Guardrails

To prevent attackers or misconfigurations from disabling security controls:

- Implemented **Service Control Policies (SCPs)**
- Prevents disabling:
  - AWS Config
  - GuardDuty
  - Security monitoring services

This protects the **security baseline across AWS accounts**.
