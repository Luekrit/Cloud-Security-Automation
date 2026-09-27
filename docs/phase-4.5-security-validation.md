# Phase 4.5 — Security Validation and Hardening

Phase 4.5 introduced static Infrastructure-as-Code validation with Checkov and
runtime AWS posture assessment with Prowler.

The objective was not to force every scanner finding to PASS. Findings were
reviewed against the architecture and classified before remediation so that
security tooling did not drive unnecessary, unsafe, or out-of-scope changes.

## Validation tools

| Tool | Version | Purpose |
|---|---:|---|
| Checkov | 3.3.16 | Terraform / IaC static security analysis |
| Prowler | 5.42.0 | Runtime AWS configuration and posture assessment |

Prowler was executed through a dedicated read-only `ProwlerAuditRole` rather
than an administrator identity.

---

## Checkov results

### Initial Phase 4 baseline

- Passed: 65
- Failed: 26
- Skipped: 0

### Final Phase 4.5 result

- Passed: 96
- Failed: 18
- Skipped: 0

The final scan remained stable after the Lambda execution-role trust-policy
hardening.

### Controls remediated during Phase 4.5

- Lambda asynchronous failure handling through a dedicated SQS dead-letter queue.
- CloudTrail integration with CloudWatch Logs.
- CloudWatch log encryption using the CloudTrail customer-managed KMS key.
- CloudWatch log retention configured for 365 days.
- CloudTrail runtime log delivery validated.
- Lambda execution-role trust restricted with `aws:SourceAccount`.

---

## Remaining Checkov findings

Remaining scanner findings are recorded rather than silently suppressed.

| Check | Resource / area | Status | Rationale |
|---|---|---|---|
| CKV_AWS_109 | CloudTrail KMS policy | Contextual / documented | Service KMS permissions require broad resource syntax while additional policy conditions constrain usage. |
| CKV_AWS_111 | CloudTrail KMS policy | Contextual / documented | Same KMS service-policy context as CKV_AWS_109. |
| CKV_AWS_356 | CloudTrail KMS policy | Contextual / documented | Wildcard resource remains within a service-specific KMS policy constrained by conditions. |
| CKV_AWS_252 | CloudTrail | Deferred | CloudTrail currently delivers to S3 and CloudWatch Logs. Project alerting is handled separately through the remediation SNS path. |
| CKV_AWS_272 | Lambda code signing | Deferred | Code signing is planned with the CI/CD and software-supply-chain phase. |
| CKV_AWS_173 | Lambda environment KMS | Deferred hardening | No application secrets are stored in Lambda environment variables; customer-managed environment encryption remains a future hardening option. |
| CKV_AWS_115 | Lambda reserved concurrency | Technical limitation | A deployment attempt was rejected because the account concurrency quota requires the available concurrency to remain unreserved. |
| CKV_AWS_117 | Lambda VPC placement | Architecture decision | The remediation function uses AWS service APIs and does not currently require private VPC resources. VPC placement would add networking dependencies and cost without a current workload requirement. |
| CKV_AWS_50 | Lambda X-Ray | Deferred | Distributed tracing is an observability enhancement rather than a prerequisite for the current remediation workflow. |
| CKV2_AWS_62 | Terraform state bucket | Deferred | S3 event notifications are not required by the current state-backend design. |
| CKV2_AWS_62 | CloudTrail log bucket | Deferred | CloudTrail delivery and monitoring are already handled through CloudTrail and CloudWatch Logs. |
| CKV2_AWS_61 | Terraform state bucket | Deferred | Lifecycle policy will be added when retention requirements are formally defined. |
| CKV2_AWS_61 | CloudTrail log bucket | Deferred | Lifecycle policy will be added when retention requirements are formally defined. |
| CKV_AWS_18 | Terraform state bucket | Deferred | Server access logging would require a separate logging destination and is outside the current bootstrap scope. |
| CKV_AWS_18 | CloudTrail log bucket | Deferred | Server access logging would require a separate logging destination and additional log-storage design. |
| CKV_AWS_144 | Terraform state bucket | Accepted scope | Cross-region replication is outside the current single-account portfolio scope. |
| CKV_AWS_144 | CloudTrail log bucket | Accepted scope | Cross-region replication is outside the current single-account portfolio scope. |
| CKV_AWS_145 | Terraform state bucket | Deferred bootstrap hardening | Migrating the remote-state backend to a customer-managed KMS key requires careful bootstrap/state migration and is intentionally separated from the application stack. |

No Checkov finding was silently skipped in the final scan.

---

## Prowler assessment

### Targeted baseline

Services assessed:

`IAM`, `CloudTrail`, `S3`, `Lambda`, `KMS`, `CloudWatch`,
`DynamoDB`, `SNS`, and `SQS`.

Results:

- Passed findings: 161
- Failed findings: 84
- Muted findings: 0

### Final targeted assessment

- Passed findings: 170
- Failed findings: 81
- Muted findings: 0

The failed-finding count decreased by three after deliberate remediation.

### Remediated runtime findings

| Finding | Action | Validation |
|---|---|---|
| Root account MFA disabled | Enabled MFA for the AWS root account | AWS credential report refreshed to `mfa_active=true`; Prowler PASS |
| S3 account-level Block Public Access disabled | Enabled all four account-level S3 Block Public Access controls | AWS API verification; Prowler PASS |
| Lambda execution role lacks confused-deputy protection | Added `aws:SourceAccount` to the Lambda execution-role trust policy | Terraform no-drift check, successful Lambda invocation, SNS publish success, Prowler PASS |

### Lambda trust-policy runtime validation

The Lambda execution-role trust policy was changed from a service-principal-only
trust to a service principal constrained by the AWS account:

```text
Principal: lambda.amazonaws.com
Condition: aws:SourceAccount = current AWS account
```

Validation after deployment confirmed:

- Lambda function state remained `Active`.
- `DRY_RUN=true` remained enabled.
- A synthetic unsupported event returned HTTP status 200.
- Governance returned `NO_ACTION`.
- No remediation was performed.
- SNS notification publishing succeeded.
- CloudWatch Logs recorded normal function start, execution, and completion.
- Prowler changed the Lambda confused-deputy finding from FAIL to PASS.

---

## Findings intentionally not remediated

### CloudTrail → CloudWatch execution role

Prowler continues to flag the CloudTrail-to-CloudWatch IAM role for
cross-service confused-deputy protection.

This finding is currently documented rather than modified. CloudTrail log
delivery is functioning and has been runtime validated. Additional trust-policy
conditions require controlled compatibility testing before changing this
working logging path.

### Security Hub

Security Hub findings from the broader account scan are deferred to Phase 5,
where Security Hub integration is implemented deliberately rather than being
enabled only to satisfy a posture scanner.

### Account-wide services

The broader Prowler scan also identified controls involving services such as
GuardDuty, AWS Config, EC2, Organizations, Inspector, and other account-level
services.

Those results are retained as account-posture observations but are not treated
as defects in the Cloud Security Automation and Remediation application unless
they directly affect the project architecture.

---

## Validation principle

Phase 4.5 follows a:

`detect → investigate → classify → remediate → functionally test → rescan`

workflow.

A scanner finding is treated as evidence requiring investigation, not as an
automatic instruction to modify infrastructure.