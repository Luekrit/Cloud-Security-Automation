# Phase 6: Controlled Live Remediation

## Outcome

On 4 November 2026, a controlled test validated the real
CloudTrail → EventBridge → Lambda remediation path in us-east-1.

AdministratorAccess was attached to the disposable IAM user
iam-test-user. The Lambda execution role detached that policy
approximately four seconds later, based on CloudTrail event timestamps.

Lambda logs, CloudTrail events, and a completed DynamoDB action-ledger
record corroborated the result. Dry-run mode was restored afterward,
the live target was cleared, and the user had no attached managed
policies. A final Terraform plan reported no changes with the explicit
restored configuration.

This was one controlled lab test, not a production-readiness assessment
or a performance guarantee.

## Purpose and Scope

An unexpected AdministratorAccess attachment can introduce excessive
privileges. This phase tested whether the automation could remove that
specific attachment while preserving exception governance and limiting
the scope of live execution.

The live test was restricted to:

- User: iam-test-user.
- Policy: arn:aws:iam::aws:policy/AdministratorAccess.
- Event: AttachUserPolicy.
- Function: cloud-security-automation-global-dev-remediation.
- Region: us-east-1.

Before the test, the user had no attached managed policies, inline
policies, group memberships, access keys, or console login profile.

## Controls Added

| Control | Behaviour |
|---|---|
| Safe default | DRY_RUN defaults to true; only an explicit false enables mutations. |
| Exact live target | LIVE_REMEDIATION_USER must be nonempty and exactly match the target username. |
| Event freshness | Live actions reject missing or invalid timestamps, events at least 15 minutes old, and timestamps more than 60 seconds in the future. |
| Exception governance | Approval decisions use the separate exceptions table, which remains read-only to Lambda. |
| Action claim | A conditional DynamoDB write claims the original CloudTrail event before the IAM action. |
| Owned completion | Completion requires the matching owner token and an IN_PROGRESS record. |
| Conservative recovery | Existing incomplete claims are blocked for operator reconciliation rather than automatically reclaimed. |
| IAM permissions | Detachment remains limited to AdministratorAccess on iam-test-* users. The runtime guard further narrows the target to the configured exact username. |

The action ledger is cloud-security-automation-dev-remediation-actions,
separate from cloud-security-automation-dev-security-exceptions.

The ledger uses on-demand billing, encryption, point-in-time recovery,
and TTL cleanup. The application sets cleanup eligibility to 24 hours
after claim creation; TTL is not an approval or recovery mechanism.

## Validation Performed

### Local Validation

- 54 Python unit tests passed after ledger integration.
- Terraform configuration validation passed.
- git diff --check passed.

The unit tests cover the live-target and freshness guards, conditional
claims, owned completion, completed-event replay, uncertain IAM outcomes,
and uncertain completion.

These mocked tests do not establish deployed replay behaviour or
exactly-once execution.

### Deployed Dry Run

A controlled fixture was invoked directly against the deployed Lambda:

- Decision: REMEDIATE.
- Exception lookup: no record found.
- SNS publish: success.
- Security Hub import: success.
- Remediation result: dry_run.

This test did not attach an IAM policy or exercise the upstream
CloudTrail-to-EventBridge route.

### Controlled Live Test

Terraform temporarily deployed:

- DRY_RUN=false.
- LIVE_REMEDIATION_USER=iam-test-user.
- SECURITY_HUB_ENABLED=true.

The operator then made one real AdministratorAccess attachment.
The test script checked for removal and included conditional manual
cleanup if removal was not observed within its observation window.

The policy was absent at the first check. The manual cleanup branch
did not run. Subsequent evidence confirmed that the Lambda execution
role performed the detachment.

| UTC timestamp | Evidence |
|---|---|
| 2026-11-04T06:58:36Z | Successful AttachUserPolicy by SecurityTeamAdmin. |
| 2026-11-04T06:58:39.582Z | Lambda governance decision: REMEDIATE; no exception record. |
| 2026-11-04T06:58:39.807Z | SNS publish succeeded. |
| 2026-11-04T06:58:40.146Z | Security Hub import succeeded. |
| 2026-11-04T06:58:40Z | Successful DetachUserPolicy by cloud-security-automation-dev-lambda-role. |
| 2026-11-04T06:58:40.683Z | Lambda logged successful remediation completion. |

Correlation identifiers:

- Attachment event: 361dae30-1100-45bf-814b-1163248800a3.
- Detachment event: ec877497-a076-4c66-ae42-acbe3e923b20.
- Ledger status: COMPLETED.
- Ledger result: success / detach_user_policy.

The ledger record references the original attachment event ID.

## Deployment Issue and Resolution

The first deployment failed because TerraformExecutionRole could manage
the exceptions table but lacked CreateTable permission for the new ledger.

A separate statement was added to its existing managed policy, scoped
to the exact remediation-actions table ARN. It permits table lifecycle,
TTL, recovery, and tagging operations without adding item-level access.

This deployment-policy change was made separately through IAM and should
be retained in the deployment-role provisioning record. It is distinct
from the Lambda runtime policy managed by this Terraform environment.

## Restoration and Final State

After the test, a fresh Terraform restoration plan was applied.

Verified final state:

- Lambda: Active, with LastUpdateStatus=Successful.
- DRY_RUN=true.
- LIVE_REMEDIATION_USER is empty.
- iam-test-user has no attached managed policies.
- Terraform reports no changes using the explicit restored values.

The final verification command was:

```powershell
terraform -chdir=terraform/environments/dev plan `
  -var-file="dev terraform.tfvars" `
  -var="remediation_dry_run=true" `
  -var="live_remediation_user=" `
  -var="enable_security_hub=true"
```

This no-change result applies to those explicit inputs. Command-line
overrides do not update the saved tfvars file.

## Evidence

Public screenshots omit or mask account identifiers and unnecessary
credential identifiers and IP addresses. Original evidence is retained
separately.

| Evidence | Screenshot |
|---|---|
| Deployed dry-run result | [01: Dry run](../diagrams/Phase%206/Phase-6-01-deployed-dry-run-success.png) |
| Exact live configuration | [02: Live configuration](../diagrams/Phase%206/Phase-6-02-controlled-live-configuration.png) |
| Restored settings and empty policy list | [03: Restoration](../diagrams/Phase%206/Phase-6-03-restored-safety-settings.png) |
| Lambda decision, reporting, and successful action | [04: Lambda logs](../diagrams/Phase%206/Phase-6-04-live-remediation-success.png) |
| Attachment and Lambda-role detachment | [05: CloudTrail](../diagrams/Phase%206/Phase-6-05-cloudtrail-detachment-proof.png) |
| Completed action-ledger record | [06: Ledger](../diagrams/Phase%206/Phase-6-06-action-ledger-completed.png) |
| Post-test Terraform verification | [07: No changes](../diagrams/Phase%206/Phase-6-07-post-test-no-changes.png) |

## Limitations and Remaining Work

- Validation covers one controlled managed-policy attachment scenario.
- The four-second interval is one observation, not a response-time SLA.
- Deployed duplicate-event replay and failure recovery were not tested
  during this live run.
- DynamoDB and IAM do not share an atomic transaction. Uncertain outcomes
  require reconciliation; the ledger does not guarantee exactly-once execution.
- Incomplete claims return a blocked application result and require
  operator review; not every blocked result causes a retry or DLQ delivery.
- Runtime DLQ delivery remains a separate validation item.
- SNS and Security Hub success confirm reporting, not the IAM outcome.
  CloudTrail and the resulting IAM state provide independent action evidence.
- Existing broad Terraform deployment-role permissions require a separate
  hardening review.
- No fresh Checkov or Prowler results are claimed for this phase.