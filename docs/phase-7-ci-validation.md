# Phase 7: CI Checks and Protected Terraform Plan

## Outcome

Python regression tests and Terraform dev validation passed in GitHub Actions.
The protected dev plan completed with no proposed changes.
The report-only Checkov CI scan recorded a baseline of
98 passed, 19 failed, and 0 skipped.

## Purpose and Scope

Automate validation of Python and Terraform changes before merge, surface IaC
findings during review, and verify the AWS dev plan through a separate workflow
with dedicated AWS access.

## Controls Added

- Run Python regression tests, Terraform dev validation, and Checkov on pull
  requests and pushes to `main`.
- Run the AWS-backed dev plan manually from `main` in the `terraform-plan-dev`
  environment. GitHub OIDC supplies temporary credentials through a dedicated
  AWS plan role.
- Pass `remediation_dry_run=true` and an empty `live_remediation_user` to the
  dev plan. Deployment requires a separate manual apply of a reviewed plan.

## Validation Performed

| Check | Result |
| --- | --- |
| Python regression tests and Terraform dev validation | Both CI jobs passed. |
| Protected Terraform dev plan | Run #7 at commit `0641df6` completed with no proposed changes. |
| Checkov 3.3.16 | PR #28 run #5 reported 98 passed, 19 failed, and 0 skipped. |

## Deployment Issue and Resolution

Windows and Linux initially produced different Lambda ZIP hashes.
Normalising the Python source to LF and setting ZIP entry permissions to
`0644` made the hashes match. After the reviewed deployment, AWS confirmed
`DRY_RUN=true` and an empty live remediation target. The subsequent dev plan
proposed no changes.

## Evidence

- [CI validation run #3](https://github.com/Luekrit/Cloud-Security-Automation/actions/runs/42647317871)
- [Terraform dev plan run #7](https://github.com/Luekrit/Cloud-Security-Automation/actions/runs/43004069488)
- [Checkov Terraform scan run #5](https://github.com/Luekrit/Cloud-Security-Automation/actions/runs/43701046747)
- [Checkov risk register](phase-7-checkov-risk-register.md)

## Limitations and Remaining Work

The 19 Checkov findings remain open, with individual dispositions,
justifications, and follow-up actions documented in the
[Checkov risk register](phase-7-checkov-risk-register.md).
Checkov runs in report-only mode, so findings do not block merges.
Blocking enforcement remains a proposed follow-up.

Terraform dev plan #7 proposed no changes to the AWS dev environment
when it ran from `main` at commit `0641df6`.