# -----------------------------------------------------------------------------
# Production Environment
# -----------------------------------------------------------------------------
# Not yet deployed. This environment mirrors the dev configuration but is
# intentionally left unpopulated until Phase 5 (controlled live remediation).
#
# Before deploying to prod:
#   - Set DRY_RUN = false only after full validation in dev
#   - Review PROTECTED_USERS and DANGEROUS_POLICIES in remediate.py
#   - Confirm SNS alert email is a monitored production mailbox
#   - Run terraform plan and review all changes before apply
# -----------------------------------------------------------------------------
