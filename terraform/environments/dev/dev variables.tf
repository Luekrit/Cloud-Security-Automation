variable "aws_region" {
  description = "AWS region for this environment"
  type        = string
}

variable "aws_profile" {
  description = "AWS CLI profile used by Terraform"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "event_names" {
  description = "CloudTrail event names that EventBridge should match"
  type        = list(string)

  default = [
    "AttachUserPolicy"
  ]
}

variable "alert_email" {
  description = "Email address subscribed to the SNS security alerts topic"
  type        = string
}

variable "enable_security_hub" {
  description = "Enables Phase 5 ASFF publishing and its least-privilege runtime permission. Security Hub must already be enabled in us-east-1."
  type        = bool
  default     = false
}

variable "remediation_dry_run" {
  description = "Keep remediation in dry-run mode unless a controlled live test is explicitly enabled."
  type        = bool
  default     = true
}

variable "live_remediation_user" {
  description = "Exact disposable IAM username allowed for controlled live remediation. Empty keeps live remediation unarmed."
  type        = string
  default     = ""
}