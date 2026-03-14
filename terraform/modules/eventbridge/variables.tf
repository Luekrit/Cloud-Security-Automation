variable "project_name" {
  description = "Project name used for naming EventBridge resources"
  type        = string
}

variable "environment" {
  description = "Environment name such as dev or prod"
  type        = string
}

variable "lambda_function_arn" {
  description = "ARN of the Lambda function to invoke"
  type        = string
}

variable "rule_name_suffix" {
  description = "Suffix appended to the EventBridge rule name"
  type        = string
  default     = "iam-risk-detection"
}

variable "rule_description" {
  description = "Description of the EventBridge rule"
  type        = string
  default     = "Detect risky IAM API activity and trigger remediation"
}

variable "target_id" {
  description = "Target ID for the EventBridge target"
  type        = string
  default     = "InvokeRemediationLambda"
}

variable "event_names" {
  description = "IAM API event names that should trigger the remediation rule"
  type        = list(string)

  default = [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "PassRole"
  ]

  validation {
    condition     = length(var.event_names) > 0
    error_message = "event_names must contain at least one IAM API event."
  }
}

variable "tags" {
  description = "Common tags applied to EventBridge resources"
  type        = map(string)
  default     = {}
}