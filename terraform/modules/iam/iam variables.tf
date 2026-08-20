variable "project_name" {
  description = "Project name used for naming IAM resources"
  type        = string
}

variable "environment" {
  description = "Environment name such as dev or prod"
  type        = string
}

variable "tags" {
  description = "Common tags applied to IAM resources"
  type        = map(string)
  default     = {}
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic the Lambda publishes alerts to. Empty string disables the publish grant."
  type        = string
  default     = ""
}

variable "sns_kms_key_arn" {
  description = "ARN of the customer-managed KMS key encrypting the SNS topic. Required when the topic uses SSE-KMS; empty string disables the KMS grant."
  type        = string
  default     = ""
}

variable "exception_table_arn" {
  description = "ARN of the DynamoDB exception governance table. Empty string disables the read grant, in which case the Lambda fails closed on every exception lookup."
  type        = string
  default     = ""
}

variable "enable_extended_remediation" {
  description = "When true, grants the Lambda role permission to delete inline policies, access keys, and login profiles on test users. Capability gate for live remediation; keep false while operating in dry-run."
  type        = bool
  default     = false
}
