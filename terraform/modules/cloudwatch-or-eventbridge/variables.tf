variable "project_name" {
  description = "Project name used for naming EventBridge resources"
  type        = string
}

variable "environment" {
  description = "Environment name such as dev or prod"
  type        = string
}

variable "lambda_function_arn" {
  description = "ARN of the Lambda function to invoke when the rule matches"
  type        = string
}

variable "rule_name_suffix" {
  description = "Suffix appended to the EventBridge rule name"
  type        = string
  default     = "iam-policy-change"
}

variable "rule_description" {
  description = "Description of the EventBridge rule"
  type        = string
  default     = "Detect risky IAM policy attachment events"
}

variable "event_names" {
  description = "IAM API event names that should trigger the rule"
  type        = list(string)
  default     = ["AttachRolePolicy"]
}

variable "tags" {
  description = "Common tags applied to EventBridge resources"
  type        = map(string)
  default     = {}
}