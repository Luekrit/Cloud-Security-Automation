variable "project_name" {
  description = "Project name used for naming resources"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "lambda_role_arn" {
  description = "IAM role ARN for Lambda execution"
  type        = string
}

variable "lambda_source_path" {
  description = "Path to the Lambda source code"
  type        = string
}

variable "tags" {
  description = "Common tags applied to Lambda resources"
  type        = map(string)
  default     = {}
}

variable "dry_run" {
  type    = bool
  default = true
}

variable "environment_variables" {
  type    = map(string)
  default = {}
}