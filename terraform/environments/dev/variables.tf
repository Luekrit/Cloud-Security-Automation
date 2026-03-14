variable "project_name" {
  description = "Project name"
  type        = string
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
}
variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "event_names" {
  description = "IAM API event names that should trigger remediation"
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
}