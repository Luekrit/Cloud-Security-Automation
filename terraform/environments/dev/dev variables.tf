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
  description = "novemberluekrit2537@outlook.com"
  type        = string
}