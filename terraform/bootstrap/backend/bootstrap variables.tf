variable "aws_region" {
  description = "AWS region for Terraform backend resources"
  type        = string
  default     = "ap-southeast-2"
}

variable "aws_profile" {
  description = "AWS CLI profile used for backend bootstrap"
  type        = string
  default     = "terraform"
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket used for Terraform remote state"
  type        = string
}

variable "project_name" {
  description = "Project name used for tagging"
  type        = string
  default     = "cloud-security-automation"
}

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "shared"
}