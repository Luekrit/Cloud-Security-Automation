variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "trail_name" {
  description = "CloudTrail trail name"
  type        = string
  default     = null
}

variable "s3_bucket_name" {
  description = "S3 bucket for CloudTrail logs"
  type        = string
}

variable "enable_logging" {
  description = "Whether to enable logging"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "cloudtrail_kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudTrail logs"
  type        = string
  default     = null
}