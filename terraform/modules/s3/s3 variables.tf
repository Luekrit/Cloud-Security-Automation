variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "force_destroy" {
  description = "Allow bucket deletion even if it contains objects"
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "KMS key ARN for SSE-KMS encryption. Uses the AWS managed S3 key (aws/s3) if not provided."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to the S3 bucket"
  type        = map(string)
  default     = {}
}
