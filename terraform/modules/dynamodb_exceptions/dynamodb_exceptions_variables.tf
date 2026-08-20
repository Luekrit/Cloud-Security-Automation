variable "table_name" {
  description = "Name of the DynamoDB table used for security exception governance."
  type        = string
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for the DynamoDB exception table."
  type        = bool
  default     = true
  # Defaults true, not false - PITR is the safe default for a table that
  # gates security decisions. Turning it off should take a deliberate
  # override, not be the thing that happens if nobody sets it.
}

variable "kms_key_arn" {
  description = "Optional customer-managed KMS key ARN for table encryption. Leave null to use the AWS-managed alias/aws/dynamodb key."
  type        = string
  default     = null
  # Left as an open door, not a forced decision. The current default
  # matches the SNS topic's key choice; if you later want a CMK here (say,
  # to add a key policy restricting exactly which roles can decrypt
  # exception records), this is the one line that changes.
}

variable "tags" {
  description = "Tags applied to the DynamoDB exception table."
  type        = map(string)
  default     = {}
}

variable "ttl_enabled" {
  description = "Enable DynamoDB TTL for exception record retention cleanup."
  type        = bool
  default     = true
}

variable "ttl_attribute_name" {
  description = "DynamoDB TTL attribute used for deleting old exception records after audit retention."
  type        = string
  default     = "ttl_delete_at_epoch"
}
