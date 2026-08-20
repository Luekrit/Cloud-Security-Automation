terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# ---------------------------------------------------------------------------
# DynamoDB Exception Governance Table
# ---------------------------------------------------------------------------
# Replaces the old IAM-tag-based exception model. A SecurityApproved=true tag
# could be set by anyone holding iam:TagUser - including the same actor the
# control exists to check. That made the "approval" self-issuable, which is
# a bypass wearing a governance costume, not governance.
#
# This table is read-only from the Lambda's side - the IAM module only ever
# grants dynamodb:GetItem here. Exception records get written out-of-band by
# a human with dynamodb:PutItem access. That's what actually gives you
# maker/checker separation: the system asking "is this exception valid?" is
# never the system that can say "yes."

resource "aws_dynamodb_table" "this" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  # On-demand: exception lookups are one GetItem per risky IAM event - low
  # volume and bursty. Provisioned capacity would mean paying to keep
  # throughput idle almost all the time.

  hash_key  = "pk"
  range_key = "sk"
  # Composite key on purpose, not convenience. pk scopes the resource
  # ("RESOURCE#<name>"), sk scopes the control ("CONTROL#<control_id>").
  # An approval for "attach AdministratorAccess to user X" (one sk) does
  # not cover "create an access key for user X" (a different sk under the
  # same pk) - each risky action needs its own, separately approved record.

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }
  # Only key attributes are declared here. status, expires_at, approved_by
  # and the rest are just item data - DynamoDB doesn't need them defined
  # up front the way a relational schema would.

  ttl {
    attribute_name = var.ttl_attribute_name
    enabled        = var.ttl_enabled
  }
  # TTL is housekeeping, not enforcement. DynamoDB can take up to 48 hours
  # to actually delete an expired item, so remediate.py never trusts TTL by
  # itself - it re-checks expires_at_epoch against the current time on
  # every read (see check_exception() in remediate.py). TTL just keeps this
  # table from accumulating dead records forever.

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
  # enabled = true with kms_key_arn left null uses AWS's managed key
  # (alias/aws/dynamodb) - the same category of call already made for the
  # SNS topic (alias/aws/sns over a customer-managed key). This table holds
  # exception metadata, not the CloudTrail log integrity chain, so a CMK
  # isn't buying real additional protection here. Pass var.kms_key_arn if
  # that changes.

  point_in_time_recovery {
    enabled = var.enable_point_in_time_recovery
  }
  # Checkov flagged this as a genuine fix, not an accept-with-reason. PITR
  # protects the records that decide whether risky IAM activity gets
  # remediated or skipped - a bad update-item call or an accidental delete
  # on this table has real consequences, so it should be recoverable.

  tags = var.tags
}
