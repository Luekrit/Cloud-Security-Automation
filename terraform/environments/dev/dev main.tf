locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  cloudtrail_trail_name = "${var.project_name}-${var.environment}-trail"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

module "iam" {
  source = "../../modules/iam"

  project_name  = var.project_name
  environment   = var.environment
  sns_topic_arn = module.sns_global.topic_arn
  tags          = local.common_tags
}

module "lambda" {
  source = "../../modules/lambda"

  project_name       = var.project_name
  environment        = var.environment
  lambda_role_arn    = module.iam.lambda_execution_role_arn
  lambda_source_path = "../../../lambda/src/remediate.py"
  tags               = local.common_tags
}

module "cloudtrail_logs_bucket" {
  source = "../../modules/s3"

  bucket_name = "${var.project_name}-${var.environment}-cloudtrail-logs"
  tags        = local.common_tags
}

data "aws_iam_policy_document" "cloudtrail_kms_policy" {
  statement {
    sid    = "EnableRootAccountKeyAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "kms:*"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailGenerateDataKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey*"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_trail_name}"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
      ]
    }
  }

  statement {
    sid    = "AllowCloudTrailDescribeKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_trail_name}"
      ]
    }
  }

  statement {
    sid    = "AllowCloudTrailDecryptForS3BucketKey"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_trail_name}"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
      ]
    }
  }
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.cloudtrail_kms_policy.json

  tags = local.common_tags
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.project_name}-${var.environment}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  project_name           = var.project_name
  environment            = var.environment
  s3_bucket_name         = module.cloudtrail_logs_bucket.bucket_name
  cloudtrail_kms_key_arn = aws_kms_key.cloudtrail.arn
  tags                   = local.common_tags
}

# Existing Sydney EventBridge rule
# You can keep this for now or remove it later after us-east-1 is confirmed working.
module "eventbridge" {
  source = "../../modules/eventbridge"

  project_name        = var.project_name
  environment         = var.environment
  lambda_function_arn = module.lambda.lambda_function_arn
  event_names         = var.event_names
  tags                = local.common_tags
}

# New us-east-1 Lambda for real IAM global event detection
module "lambda_global" {
  source = "../../modules/lambda"

  providers = {
    aws = aws.global
  }

  project_name       = "${var.project_name}-global"
  environment        = var.environment
  lambda_role_arn    = module.iam.lambda_execution_role_arn
  lambda_source_path = "../../../lambda/src/remediate.py"

  environment_variables = {
    SNS_TOPIC_ARN       = module.sns_global.topic_arn
    EXCEPTION_TAG_KEY   = "SecurityApproved"
    EXCEPTION_TAG_VALUE = "true"
  }

  tags = merge(local.common_tags, { RegionScope = "global-us-east-1" })
}

# New us-east-1 EventBridge rule for real IAM events
module "eventbridge_global" {
  source = "../../modules/eventbridge"

  providers = {
    aws = aws.global
  }

  project_name        = "${var.project_name}-global"
  environment         = var.environment
  lambda_function_arn = module.lambda_global.lambda_function_arn

  event_names = [
    "AttachUserPolicy"
  ]

  tags = merge(local.common_tags, { RegionScope = "global-us-east-1" })
}

module "sns_global" {
  source = "../../modules/sns"

  providers = {
    aws = aws.global
  }

  project_name      = var.project_name
  environment       = "${var.environment}-global"
  topic_name_suffix = "security-alerts"
  email_endpoint    = var.alert_email
  tags              = local.common_tags
}