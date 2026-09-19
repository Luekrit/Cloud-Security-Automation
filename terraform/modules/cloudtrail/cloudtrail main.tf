locals {
  trail_name = var.trail_name != null ? var.trail_name : "${var.project_name}-${var.environment}-trail"
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${local.trail_name}"
  retention_in_days = 365
  kms_key_id        = var.cloudtrail_kms_key_arn

  tags = var.tags
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_assume_role" {
  statement {
    sid    = "AllowCloudTrailAssumeRole"
    effect = "Allow"

    actions = [
      "sts:AssumeRole"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.project_name}-${var.environment}-cloudtrail-cloudwatch-role"

  assume_role_policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch" {
  statement {
    sid    = "AllowCloudTrailWriteToCloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name   = "${var.project_name}-${var.environment}-cloudtrail-cloudwatch-policy"
  role   = aws_iam_role.cloudtrail_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch.json
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = var.s3_bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.s3_bucket_name}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.s3_bucket_name}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = var.s3_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = var.enable_logging

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # Detects if log files are modified or deleted after delivery
  enable_log_file_validation = true

  # Encrypts CloudTrail-delivered log files using a customer-managed KMS key when provided
  kms_key_id = var.cloudtrail_kms_key_arn

  event_selector {
    read_write_type           = "WriteOnly"
    include_management_events = true
  }

  tags = var.tags

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_iam_role_policy.cloudtrail_cloudwatch
  ]
}