terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  allowed_test_user_arn           = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/iam-test-*"
  administrator_access_policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.project_name}-${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_remediation_policy" {
  name = "${var.project_name}-${var.environment}-lambda-remediation-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AllowReadTestIamUserForExceptionCheck"
          Effect = "Allow"
          Action = [
            "iam:GetUser",
            "iam:ListUserTags"
          ]
          Resource = local.allowed_test_user_arn
        },
        {
          Sid    = "AllowDetachAdministratorAccessFromTestUsersOnly"
          Effect = "Allow"
          Action = [
            "iam:DetachUserPolicy"
          ]
          Resource = local.allowed_test_user_arn
          Condition = {
            StringEquals = {
              "iam:PolicyARN" = local.administrator_access_policy_arn
            }
          }
        }
      ],

      # SNS publish (existing) - only added when a topic ARN is supplied.
      var.sns_topic_arn != "" ? [
        {
          Sid    = "AllowPublishToProjectSnsTopic"
          Effect = "Allow"
          Action = [
            "sns:Publish"
          ]
          Resource = var.sns_topic_arn
        }
      ] : [],

      # KMS - required to publish to a KMS-encrypted SNS topic. Without this,
      # sns:Publish fails authorization and the alert channel dies silently.
      # Scoped to SNS usage only via kms:ViaService so the role cannot use this
      # key for arbitrary KMS operations. If a publish ever fails ON THE
      # CONDITION during testing, remove the Condition block but keep Resource.
      var.sns_kms_key_arn != "" ? [
        {
          Sid    = "AllowUseOfSnsKmsKeyForPublishViaSns"
          Effect = "Allow"
          Action = [
            "kms:GenerateDataKey*",
            "kms:Decrypt"
          ]
          Resource = var.sns_kms_key_arn
          Condition = {
            StringEquals = {
              "kms:ViaService" = "sns.${data.aws_region.current.name}.amazonaws.com"
            }
          }
        }
      ] : [],

      # DynamoDB - read-only lookup of exception records. If this is omitted
      # (empty ARN), check_exception() hits its fail-closed ClientError path on
      # every invocation and no approval is ever honoured.
      var.exception_table_arn != "" ? [
        {
          Sid    = "AllowReadExceptionGovernanceTable"
          Effect = "Allow"
          Action = [
            "dynamodb:GetItem"
          ]
          Resource = var.exception_table_arn
        }
      ] : [],

      # Extended live remediation for the new Phase 4 scenarios. Gated behind an
      # explicit flag so the CAPABILITY to delete does not exist until
      # deliberately enabled - defense in depth on top of the DRY_RUN env var.
      # NOTE: no iam:PolicyARN condition here. That condition key applies to
      # attach/detach of MANAGED policies only; on these actions it would never
      # match and would deny every call. Scope is by resource ARN instead.
      var.enable_extended_remediation ? [
        {
          Sid    = "AllowExtendedRemediationOnTestUsersOnly"
          Effect = "Allow"
          Action = [
            "iam:DeleteUserPolicy",
            "iam:DeleteAccessKey",
            "iam:DeleteLoginProfile"
          ]
          Resource = local.allowed_test_user_arn
        }
      ] : []
    )
  })
}
