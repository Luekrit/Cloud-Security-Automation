terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

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
      var.sns_topic_arn != "" ? [
        {
          Sid    = "AllowPublishToProjectSnsTopic"
          Effect = "Allow"
          Action = [
            "sns:Publish"
          ]
          Resource = var.sns_topic_arn
        }
      ] : []
    )
  })
}