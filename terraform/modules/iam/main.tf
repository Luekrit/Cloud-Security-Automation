terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
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
          Sid    = "AllowDetachUserPolicy"
          Effect = "Allow"
          Action = [
            "iam:DetachUserPolicy"
          ]
          Resource = "*"
        }
      ],
      var.sns_topic_arn != "" ? [
        {
          Sid    = "AllowPublishToSns"
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