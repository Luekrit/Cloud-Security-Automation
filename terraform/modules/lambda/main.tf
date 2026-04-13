terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }

    archive = {
      source = "hashicorp/archive"
    }
  }
}
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = var.lambda_source_path
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "remediation_lambda" {
  function_name = "${var.project_name}-${var.environment}-remediation"

  role    = var.lambda_role_arn
  handler = "remediate.lambda_handler"
  runtime = "python3.12"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout = 30

  environment {
    variables = merge(
      {
        DRY_RUN = tostring(var.dry_run)
      },
      var.environment_variables
    )
  }
  tags = var.tags
}