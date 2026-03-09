data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = var.lambda_source_path
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "remediation_lambda" {
  function_name = "${var.project_name}-${var.environment}-remediation"

  runtime = "python3.11"
  handler = "remediate.lambda_handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  role = var.lambda_role_arn

  timeout = 30

  tags = var.tags
}