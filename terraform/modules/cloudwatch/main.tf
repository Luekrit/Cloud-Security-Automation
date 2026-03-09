resource "aws_cloudwatch_event_rule" "security_detection" {
  name        = "${var.project_name}-${var.environment}-iam-detection"
  description = "Detect IAM user creation events"

  event_pattern = jsonencode({
    source = ["aws.iam"]

    detail-type = ["AWS API Call via CloudTrail"]

    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateUser"]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda_trigger" {
  rule = aws_cloudwatch_event_rule.security_detection.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_arn
  principal     = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.security_detection.arn
}