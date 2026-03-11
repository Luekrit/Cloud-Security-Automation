resource "aws_cloudwatch_event_rule" "security_detection_rule" {
  name        = "${var.project_name}-${var.environment}-iam-policy-change"
  description = "Detect IAM policy changes"

  event_pattern = jsonencode({
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["iam.amazonaws.com"],
      "eventName": [
        "CreatePolicy",
        "DeletePolicy",
        "AttachRolePolicy",
        "PutRolePolicy"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.security_detection_rule.name
  target_id = "LambdaSecurityRemediation"
  arn       = var.lambda_function_arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_detection_rule.arn
}