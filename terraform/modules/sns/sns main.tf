terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

locals {
  topic_name = "${var.project_name}-${var.environment}-${var.topic_name_suffix}"
}

resource "aws_sns_topic" "this" {
  name = local.topic_name
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.email_endpoint != "" ? 1 : 0
  topic_arn = aws_sns_topic.this.arn
  protocol  = "email"
  endpoint  = var.email_endpoint
}