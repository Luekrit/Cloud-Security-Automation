locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

module "iam" {
  source = "../../modules/iam"

  project_name = var.project_name
  environment  = var.environment
  tags         = local.common_tags
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

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  project_name   = var.project_name
  environment    = var.environment
  s3_bucket_name = module.cloudtrail_logs_bucket.bucket_name
  tags           = local.common_tags
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
    SNS_TOPIC_ARN = module.sns_global.topic_arn
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