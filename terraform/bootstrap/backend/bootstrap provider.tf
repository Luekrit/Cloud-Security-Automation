terraform {
  required_version = ">= 1.11.0"
  backend "s3" {
    bucket       = "luekrit-tf-state"
    key          = "bootstrap/terraform.tfstate" # Different key from dev
    region       = "ap-southeast-2"
    use_lockfile = true
    encrypt      = true
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  profile = var.aws_profile
}

