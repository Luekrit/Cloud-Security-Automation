variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "topic_name_suffix" {
  type    = string
  default = "security-alerts"
}

variable "email_endpoint" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}