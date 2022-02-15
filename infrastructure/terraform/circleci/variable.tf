
variable "region" {
  type    = "string"
  default = "us-east-1"
}

#Application Stack reference Variable


variable "accountId" {
  type    = "string"
  default = "blah"
}

variable "codeDeployApplicationName" {
  type    = "string"
  default = "blah"
}

variable "codeDeployApplicationGroup" {
  type    = "string"
  default = "blah"
}

variable "aws_circleci_user_name" {
  type = "string"
}
