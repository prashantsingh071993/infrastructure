variable "vpc_id" {
  type    = "string"
  default = ""
}

variable "subnet2_id" {
  type    = "string"
  default = ""
}
variable "subnet3_id" {
  type    = "string"
  default = ""
}

variable "bucketName" {
  type    = "string"
  default = "codedeploy.prod.singhprasha.me"
}

variable "codedeployS3Bucket" {
  type    = "string"
  default = "blah"
}

variable "ami_id" {
  type    = "string"
  default = ""
}
variable "key_name" {
  type    = "string"
  default = ""
}

variable "aws_circleci_user_name" {
  type = "string"
}

variable "lambdaBucket" {
  type    = "string"
  default = "lambdaBucket"
}

variable "domainName" {
  type = "string"
}


variable "TTL" {
  type = "string"
}
