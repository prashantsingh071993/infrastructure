
variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "cidr_block" {
  type    = "string"
  default = "10.0.0.0/16"
}

variable "vpcname" {
  type    = "string"
  default = "testvpc"
}

variable "subnet_cidr_block_1" {
  type    = "string"
  default = "10.0.1.0/24"

}

variable "subnet_cidr_block_2" {
  type    = "string"
  default = "10.0.2.0/24"
}

variable "subnet_cidr_block_3" {
  type    = "string"
  default = "10.0.3.0/24"
}



variable "subnet1" {
  type    = "string"
  default = "test-subnet1"
}

variable "subnet2" {
  type    = "string"
  default = "test-subnet2"
}

variable "subnet3" {
  type    = "string"
  default = "test-subnet3"
}

variable "internetGateway" {
  type    = "string"
  default = "test-internetGateway"
}


variable "routetableName" {
  type    = "string"
  default = "test-routetable"
}

variable "destination_cidr_block" {
  type    = "string"
  default = "0.0.0.0/0"
}
