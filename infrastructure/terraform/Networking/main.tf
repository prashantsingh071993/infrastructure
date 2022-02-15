
resource "aws_vpc" "vpc" {
  cidr_block                     = "${var.cidr_block}"
  enable_dns_hostnames           = true
  enable_classiclink_dns_support = false
  tags = {
    vpcname = "${var.vpcname}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "subnet1" {
  vpc_id            = "${aws_vpc.vpc.id}"
  cidr_block        = "${var.subnet_cidr_block_1}"
  availability_zone = "${data.aws_availability_zones.available.names[0]}"

  #it will asssign public IP

  map_public_ip_on_launch = true
  tags = {
    vpcname = "${var.subnet1}"
  }
}

resource "aws_subnet" "subnet2" {
  vpc_id                  = "${aws_vpc.vpc.id}"
  cidr_block              = "${var.subnet_cidr_block_2}"
  availability_zone       = "${data.aws_availability_zones.available.names[1]}"
  map_public_ip_on_launch = true
  tags = {
    vpcname = "${var.subnet2}"
  }
}

resource "aws_subnet" "subnet3" {
  vpc_id                  = "${aws_vpc.vpc.id}"
  cidr_block              = "${var.subnet_cidr_block_3}"
  availability_zone       = "${data.aws_availability_zones.available.names[2]}"
  map_public_ip_on_launch = true
  tags = {
    vpcname = "${var.subnet3}"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.vpc.id}"
  tags = {
    vpcname = "${var.internetGateway}"
  }
}

resource "aws_route_table" "routetable" {
  vpc_id = "${aws_vpc.vpc.id}"
  tags = {
    vpcname = "${var.routetableName}"
  }
}

resource "aws_route_table_association" "r1" {
  subnet_id      = "${aws_subnet.subnet1.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "r2" {
  subnet_id      = "${aws_subnet.subnet2.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route_table_association" "r3" {
  subnet_id      = "${aws_subnet.subnet3.id}"
  route_table_id = "${aws_route_table.routetable.id}"
}

resource "aws_route" "route" {
  route_table_id         = "${aws_route_table.routetable.id}"
  destination_cidr_block = "${var.destination_cidr_block}"
  gateway_id             = "${aws_internet_gateway.gw.id}"
}
