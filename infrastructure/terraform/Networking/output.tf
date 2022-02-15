output "vpc_id" {
  value = "${aws_vpc.vpc.id}"
}

output "public_subnet_id2" {
  value = "${aws_subnet.subnet2.id}"
}

output "public_subnet_id3" {
  value = "${aws_subnet.subnet3.id}"
}
