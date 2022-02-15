#security groups
#Application Security group
resource "aws_security_group" "application_security_group" {
  name        = "application_security_group"
  description = "Application security group"
  vpc_id      = "${var.vpc_id}"

  ingress {
    from_port       = 3005
    to_port         = 3005
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
    security_groups = ["${aws_security_group.lb_sg.id}"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}



## Security Group for ALB
resource "aws_security_group" "lb_sg" {
  name        = "aws_lb_sg"
  vpc_id      = "${var.vpc_id}"
  description = "Allow ALB inbound traffic"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}


#Creating db security group
resource "aws_db_subnet_group" "rds_sn" {
  name       = "rds_subnet_group"
  subnet_ids = ["${var.subnet2_id}", "${var.subnet3_id}"]
}


resource "aws_security_group" "database" {
  name        = "database_security_group"
  vpc_id      = "${var.vpc_id}"
  description = "allow incoming database connection"
  ingress {
    from_port       = 5432
    protocol        = "tcp"
    security_groups = ["${aws_security_group.application_security_group.id}"]
    to_port         = 5432
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "rds" {
  allocated_storage      = 20
  identifier             = "csye6225-fall2019"
  multi_az               = false
  db_subnet_group_name   = "${aws_db_subnet_group.rds_sn.name}"
  engine                 = "postgres"
  engine_version         = "11.5"
  instance_class         = "db.t2.micro"
  name                   = "thunderstorm"
  username               = "thunderstorm"
  password               = "thunderstorm_123"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot    = true
  publicly_accessible    = true

}

resource "aws_s3_bucket" "s3" {

  bucket        = "${var.bucketName}"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}


resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = "csye6225"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "id"


  attribute {
    name = "id"
    type = "S"
  }
}
#policies

resource "aws_iam_policy" "policy2" {
  name        = "CircleCI-Upload-To-S3"
  description = "s3 upload Policy for user circleci"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
            "arn:aws:s3:::${var.codedeployS3Bucket}",
            "arn:aws:s3:::${var.lambdaBucket}",
            "arn:aws:s3:::${var.bucketName}"
            ]
        }
    ]
}

EOF
}

resource "aws_iam_policy" "policy3" {
  name        = "circleci-ec2-ami"
  description = "EC2 access for user circleci"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
      "Effect": "Allow",
      "Action" : [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource" : "*"
  }]
}
EOF
}

resource "aws_iam_policy" "app_policy" {
  name        = "CodeDeploy-EC2-APP"
  description = "EC2 APP access policy"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:Get*",
                "s3:List*",
                "s3:Put*",
                "s3:Delete*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:PutLogEvents",
              "logs:DescribeLogStreams"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
EOF
}

#attanchments

resource "aws_iam_policy_attachment" "circleci-attach2" {
  name  = "circleci-attachment-uploadtos3"
  users = ["${var.aws_circleci_user_name}"]
  #roles      = ["${aws_iam_role.role.name}"]
  #groups     = ["${aws_iam_group.group.name}"]
  policy_arn = "${aws_iam_policy.policy2.arn}"
  depends_on = ["aws_iam_policy.policy2"]
}

resource "aws_iam_policy_attachment" "circleci-attach3" {
  name  = "circleci-attachment-ec2-ami"
  users = ["${var.aws_circleci_user_name}"]
  #roles      = ["${aws_iam_role.role.name}"]
  #groups     = ["${aws_iam_group.group.name}"]
  policy_arn = "${aws_iam_policy.policy3.arn}"
  depends_on = ["aws_iam_policy.policy3"]
}


resource "aws_iam_policy_attachment" "circleci-attach4" {
  name  = "circleci-attachment-tests"
  users = ["${var.aws_circleci_user_name}"]
  #roles      = ["${aws_iam_role.role.name}"]
  #groups     = ["${aws_iam_group.group.name}"]
  policy_arn = "${aws_iam_policy.app_policy.arn}"
  depends_on = ["aws_iam_policy.app_policy"]
}

resource "aws_iam_policy_attachment" "lambdaCircleCI" {
  name       = "circleci-attachment-tests"
  users      = ["${var.aws_circleci_user_name}"]
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
  depends_on = ["aws_iam_policy.policy3"]
}

resource "aws_iam_role" "role1" {
  name        = "CodeDeployEC2ServiceRole"
  description = "Allows EC2 instances to call AWS services on your behalf"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "role1_profile" {
  name = "CodeDeployEC2ServiceRole"
  role = "${aws_iam_role.role1.name}"
}

resource "aws_iam_role_policy_attachment" "role1-attach" {
  role       = "${aws_iam_role.role1.name}"
  policy_arn = "${aws_iam_policy.app_policy.arn}"
}

resource "aws_cloudwatch_log_group" "thunderstormlogs" {
  name = "thunderstorm12"

}

resource "aws_iam_role_policy_attachment" "cloudwatch-attach" {
  role       = "${aws_iam_role.role1.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role" "role2" {
  name        = "CodeDeployServiceRole"
  description = "Allows CodeDeploy to call AWS services such as Auto Scaling on your behalf"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "codedeploy.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}


resource "aws_iam_role_policy_attachment" "codedeploy_service" {
  role       = "${aws_iam_role.role2.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}

resource "aws_s3_bucket" "codeDeployBucket" {
  bucket        = "${var.codedeployS3Bucket}"
  acl           = "private"
  force_destroy = true
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    enabled = "true"
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }

}

resource "aws_codedeploy_app" "codedeploy_app" {
  name = "csye6225-webapp"
}

# resource "aws_sns_topic" "example" {
#   name = "example-topic"
# }

resource "aws_codedeploy_deployment_group" "codedeploy_deployment_group" {
  app_name               = "csye6225-webapp"
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = "${aws_iam_role.role2.arn}"

  ec2_tag_set {
    ec2_tag_filter {
      key   = "name"
      type  = "KEY_AND_VALUE"
      value = "Codedeploy_ec2"
    }
  }
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["my-alarm-name"]
    enabled = true
  }

  load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = ["${aws_lb_listener.ssl.arn}"]
      }

      target_group {
        name = "${aws_lb_target_group.ip-example.name}"
      }

    }
  }
  autoscaling_groups = ["${aws_autoscaling_group.as_group.name}"]
}



resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {

  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
resource "aws_iam_role_policy_attachment" "AmazonSESFullAccess" {

  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
}
resource "aws_iam_role_policy_attachment" "mgd_pol_1" {

  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
}

resource "aws_iam_role_policy_attachment" "lambdaCircleCI" {

  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}

resource "aws_lambda_function" "user_recipes_fn" {
  filename      = "${path.module}/userRecipes.zip"
  function_name = "userRecipes"
  role          = "${aws_iam_role.iam_for_lambda.arn}"
  handler       = "index.userRecipes"
  timeout       = 20
  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  # source_code_hash = "${filebase64sha256("lambda_function_payload.zip")}"

  runtime = "nodejs8.10"

  environment {
    variables = {
      DOMAIN_NAME = "${var.domainName}",
      TTL         = "${var.TTL}"
    }
  }
}
resource "aws_sns_topic" "user-recipes" {
  name = "user-recipes-topic"
}
resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.user_recipes_fn.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.user-recipes.arn}"
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = "${aws_sns_topic.user-recipes.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.user_recipes_fn.arn}"
}

resource "aws_s3_bucket" "lambdaBucket" {
  bucket        = "${var.lambdaBucket}"
  acl           = "private"
  force_destroy = true
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  tags = {
    Name = "${var.lambdaBucket}"
  }

  lifecycle_rule {
    enabled = "true"
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }

}

resource "aws_iam_policy" "SNSToEC2" {
  name        = "SNSToEC2"
  description = "A test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "AttachSNSToEC2" {
  role       = "${aws_iam_role.role1.name}"
  policy_arn = "${aws_iam_policy.SNSToEC2.arn}"
}


resource "aws_launch_configuration" "asg_launch_config" {
  image_id      = "${var.ami_id}"
  instance_type = "t2.micro"
  key_name      = "${var.key_name}"
  user_data     = <<-EOF
                      #!/bin/bash -ex
                      exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
                      echo BEGIN
                      date '+%Y-%m-%d %H:%M:%S'
                      echo END
                      cd /home/centos
                      sudo touch environment.sh
                      chmod 777 environment.sh
                      echo export host=${aws_db_instance.rds.address} >> environment.sh
                      echo export RDS_CONNECTION_STRING=${aws_db_instance.rds.address} >> environment.sh
                      echo export RDS_USER_NAME=thunderstorm >> environment.sh
                      echo export RDS_PASSWORD=thunderstorm_123 >> environment.sh
                      echo export RDS_DB_NAME=thunderstorm >> environment.sh
                      echo export PORT=3005 >> environment.sh
                      echo export S3_BUCKET_NAME=${var.bucketName} >> environment.sh
                      echo export bucket=${var.codedeployS3Bucket} >> environment.sh
                      echo export DOMAIN_NAME=${var.domainName} >> environment.sh
  EOF
  root_block_device {
    volume_size           = "20"
    volume_type           = "gp2"
    delete_on_termination = "true"
  }
  iam_instance_profile        = "${aws_iam_instance_profile.role1_profile.name}"
  security_groups             = ["${aws_security_group.application_security_group.id}"]
  associate_public_ip_address = true
  depends_on                  = ["aws_db_instance.rds"]

  lifecycle {
    create_before_destroy = true
  }
}




resource "aws_lb" "my-test-lb" {
  name                       = "my-test-lb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = ["${aws_security_group.lb_sg.id}"]
  subnets                    = ["${var.subnet2_id}", "${var.subnet3_id}"]
  ip_address_type            = "ipv4"
  enable_deletion_protection = false

}

#web server group
resource "aws_lb_target_group" "ip-example" {
  name     = "tf-example-lb-tg"
  port     = 3005
  protocol = "HTTP"
  vpc_id   = "${var.vpc_id}"
  health_check {
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    path                = "/v1/howyoudoin"
  }
}

data "aws_acm_certificate" "example" {
  domain   = "${var.domainName}"
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = "${aws_lb.my-test-lb.arn}"
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.ip-example.arn}"
  }
}

resource "aws_lb_listener" "ssl" {
  load_balancer_arn = "${aws_lb.my-test-lb.arn}"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${data.aws_acm_certificate.example.arn}"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.ip-example.arn}"
  }
}

resource "aws_autoscaling_group" "as_group" {
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  vpc_zone_identifier  = ["${var.subnet2_id}", "${var.subnet3_id}"]
  target_group_arns    = ["${aws_lb_target_group.ip-example.arn}"]

  lifecycle {
    create_before_destroy = true
  }
  min_size         = 3
  max_size         = 10
  default_cooldown = "60"
  tag {
    #need to check
    key                 = "name"
    value               = "Codedeploy_ec2"
    propagate_at_launch = true
  }
}

# scale up alarm
resource "aws_autoscaling_policy" "example-cpu-policy" {
  name                   = "example-cpu-policy"
  autoscaling_group_name = "${aws_autoscaling_group.as_group.name}"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "1"
  cooldown               = "60"
  policy_type            = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "example-cpu-alarm" {
  alarm_name          = "example-cpu-alarm"
  alarm_description   = "example-cpu-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.as_group.name}"
  }
  actions_enabled = true
  alarm_actions   = ["${aws_autoscaling_policy.example-cpu-policy.arn}"]
}
# scale down alarm
resource "aws_autoscaling_policy" "example-cpu-policy-scaledown" {
  name                   = "example-cpu-policy-scaledown"
  autoscaling_group_name = "${aws_autoscaling_group.as_group.name}"
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "-1"
  cooldown               = "60"
  policy_type            = "SimpleScaling"
}
resource "aws_cloudwatch_metric_alarm" "example-cpu-alarm-scaledown" {
  alarm_name          = "example-cpu-alarm-scaledown"
  alarm_description   = "example-cpu-alarm-scaledown"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.as_group.name}"
  }
  actions_enabled = true
  alarm_actions   = ["${aws_autoscaling_policy.example-cpu-policy-scaledown.arn}"]
}


data "aws_route53_zone" "selected" {
  name         = "${var.domainName}"
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = "${data.aws_route53_zone.selected.zone_id}"
  name    = "${var.domainName}"
  type    = "A"
  alias {
    name                   = "${aws_lb.my-test-lb.dns_name}"
    zone_id                = "${aws_lb.my-test-lb.zone_id}"
    evaluate_target_health = false
  }
}


resource "aws_cloudformation_stack" "waf" {
  name = "waf-stack"

  parameters = {
    ALBArn = "${aws_lb.my-test-lb.arn}"
  }

  template_body = <<STACK
  {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Cloud Formation Template - CSYE6225 - Creating WAF Rules",
    "Parameters": {
        "IPtoBlock1": {
            "Description": "IPAddress to be blocked",
            "Default": "155.33.133.6/32",
            "Type": "String"
        },
        "IPtoBlock2": {
            "Description": "IPAddress to be blocked",
            "Default": "192.0.7.0/24",
            "Type": "String"
        },
        "ALBArn": {
            "Description": "IPAddress to be blocked",
            "Type": "String"
        }
    },
    "Resources": {
        "wafrSQLiSet": {
            "Type": "AWS::WAFRegional::SqlInjectionMatchSet",
            "Properties": {
                "Name": "wafrSQLiSet",
                "SqlInjectionMatchTuples": [
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "BODY"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "BODY"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "cookie"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "cookie"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "Authorization"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "Authorization"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    }
                ]
            }
        },
        "wafrSQLiRule": {
            "Type": "AWS::WAFRegional::Rule",
            "DependsOn": [
                "wafrSQLiSet"
            ],
            "Properties": {
                "MetricName": "wafrSQLiRule",
                "Name": "wafr-SQLiRule",
                "Predicates": [
                    {
                        "Type": "SqlInjectionMatch",
                        "Negated": false,
                        "DataId": {
                            "Ref": "wafrSQLiSet"
                        }
                    }
                ]
            }
        },
        "MyIPSetWhiteList": {
            "Type": "AWS::WAFRegional::IPSet",
            "Properties": {
                "Name": "WhiteList IP Address Set",
                "IPSetDescriptors": [
                    {
                        "Type": "IPV4",
                        "Value": "155.33.135.11/32"
                    },
                    {
                        "Type": "IPV4",
                        "Value": "192.0.7.0/24"
                    }
                ]
            }
        },
        "MyIPSetWhiteListRule": {
            "Type": "AWS::WAFRegional::Rule",
            "Properties": {
                "Name": "WhiteList IP Address Rule",
                "MetricName": "MyIPSetWhiteListRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "MyIPSetWhiteList"
                        },
                        "Negated": false,
                        "Type": "IPMatch"
                    }
                ]
            }
        },
        "myIPSetBlacklist": {
            "Type": "AWS::WAFRegional::IPSet",
            "Properties": {
                "Name": "myIPSetBlacklist",
                "IPSetDescriptors": [
                    {
                        "Type": "IPV4",
                        "Value": {
                            "Ref": "IPtoBlock1"
                        }
                    },
                    {
                        "Type": "IPV4",
                        "Value": {
                            "Ref": "IPtoBlock2"
                        }
                    }
                ]
            }
        },
        "myIPSetBlacklistRule": {
            "Type": "AWS::WAFRegional::Rule",
            "DependsOn": [
                "myIPSetBlacklist"
            ],
            "Properties": {
                "Name": "Blacklist IP Address Rule",
                "MetricName": "myIPSetBlacklistRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "myIPSetBlacklist"
                        },
                        "Negated": false,
                        "Type": "IPMatch"
                    }
                ]
            }
        },
        "MyScanProbesSet": {
            "Type": "AWS::WAFRegional::IPSet",
            "Properties": {
                "Name": "MyScanProbesSet"
            }
        },
        "MyScansProbesRule": {
            "Type": "AWS::WAFRegional::Rule",
            "DependsOn": "MyScanProbesSet",
            "Properties": {
                "Name": "MyScansProbesRule",
                "MetricName": "SecurityAutomationsScansProbesRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "MyScanProbesSet"
                        },
                        "Negated": false,
                        "Type": "IPMatch"
                    }
                ]
            }
        },
        "DetectXSS": {
            "Type": "AWS::WAFRegional::XssMatchSet",
            "Properties": {
                "Name": "XssMatchSet",
                "XssMatchTuples": [
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TextTransformation": "URL_DECODE"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TextTransformation": "HTML_ENTITY_DECODE"
                    }
                ]
            }
        },
        "XSSRule": {
            "Type": "AWS::WAFRegional::Rule",
            "Properties": {
                "Name": "XSSRule",
                "MetricName": "XSSRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "DetectXSS"
                        },
                        "Negated": false,
                        "Type": "XssMatch"
                    }
                ]
            }
        },
        "sizeRestrict": {
            "Type": "AWS::WAFRegional::SizeConstraintSet",
            "Properties": {
                "Name": "sizeRestrict",
                "SizeConstraints": [
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TextTransformation": "NONE",
                        "ComparisonOperator": "GT",
                        "Size": "512"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TextTransformation": "NONE",
                        "ComparisonOperator": "GT",
                        "Size": "1024"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "BODY"
                        },
                        "TextTransformation": "NONE",
                        "ComparisonOperator": "GT",
                        "Size": "204800"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "cookie"
                        },
                        "TextTransformation": "NONE",
                        "ComparisonOperator": "GT",
                        "Size": "4096"
                    }
                ]
            }
        },
        "reqSizeRule": {
            "Type": "AWS::WAFRegional::Rule",
            "DependsOn": [
                "sizeRestrict"
            ],
            "Properties": {
                "MetricName": "reqSizeRule",
                "Name": "reqSizeRule",
                "Predicates": [
                    {
                        "Type": "SizeConstraint",
                        "Negated": false,
                        "DataId": {
                            "Ref": "sizeRestrict"
                        }
                    }
                ]
            }
        },
        "PathStringSetReferers": {
            "Type": "AWS::WAFRegional::ByteMatchSet",
            "Properties": {
                "Name": "Path String Referers Set",
                "ByteMatchTuples": [
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": "../",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": "../",
                        "TextTransformation": "HTML_ENTITY_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TargetString": "../",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TargetString": "../",
                        "TextTransformation": "HTML_ENTITY_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": "://",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": "://",
                        "TextTransformation": "HTML_ENTITY_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TargetString": "://",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "QUERY_STRING"
                        },
                        "TargetString": "://",
                        "TextTransformation": "HTML_ENTITY_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    }
                ]
            }
        },
        "PathStringSetReferersRule": {
            "Type": "AWS::WAFRegional::Rule",
            "Properties": {
                "Name": "PathStringSetReferersRule",
                "MetricName": "PathStringSetReferersRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "PathStringSetReferers"
                        },
                        "Negated": false,
                        "Type": "ByteMatch"
                    }
                ]
            }
        },
        "BadReferers": {
            "Type": "AWS::WAFRegional::ByteMatchSet",
            "Properties": {
                "Name": "Bad Referers",
                "ByteMatchTuples": [
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "cookie"
                        },
                        "TargetString": "badrefer1",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "HEADER",
                            "Data": "authorization"
                        },
                        "TargetString": "QGdtYWlsLmNvbQ==",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "CONTAINS"
                    }
                ]
            }
        },
        "BadReferersRule": {
            "Type": "AWS::WAFRegional::Rule",
            "Properties": {
                "Name": "BadReferersRule",
                "MetricName": "BadReferersRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "BadReferers"
                        },
                        "Negated": false,
                        "Type": "ByteMatch"
                    }
                ]
            }
        },
        "ServerSideIncludesSet": {
            "Type": "AWS::WAFRegional::ByteMatchSet",
            "Properties": {
                "Name": "Server Side Includes Set",
                "ByteMatchTuples": [
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": "/includes",
                        "TextTransformation": "URL_DECODE",
                        "PositionalConstraint": "STARTS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".cfg",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".conf",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".config",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".ini",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".log",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".bak",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".bakup",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    },
                    {
                        "FieldToMatch": {
                            "Type": "URI"
                        },
                        "TargetString": ".txt",
                        "TextTransformation": "LOWERCASE",
                        "PositionalConstraint": "ENDS_WITH"
                    }
                ]
            }
        },
        "ServerSideIncludesRule": {
            "Type": "AWS::WAFRegional::Rule",
            "Properties": {
                "Name": "ServerSideIncludesRule",
                "MetricName": "ServerSideIncludesRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "ServerSideIncludesSet"
                        },
                        "Negated": false,
                        "Type": "ByteMatch"
                    }
                ]
            }
        },
        "WAFAutoBlockSet": {
            "Type": "AWS::WAFRegional::IPSet",
            "Properties": {
                "Name": "Auto Block Set"
            }
        },
        "MyAutoBlockRule": {
            "Type": "AWS::WAFRegional::Rule",
            "DependsOn": "WAFAutoBlockSet",
            "Properties": {
                "Name": "Auto Block Rule",
                "MetricName": "AutoBlockRule",
                "Predicates": [
                    {
                        "DataId": {
                            "Ref": "WAFAutoBlockSet"
                        },
                        "Negated": false,
                        "Type": "IPMatch"
                    }
                ]
            }
        },
        "MyWebACL": {
            "Type": "AWS::WAFRegional::WebACL",
            "Properties": {
                "Name": "MyWebACL",
                "DefaultAction": {
                    "Type": "ALLOW"
                },
                "MetricName": "MyWebACL",
                "Rules": [
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 1,
                        "RuleId": {
                            "Ref": "reqSizeRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "ALLOW"
                        },
                        "Priority": 2,
                        "RuleId": {
                            "Ref": "MyIPSetWhiteListRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 3,
                        "RuleId": {
                            "Ref": "myIPSetBlacklistRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 4,
                        "RuleId": {
                            "Ref": "MyAutoBlockRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 5,
                        "RuleId": {
                            "Ref": "wafrSQLiRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 6,
                        "RuleId": {
                            "Ref": "BadReferersRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 7,
                        "RuleId": {
                            "Ref": "PathStringSetReferersRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 8,
                        "RuleId": {
                            "Ref": "ServerSideIncludesRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 9,
                        "RuleId": {
                            "Ref": "XSSRule"
                        }
                    },
                    {
                        "Action": {
                            "Type": "BLOCK"
                        },
                        "Priority": 10,
                        "RuleId": {
                            "Ref": "MyScansProbesRule"
                        }
                    }
                ]
            }
        },
        "MyWebACLAssociation": {
            "Type": "AWS::WAFRegional::WebACLAssociation",
            "DependsOn": [
                "MyWebACL"
            ],
            "Properties": {
                "ResourceArn": {
                    "Ref": "ALBArn"
                },
                "WebACLId": {
                    "Ref": "MyWebACL"
                }
            }
        }
    }
}
STACK
}


