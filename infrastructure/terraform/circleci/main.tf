

resource "aws_iam_policy" "policy1" {
  name        = "CircleCI-Code-Deploy"
  description = "Code Deploy Policy for user circleci"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.accountId}:application:${var.codeDeployApplicationName}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.accountId}:deploymentgroup:${var.codeDeployApplicationName}/${var.codeDeployApplicationGroup}" 
      ]
    },
    {
      "Effect": "Allow",  
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.accountId}:deploymentconfig:${var.codeDeployApplicationGroup}",
        "arn:aws:codedeploy:${var.region}:${var.accountId}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${var.accountId}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${var.accountId}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}


resource "aws_iam_policy_attachment" "circleci-attach1" {
  name  = "circleci-attachment-codedeploy"
  users = ["${var.aws_circleci_user_name}"]
  #roles      = ["${aws_iam_role.role.name}"]
  #groups     = ["${aws_iam_group.group.name}"]
  policy_arn = "${aws_iam_policy.policy1.arn}"
  depends_on = ["aws_iam_policy.policy1"]
}


