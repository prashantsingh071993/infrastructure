## Instructions to run script

* Clone repository
* Now navigate to script folder using command "cd infrastructure/aws/terraform/"
* To setup a terraform stack, install terraform binary and add to path
* Create a module using below command

     `terraform init`

* Add input variable parameters in terraform.tfvars file

    region= "us-east-1"
    cidr_block          = "10.0.0.0/16"
    subnet_cidr_block_1 = "10.0.1.0/24"
    subnet_cidr_block_2 = "10.0.2.0/24"
    subnet_cidr_block_3 = "10.0.3.0/24"
    vpcname             = "vpc-terraform"

* To create terraform network stack run below command

    `terraform apply`
    
* To delete terraform network stack run below command
 
    `terraform destroy`