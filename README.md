# DataOps-aws
The purpose of this project is develop an ETL application on AWS using DataOps knowledge. DataOps, short for Data Operations, is an approach that emphasizes collaboration and communication between data engineers, data scientist, and other data-related proffesionals. The goal of DataOps is to improve the overall efficiency and effectiveness of data-related processes throughout the entire data lifecycle.

## The advantages of DataOps:

1. **Collaboration:**
    - Cross-functional Teams
    - Communication
2. **Agile Methodologies:**
3. **Automation:**
    - Workflow Automation:
    - Infrastructure as Code (IaC)
4. **Version Control:**
5. **Monitoring and Logging:**
    - Operational Monitoring
    - Alerts and Notifications
6. **DevOps Practices:**
    - Infrastructure as Code (IaC)
    - Continuous Integration/Continuous Deployment (CI/CD)
7. **Quality and Testing:**
    - Data Quality Management
    - Automated Testing

## List of tools we'll be using

### CI/CD (Github Workflow)

- `verify.yml` for testing and validation of resource construction
- `deploy.yml` for building resources
- `destroy.yml` for resource destruction

### GitOps

- ArgoCD

### **Resource Construction**

- Terraform

---

### AWS Tools

- Lambda Function
- RDS
- Redshift
- Athena
- S3
- EMR
- Glue Crawler
- Glue Database
- Policy
- Roles
- EKS
- VPC
- SNS
- Security Groups

---

### **Pipeline Orchestration**

- Airflow (*Helm Chart used:* https://artifacthub.io/packages/helm/airflow-helm/airflow)

---

### Terraform Scripts
Backend.tf is created to store the state of our infrastructure in our bucket.

```terraform
terraform {
  backend "s3" {
    bucket = "tfstate-torres-etl-aws"
    key    = "terraform/tfstate"
    region = "us-east-1"
  }
}
```
---
Since we are going to be ingesting data in redshift, there is a bunch of different things we need to create. Here we are basically creating a VPC, a getaway, a security group and so forth. Before we get too far, it is important to mention that there is different ways to define IAM policies, ther first one is using heredoc syntax `(<<EOF ... EOF)` and the second one is with `jsonencode`. The problem with both approaches: If your policy is malformed, you have to terraform apply before you realize the mistake. Besides that, your IDE’s auto-complete can not help you much when using those approaches. Having said that, you can overlook the `(<<EOF ... EOF)` and prefer the data source `aws_iam_policy_document` instead. This way, Terraform can validate your IAM policy (at least from a structural perspective), and your IDE can do a much better job of increasing your productivity.

```terraform
resource "aws_vpc" "redshift_vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "redshift-vpc"
  }
}

resource "aws_internet_gateway" "redshift_vpc_gw" {
  vpc_id = aws_vpc.redshift_vpc.id

  depends_on = [
    aws_vpc.redshift_vpc
  ]
}

resource "aws_default_security_group" "redshift_security_group" {
  vpc_id = aws_vpc.redshift_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "redshift-sg"
  }

  depends_on = [
    aws_vpc.redshift_vpc
  ]
}

resource "aws_subnet" "redshift_subnet_1" {
  vpc_id                  = aws_vpc.redshift_vpc.id
  cidr_block              = "10.0.1.0/28"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = "true"

  tags = {
    Name = "redshift-subnet-1"
  }

  depends_on = [
    aws_vpc.redshift_vpc
  ]
}

resource "aws_subnet" "redshift_subnet_2" {
  vpc_id                  = aws_vpc.redshift_vpc.id
  cidr_block              = "10.0.32.0/20"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = "true"

  tags = {
    Name = "redshift-subnet-2"
  }

  depends_on = [
    aws_vpc.redshift_vpc
  ]
}

resource "aws_redshift_subnet_group" "redshift_subnet_group" {
  name = "redshift-subnet-group"

  subnet_ids = [
    aws_subnet.redshift_subnet_1.id,
    aws_subnet.redshift_subnet_2.id
  ]

  tags = {
    environment = "torres-etl-aws"
    Name        = "redshift-subnet-group"
  }
}


resource "aws_iam_role_policy" "s3_full_access_policy" {
  name = "redshift_s3_policy"

  role   = aws_iam_role.redshift_role.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}
  EOF
}

resource "aws_iam_role" "redshift_role" {
  name               = "redshift_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "redshift.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
  EOF

  tags = {
    tag-key = "redshift-role"
  }
}

resource "aws_redshift_cluster" "default" {
  cluster_identifier  = "redshift-cluster-etl-torres"
  database_name       = var.redshift_db
  master_username     = var.redshift_user
  master_password     = var.redshift_pass
  node_type           = "dc2.large"
  cluster_type        = "single-node"
  skip_final_snapshot = true
  publicly_accessible = true
  iam_roles           = ["${aws_iam_role.redshift_role.arn}"]

  tags = {
    tag-key = "torres-cluster-redshift-etl-aws"
  }

  depends_on = [
    aws_vpc.redshift_vpc,
    aws_default_security_group.redshift_security_group,
    aws_redshift_subnet_group.redshift_subnet_group,
    aws_iam_role.redshift_role
  ]
}

```

