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

## Terraform Scripts
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
### cluster-redshift.tf
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
---
### eks.tf

In order to create a EKS (Elastic Kubernetes Service) in a simple manner, we are going to use a module. The main specs going to be two 16gb ram machines, one focused on memory and the other on processing.

```terraform
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "17.24.0"
  cluster_name    = var.cluster_name
  cluster_version = "1.21"
  subnets         = module.vpc.private_subnets

  tags = {
    Torres = "ETL-AWS"
  }

  vpc_id = module.vpc.vpc_id

  workers_group_defaults = {
    root_volume_type = "gp2"
  }

  worker_groups = [
    {
      name                          = "worker-group-1"
      instance_type                 = "r5.xlarge"
      asg_desired_capacity          = 1
      additional_security_group_ids = [aws_security_group.worker_group_mgmt_one.id]
    },
    {
      name                          = "worker-group-2"
      instance_type                 = "c5.2xlarge"
      additional_security_group_ids = [aws_security_group.worker_group_mgmt_two.id]
      asg_desired_capacity          = 1
    }
  ]
}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}
```
---
### emr-codes-bucket.tf

Basically here is creating a bucket that will store all our code and other dependency files of our spark job as pyfiles, and after this creation, it will upload these files.

```terraform
resource "aws_s3_bucket" "emr_codes_bucket" {
  bucket        = "emr-code-zone-torres-etl-aws"
  force_destroy = true
}

resource "aws_s3_bucket" "athena-results" {
  bucket        = "athena-results-torres-etl-aws"
  force_destroy = true
}

resource "aws_s3_bucket_object" "codes_object" {
  for_each = fileset("../codes/", "*")

  bucket        = aws_s3_bucket.emr_codes_bucket.id
  key           = each.key
  source        = "../codes/${each.key}"
  force_destroy = true

  depends_on = [aws_s3_bucket.emr_codes_bucket]
}
```
---
### glue-crawler.tf

Here we basically have the creation of a database and a crawler in glue to use in our pipeline, in addition to some policies and roles so we don't have problems with permission levels.

```terraform
resource "aws_glue_catalog_database" "aws_glue_catalog_database" {
  name = "torres-database-etl-aws"
}

resource "aws_iam_role" "glue_role" {
  name               = "glue_role"
  assume_role_policy = data.aws_iam_policy_document.glue-assume-role-policy.json
}

resource "aws_glue_crawler" "glue_crawler" {
  database_name = aws_glue_catalog_database.aws_glue_catalog_database.name
  name          = "crawlerETLawsTorres"
  role          = aws_iam_role.glue_role.arn

  s3_target {
    path = "s3://curated-zone-torres-etl-aws/curated/"
  }

  depends_on = [
    aws_glue_catalog_database.aws_glue_catalog_database,
    aws_iam_role.glue_role
  ]
}

data "aws_iam_policy_document" "glue-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["glue.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "extra-policy" {
  name   = "extra-policy"
  policy = data.aws_iam_policy_document.extra-policy-document.json

}

data "aws_iam_policy_document" "extra-policy-document" {
  statement {
    actions = [
    "s3:GetBucketLocation", "s3:ListBucket", "s3:ListAllMyBuckets", "s3:GetBucketAcl", "s3:GetObject"]
    resources = [
      "arn:aws:s3:::curated-zone-torres-etl-aws",
      "arn:aws:s3:::curated-zone-torres-etl-aws/*"
    ]
  }
}

resource "aws_iam_role_policy_attachment" "extra-policy-attachment" {
  role       = aws_iam_role.glue_role.name
  policy_arn = aws_iam_policy.extra-policy.arn
}

resource "aws_iam_role_policy_attachment" "glue-service-role-attachment" {
  role       = aws_iam_role.glue_role.name
  policy_arn = data.aws_iam_policy.AWSGlueServiceRole.arn
}

data "aws_iam_policy" "AWSGlueServiceRole" {
  arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

```
---
### lambda.tf

Here we’re basically creating a role and assuming a policy with permissions for all resources, in addition to our lambda function, with its characteristics. Bear in mind that actions allows us to perform a certain action. This can be read, list and so on. At this point we have already worked with those two forms `jsonencode` and heredoc `syntax`.

```terraform
resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": [
          "lambda.amazonaws.com"
        ]
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "policy" {
  name = "iam_for_lambda_policy"

  policy = <<-EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "policy-attach" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_lambda_function" "lambda_function" {
  function_name = "myfunction"
  filename      = "lambda_function.zip"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "lambda_function.lambda_handler"
  memory_size   = 1000
  timeout       = 120

  source_code_hash = filebase64sha256("lambda_function.zip")

  runtime = "python3.9"

}
```
---
### lambda_function.py

The lambda function make request for a web link. Then uploads it to a bucket and unzips the files in the bucket itself.

```python
import requests, io, tempfile, os, boto3
from zipfile import ZipFile

file_name = 'AdventureWorks.zip'
bucket = "landing-zone-torres-etl-aws"
folder_temp_name = 'temp'
url = 'https://github.com/camposvinicius/data/raw/main/AdventureWorks.zip'

def lambda_handler(event, context):
    
    with tempfile.TemporaryDirectory() as temp_path:
        temp_dir = os.path.join(temp_path, folder_temp_name)
        with open(temp_dir, 'wb') as f:
            req = requests.get(url)
            f.write(req.content)
        s3 = boto3.resource('s3')
        s3.Bucket(bucket).upload_file(temp_dir, file_name)
    
        zip_obj = s3.Object(bucket_name=bucket, key=file_name)
        buffer = io.BytesIO(zip_obj.get()["Body"].read())
        
        z = ZipFile(buffer)
        for filename in z.namelist():
            file_info = z.getinfo(filename)
            s3.meta.client.upload_fileobj(
                z.open(filename),
                Bucket=bucket,
                Key='data/' + f'{filename}')
    for file in s3.Bucket(bucket).objects.all():
        print(file.key)
```
---
### requirement.txt

This is an external library that we have as a dependency of our function to pack it. That is one of the ways to do it, afterwards you can see the other way using a `values.yml` because, as you can notice, in the lambda file above we are not only using request but other libraries like boto3 for example.

```txt
requests>=2.26.0
```
---
### build_lambda_package.sh
We have a shell script that, basically, at runtime of our CI/CD, installs the libraries placed in the requirements.txt file in a temporary folder along with our lambda function and then zips them.

```sh
#!/usr/bin/env bash 

cd k8s/resources

# Declare variable for reuse in directory validations
PACKAGE="package"

# Create directory and install lambda function dependencies
if [ -d $PACKAGE ]
then
	echo "The directory "$PACKAGE" already exists."
else
	echo "============================================="
	echo "Creating the directory "$PACKAGE"..."
	mkdir $PACKAGE
	echo "The directory "$PACKAGE" was created."
	echo "============================================="
fi

# Declares the variable that locates the requirements with the project's dependencies.
FILE_REQUIREMENTS=../scripts/requirements.txt

# Checks if the lambda_requirements file exists
if [ -f $FILE_REQUIREMENTS ]
then
	echo "============================================="
	echo "Installing dependencies located in "$FILE_REQUIREMENTS""
	pip install --target ./package -r $FILE_REQUIREMENTS
	echo "Dependencies installed successfully."
	echo "============================================="	
fi


cd $PACKAGE

# Declares variable that locates the lambda function for reuse in code.
LAMBDA_FUNCTION=../../lambda-function/lambda_function.py

# Checks if the lambda_function.py file exists.
if [ -f $LAMBDA_FUNCTION ]
then
	echo "============================================="
	echo "Copying Handler function..."
	cp $LAMBDA_FUNCTION .
	echo "Compressing file lambda_function.zip"
	zip -r9 ../lambda_function.zip . # Compress the package for deployment
	echo "File zipped successfully!"
	echo "============================================="
fi

cd ..

```
---
### provider.tf

When we work with eks for example, if we want to have different users and manage them in our cluster, we should keep in mind that once the cluster is created, the user who creates it is the administrator and is he only one with access. If we want to include other users we must do this:
```terraform
data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}
```
And then we have to indicate the provider.
```terraform
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}
```
Basically, here are the providers needed to work when creating the cluster.

```terraform
provider "aws" {
  region = var.region
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

provider "kubectl" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
}
```
---