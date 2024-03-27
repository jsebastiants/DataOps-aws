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
### rds.tf

For this part we will also create a security group with general entry permission for any type of protocol just for case study, we will use a default VPC and create the instance. Having said that, if you want to use this resource you must keep in mind that there are important argument when you are in the deployment stage. To mention a bunch of arguments, we have Blue/Green deployments for database updates, deletion_protection, skip_final_snapshot(we are considering this argument just for case study), etc.
``` terraform
resource "aws_db_instance" "torrespostgresql-instance" {
  identifier             = "torrespostgresql-instance"
  db_name                = "torrespostgresql"
  instance_class         = "db.t2.micro"
  allocated_storage      = 5
  engine                 = "postgres"
  engine_version         = "12.7"
  skip_final_snapshot    = true
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.torrespostgresql.id]
  username               = var.postgres_user
  password               = var.postgres_user

  tags = {
    tag-key = "torres-cluster-postgres-etl-aws"
  }
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "torrespostgresql" {
  vpc_id = data.aws_vpc.default.id
  name   = "torrespostgresql"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    tag-key = "sg-postgres"
  }
}
```
---
### security_groups.tf
Here we are basically creating security groups for our workers from our EKS cluster with internal access via TCP protocol on port 22 and using our VPC ID that we will see shortly.

```terraform
resource "aws_security_group" "worker_group_mgmt_one" {
  name_prefix = "worker_group_mgmt_one"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
    ]
  }
}

resource "aws_security_group" "worker_group_mgmt_two" {
  name_prefix = "worker_group_mgmt_two"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "192.168.0.0/16",
    ]
  }
}

resource "aws_security_group" "all_worker_mgmt" {
  name_prefix = "all_worker_management"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }
}
```
---
### notification_service.tf

Then we are going to create a topic on the SNS and a subscription via email for use.
``` terraform
resource "aws_sns_topic" "mysns" {
  name = "send-email"
}

resource "aws_sns_topic_subscription" "send-email" {
  topic_arn = aws_sns_topic.mysns.arn
  protocol  = "email"
  endpoint  = var.email

  depends_on = [
    aws_sns_topic.mysns
  ]
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Publish"
    ]

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.mysns.arn,
    ]

    sid = "__default_statement_ID"
  }
}
```
---
### variables.tf
Here are the variables being used in our code.

``` terraform
variable "region" {
  default = "us-east-1"
}

variable "cluster_name" {
  default = "torres-cluster-eks"
}

variable "redshift_user" {
  default = "your-redshift-user"
}

variable "redshift_pass" {
  default = "your-redshift-password"
}

variable "redshift_db" {
  default = "elttorres"
}

variable "postgres_user" {
  default = "your-postgres-user"
}

variable "postgres_pass" {
  default = "your-postgres-password"
}

variable "email" {
  default = "your-email"
}
```
---
### versions.tf
The necessary versions of the modules that we will use for our code.

```terraform
terraform {

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.73.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "3.1.0"
    }

    local = {
      source  = "hashicorp/local"
      version = "2.1.0"
    }

    null = {
      source  = "hashicorp/null"
      version = "3.1.0"
    }

    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.7.0"
    }

  }

  required_version = ">= 0.14"
}
```
---
### vpc.tf
Here we are creating a VPC module that we will use for the operation of our EKS cluster. When we work with eks what we are looking for is that our cluster is located in a private subnet. This will allow your nodes not to be exposed to the internet, it is a very good practice. In production is more suitable have the `single_nat_gateway = False` this is because we expect have one nat_gateway per subnet.

```terraform
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.2.0"

  name                 = "eks-vpc"
  cidr                 = "10.0.0.0/16"
  azs                  = ["${var.region}a", "${var.region}b"]
  private_subnets      = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = "1"
  }
}
```
---
### output.tf

Here we are just seeing in the log after creation some resources like the cluster ID, its name, endpoint and AWS region.
``` terraform 
output "cluster_id" {
  description = "EKS cluster ID."
  value       = module.eks.cluster_id
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane."
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane."
  value       = module.eks.cluster_security_group_id
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = var.cluster_name
}
```
---
### apps.tf
In order to be clear, first the `argocd` and `airflow` namespaces are created. Afterwards, the installation file is applied to the `argocd` namespace.
- After argocd is deployed, it will authenticate to the private repository, which I will explain how you will make it work.
- Afterwards, a secret will be created in the airflow namespace that will give access to the private repository, which I will also explain how you will make it work.
- Afterwards, the airflow will be deployed in the airflow namespace, automatically.
- And finally, you will pass your credentials that you will use in the values.yaml of your chart, which I will also show.

This is the first step:

``` yml
apiVersion: v1
kind: Namespace
metadata:
  name: argocd

---

apiVersion: v1
kind: Namespace
metadata:
  name: airflow
```
Behind the scenes, this provider uses the same capability as the kubectl apply command, that is, you can update the YAML inline and the resource will be updated in place in kubernetes. 

- TIP: This resource only supports a single yaml resource. If you have a list of documents in your yaml file, use the `kubectl_path_documents` or `kubectl_file_documents` data source to split the files into individual resources.
``` terraform
data "kubectl_file_documents" "namespace" {
  content = file("../charts/argocd/namespace.yaml")
}
resource "kubectl_manifest" "namespace" {
  count              = length(data.kubectl_file_documents.namespace.documents)
  yaml_body          = element(data.kubectl_file_documents.namespace.documents, count.index)
  override_namespace = "argocd"
  depends_on = [
    data.kubectl_file_documents.namespace,
    module.eks
  ]
}

data "kubectl_file_documents" "argocd" {
  content = file("../charts/argocd/install.yaml")
}

resource "kubectl_manifest" "argocd" {
  count              = length(data.kubectl_file_documents.argocd.documents)
  yaml_body          = element(data.kubectl_file_documents.argocd.documents, count.index)
  override_namespace = "argocd"
  depends_on = [
    kubectl_manifest.namespace,
    data.kubectl_file_documents.argocd,
    module.eks
  ]
}

data "kubectl_file_documents" "git" {
  content = file("../charts/argocd/auth.yaml")
}

resource "kubectl_manifest" "git" {
  count              = length(data.kubectl_file_documents.git.documents)
  yaml_body          = element(data.kubectl_file_documents.git.documents, count.index)
  override_namespace = "argocd"
  depends_on = [
    kubectl_manifest.argocd,
    data.kubectl_file_documents.git
  ]
}

data "kubectl_file_documents" "airflow_key" {
  content = file("../airflow_access_git_repo/ssh.yaml")
}

resource "kubectl_manifest" "airflow_manifest" {
  count              = length(data.kubectl_file_documents.airflow_key.documents)
  yaml_body          = element(data.kubectl_file_documents.airflow_key.documents, count.index)
  override_namespace = "airflow"
  depends_on = [
    kubectl_manifest.argocd,
    data.kubectl_file_documents.airflow_key
  ]
}

data "kubectl_file_documents" "airflow" {
  content = file("../apps/airflow-app.yaml")
}

resource "kubectl_manifest" "airflow" {
  count              = length(data.kubectl_file_documents.airflow.documents)
  yaml_body          = element(data.kubectl_file_documents.airflow.documents, count.index)
  override_namespace = "argocd"
  depends_on = [
    kubectl_manifest.argocd,
    data.kubectl_file_documents.airflow,
    module.eks
  ]
}

data "kubectl_file_documents" "keys" {
  content = file("../secrets/keys.yml")
}

resource "kubectl_manifest" "keys" {
  count              = length(data.kubectl_file_documents.keys.documents)
  yaml_body          = element(data.kubectl_file_documents.keys.documents, count.index)
  override_namespace = "airflow"
  depends_on = [
    data.kubectl_file_documents.keys,
    data.kubectl_file_documents.airflow,
    kubectl_manifest.argocd,
    kubectl_manifest.airflow
  ]
}
```
---
## Explaining About Secrets !!
### ARGOCD
### namespace.yaml
Here's basically the first thing EKS will do when it's created, here you don't have to worry.
```yml
apiVersion: v1
kind: Namespace
metadata:
  name: argocd

---

apiVersion: v1
kind: Namespace
metadata:
  name: airflow
```
---
### install.yaml
Here you also don't have to worry, because this installation yaml will be applied automatically, you don't need to configure anything at all.
```yaml

BIG FILE

```
---

### auth.yaml
Here you need to pay attention only to change the settings below.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: private-bgd-repo
  namespace: argocd-repo
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: https://github.com/your/private-repo.git
  password: your-github-token
  username: your-username
```
---
### AIRFLOW

### ssh.yaml
Here you need to pay attention only to change the settings below.

```yaml

apiVersion: v1
kind: Secret
metadata:
    name: airflow-http-git-secret
    namespace: airflow
type: Opaque
data:
  username: your-username-with-base64 # you can use => echo -n "username" | base64
stringData:
  password: your-github-token

```
---
### airflow-app.yaml
Here you need to pay attention only to change the settings below.

```yaml

apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: airflow
  namespace: argocd 
  finalizers:
    - resources-finalizer.argocd.argoproj.io  #Argo CD application controller will perform a cascading delete of the Application's resources.
spec:
  project: default
  source:
    repoURL: https://github.com/your/private-repo.git
    targetRevision: main
    path: k8s/charts/airflow
  destination:
    server: https://kubernetes.default.svc
    namespace: airflow
  syncPolicy:
    automated:
      selfHeal: true
    syncOptions:
    - CreateNamespace=false

```
---
### keys.yaml

If you want to follow exactly the pipeline of this repository, follow below.

```yaml

# REMEMBER echo -n "something" | base64

apiVersion: v1
kind: Secret
metadata:
    name: aws-credentials
    namespace: airflow
type: Opaque
data:
  aws_access_key_id: your-aws_access_key_id-base64
  aws_secret_access_key: your-aws_secret_access_key-base64

---

apiVersion: v1
kind: Secret
metadata:
    name: postgres-credentials
    namespace: airflow
type: Opaque
data:
  postgres_password: your-postgres_password-base64

---

apiVersion: v1
kind: Secret
metadata:
    name: redshift-credentials
    namespace: airflow
type: Opaque
data:
  redshift_password: your-redshift_password-base64

---

apiVersion: v1
kind: Secret
metadata:
    name: token-credential
    namespace: airflow
type: Opaque
data:
  token: your-github-token-base64

```
---
## Pyspark Scripts
Now that our resource creation codes are over, let's understand what our pyspark codes do.

Our first script, `csv-to-parquet.py`, has a main class called _CSVtoPARQUET_ that takes some parameters like the spark object, the path source and target and the format source and target, with a run method that calls two other methods , __create_logger__, which instances the application log and __csv_to_parquet__, which reads the csv, caches it to memory and writes to another bucket as parquet.

Our second script, `transformation.py`, has a class called _ServeData_ that takes no parameter and instantiates the method run that calls two methods, the __create_logger__, just to run the application log and the other called __to_curated__, which basically creates views of the parquets saved in the last application, runs a sql query with a join between them, iterates in an empty list that was appended with the name of these views at the beginning of the application to drop and writes in parquet in a new bucket.

And finally we have the `variables.py` file, with our paths, view list and our query.

### csv-to-parquet.py

``` python
import logging
import sys
import ast

import pyspark.sql.functions as f

from pyspark.sql import SparkSession
from variables import PATH_SOURCE, PATH_TARGET

class CSVtoPARQUET:
    def __init__(self, spark, path_source:str, format_source: str, path_target:str, format_target: str) -> None:
        self.spark = spark

        if format_source != 'csv':
            raise Exception(f"The format_source {format_source} is not supported. Use CSV.")
        elif format_target != 'parquet':
            raise Exception(f"The format_target {format_target} is not supported. Use PARQUET.")
        else:
            self.format_source = format_source
            self.format_target = format_target
        
        self.path_source = path_source
        self.path_target = path_target
    
    def run(self) -> str:
        self.create_logger()
        self.csv_to_parquet()

        return "Application completed. Going out..."

    def create_logger(self):
        logging.basicConfig(format='%(name)s - %(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p', stream=sys.stdout)
        logger = logging.getLogger('ETL_AWS_VINICIUS_CAMPOS')
        logger.setLevel(logging.DEBUG)

    def csv_to_parquet(self):
        df = (
            self.spark.read.format(self.format_source)
            .option("sep", ",")
            .option("header", True)
            .option("encoding", "utf-8")
            .load(self.path_source)
        )

        df.cache()

        return df.coalesce(1).write.mode("overwrite").format(self.format_target).save(self.path_target)

if __name__ == "__main__":

    spark = (
        SparkSession.builder.appName('ETL_AWS_VINICIUS_CAMPOS')
        .enableHiveSupport()
        .config('spark.hadoop.mapreduce.fileoutputcommitter.algorithm.version', '2')
        .config('spark.speculation', 'false')
        .config('spark.sql.adaptive.enabled', 'true')
        .config('spark.shuffle.service.enabled', 'true')
        .config('spark.dynamicAllocation.enabled', 'true')
        .config('spark.sql.adaptive.coalescePartitions.enabled', 'true')
        .config('spark.sql.adaptive.coalescePartitions.minPartitionNum', '1')
        .config('spark.sql.adaptive.coalescePartitions.initialPartitionNum', '10')
        .config('spark.sql.adaptive.advisoryPartitionSizeInBytes', '134217728')
        .config('spark.serializer', 'org.apache.spark.serializer.KryoSerializer')
        .config('spark.dynamicAllocation.minExecutors', "5")
        .config('spark.dynamicAllocation.maxExecutors', "30")
        .config('spark.dynamicAllocation.initialExecutors', "10")
        .config('spark.sql.debug.maxToStringFields', '300')
        .config('spark.sql.join.preferSortMergeJoin', 'true')
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    script_input = ast.literal_eval(sys.argv[1])
    
    file = script_input['file']
    format_source = script_input['format_source']
    format_target = script_input['format_target']

    m = CSVtoPARQUET(
        spark, 
        PATH_SOURCE.format(file=file), 
        format_source,
        PATH_TARGET.format(file=file),
        format_target
    )

    m.run()

    spark.stop()
```
---
### transformation.py
``` python
import logging
import sys

from pyspark.sql import SparkSession
from variables import PATH_TARGET, PATH_CURATED, QUERY, VIEWS

class ServeData:
    def __init__(self, spark) -> None:
        self.spark = spark
        self.path_target = PATH_TARGET
        self.path_curated = PATH_CURATED
        self.query = QUERY
    
    def run(self) -> str:
        self.create_logger()
        self.to_curated()

        return "Application completed. Going out..."

    def create_logger(self):
        logging.basicConfig(format='%(name)s - %(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p', stream=sys.stdout)
        logger = logging.getLogger('ETL_AWS_VINICIUS_CAMPOS')
        logger.setLevel(logging.DEBUG)

    def to_curated(self):

        views_to_drop = []

        for view in VIEWS:
            print(view)
            (
                spark.read.format("parquet")
                .load(f'{self.path_target}'.format(file=view))
                .createOrReplaceTempView(f'{view}')
            )
            views_to_drop.append(view)

        print(views_to_drop)
        
        df = spark.sql(self.query['QUERY'])

        for view in views_to_drop:
            spark.catalog.dropTempView(f"{view}")

        df.cache()

        (
            df.coalesce(1)
            .write.format("parquet")
            .mode("overwrite")
            .save(self.path_curated)
        )

if __name__ == "__main__":

    spark = (
        SparkSession.builder.appName('ETL_AWS_VINICIUS_CAMPOS')
        .enableHiveSupport()
        .config('spark.hadoop.mapreduce.fileoutputcommitter.algorithm.version', '2')
        .config('spark.speculation', 'false')
        .config('spark.sql.adaptive.enabled', 'true')
        .config('spark.shuffle.service.enabled', 'true')
        .config('spark.dynamicAllocation.enabled', 'true')
        .config('spark.sql.adaptive.coalescePartitions.enabled', 'true')
        .config('spark.sql.adaptive.coalescePartitions.minPartitionNum', '1')
        .config('spark.sql.adaptive.coalescePartitions.initialPartitionNum', '10')
        .config('spark.sql.adaptive.advisoryPartitionSizeInBytes', '134217728')
        .config('spark.serializer', 'org.apache.spark.serializer.KryoSerializer')
        .config('spark.dynamicAllocation.minExecutors', "5")
        .config('spark.dynamicAllocation.maxExecutors', "30")
        .config('spark.dynamicAllocation.initialExecutors', "10")
        .config('spark.sql.debug.maxToStringFields', '300')
        .config('spark.sql.join.preferSortMergeJoin', 'true')
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    m = ServeData(spark)

    m.run()

    spark.stop()
```
---
### variables.py

``` python 
PATH_SOURCE = 's3://landing-zone-vini-poc-etl-aws/data/AdventureWorks/{file}.csv'
PATH_TARGET = 's3://processing-zone-vini-poc-etl-aws/processing/AdventureWorks_AdventureWorks_{file}'
PATH_CURATED = 's3://curated-zone-vini-poc-etl-aws/curated/'

VIEWS = [
  'Customers',
  'Product_Categories',
  'Product_Subcategories',
  'Products',
  'Returns',
  'Sales_2015',
  'Sales_2016',
  'Sales_2017'
]

QUERY = {
    
'QUERY': """ 
    WITH all_sales (
        SELECT * FROM Sales_2015
        UNION ALL
        SELECT * FROM Sales_2016
        UNION ALL
        SELECT * FROM Sales_2017
    ), info as (
    SELECT
        cast(from_unixtime(unix_timestamp(a.OrderDate, 'M/d/yyyy'), 'yyyy-MM-dd') as date) as OrderDate,
        cast(from_unixtime(unix_timestamp(a.StockDate, 'M/d/yyyy'), 'yyyy-MM-dd') as date) as StockDate,
        cast(a.CustomerKey as int) as CustomerKey,
        cast(a.TerritoryKey as int) as TerritoryKey,
        cast(a.OrderLineItem as int) as OrderLineItem,
        cast(a.OrderQuantity as int) as OrderQuantity,
        b.Prefix,
        b.FirstName,
        b.LastName,
        cast(from_unixtime(unix_timestamp(b.BirthDate, 'M/d/yyyy'), 'yyyy-MM-dd') as date) as BirthDate,
        b.MaritalStatus,
        b.Gender,
        b.EmailAddress,
        cast(replace(replace(b.AnnualIncome, "$", ""), ",", "") as decimal(10,2)) as AnnualIncome,
        cast(b.TotalChildren as int) as TotalChildren,
        b.EducationLevel,
        b.Occupation,
        b.HomeOwner,
        cast(c.ProductKey as int) as ProductKey,
        cast(d.ProductSubcategoryKey as int) as ProductSubcategoryKey,
        d.SubcategoryName,
        cast(d.ProductCategoryKey as int) as ProductCategoryKey,
        e.CategoryName,
        c.ProductSKU,
        c.ProductName,
        c.ModelName,
        c.ProductDescription,
        c.ProductColor,
        cast(c.ProductSize as int) as ProductSize,
        c.ProductStyle,
        cast(c.ProductCost as decimal(10,2)) as ProductCost ,
        cast(c.ProductPrice as decimal(10,2)) as ProductPrice,
        cast(from_unixtime(unix_timestamp(f.ReturnDate, 'M/d/yyyy'), 'yyyy-MM-dd') as date) as ReturnDate,
        NVL(cast(f.ReturnQuantity as int),0) as ReturnQuantity
    FROM
        all_sales a
    LEFT JOIN
        Customers b
    ON
        a.CustomerKey = b.CustomerKey
    LEFT JOIN
        Products c
    ON
        a.ProductKey = c.ProductKey
    LEFT JOIN
        Product_Subcategories d
    ON
        c.ProductSubcategoryKey = d.ProductSubcategoryKey
    LEFT JOIN
        Product_Categories e
    ON
        d.ProductCategoryKey = e.ProductCategoryKey
    LEFT JOIN
        Returns f
    ON
        a.TerritoryKey = f.TerritoryKey AND
        c.ProductKey = f.ProductKey
    )
    SELECT
        *
    FROM
        info
"""
}
```
---
## Charts Scripts
### airflow-values
Remember to change your host, schema and login in values. For this section we are going to split each step, in order, so that you can follow it and set your values.

``` yaml
  users:
    - username: admin
      password: admin
      role: Admin
      email: admin@example.com
      firstName: Sebastian
      lastName: Torres
```
If you want more information about connections config check this link [Manage Airflow Connections](https://github.com/airflow-helm/charts/blob/main/charts/airflow/docs/faq/dags/airflow-connections.md)

``` yaml
  connections: 
  - id: aws
    type: aws
    description: AWS CONN
    extra: |-
      { 
        "aws_access_key_id": "${AWS_ACCESS_KEY_ID}",
        "aws_secret_access_key": "${AWS_SECRET_ACCESS_KEY}",
        "region_name":"us-east-1" 
      }
    
  - id: emr
    type: emr
    description: EMR CONN
    login: "${AWS_ACCESS_KEY_ID}"
    password: "${AWS_SECRET_ACCESS_KEY}"

  - id: redshift
    type: redshift
    description: REDSHIFT CONN
    host: redshift-cluster-etl-torres.cpmardrhdluz.us-east-1.redshift.amazonaws.com
    schema: etlvini
    login: vini
    password: "${REDSHIFT_PASSWORD}"
    port: 5439

  - id: postgres
    type: postgres
    description: POSTGRES CONN
    host: torrespostgresql-instance.cngltutuixt3.us-east-1.rds.amazonaws.com
    schema: torrespostgresql
    login: torresetlaws
    password: "${POSTGRES_PASSWORD}"
    port: 5432

```

The following values will create a `"aws, emr, redshift, postgres"` type connection called `aws, emr, redshift, postgres` using a token stored in `secrets/keys.yaml`:

```yaml
  connectionsTemplates:

    AWS_ACCESS_KEY_ID:
      kind: secret
      name: aws-credentials
      key: aws_access_key_id

    AWS_SECRET_ACCESS_KEY:
      kind: secret
      name: aws-credentials
      key: aws_secret_access_key

    POSTGRES_PASSWORD:
      kind: secret
      name: postgres-credentials
      key: postgres_password

    REDSHIFT_PASSWORD:
      kind: secret
      name: redshift-credentials
      key: redshift_password
```

You may use the `airflow.variables` value to create airflow [Variables](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/variables.html) in a declarative way. There you can find detailed documentation about each one of the core concepts of Apache Airflow™ and how to use them, as well as a high-level [architectural overview](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/overview.html).

```yaml
  variables:

    - key: "AWS_ACCESS_KEY_ID"
      value: "${AWS_ACCESS_KEY_ID}"

    - key: "AWS_SECRET_ACCESS_KEY"
      value: "${AWS_SECRET_ACCESS_KEY}"

    - key: "POSTGRES_PASSWORD"
      value: "${POSTGRES_PASSWORD}"

    - key: "GITHUB_TOKEN"
      value: "${GITHUB_TOKEN}"
```

You may use `airflow.variablesTemplates` to extract string templates from keys in Secrets or Configmaps.

For example, to use templates from `secrets/keys.yaml` and `ConfigMap/my-configmap` in the variables:

```yaml
  variables:

    - key: "AWS_ACCESS_KEY_ID"
      value: "${AWS_ACCESS_KEY_ID}"

    - key: "AWS_SECRET_ACCESS_KEY"
      value: "${AWS_SECRET_ACCESS_KEY}"

    - key: "POSTGRES_PASSWORD"
      value: "${POSTGRES_PASSWORD}"

    - key: "GITHUB_TOKEN"
      value: "${GITHUB_TOKEN}"

  variablesTemplates: 

    AWS_ACCESS_KEY_ID:
      kind: secret
      name: aws-credentials
      key: aws_access_key_id

    AWS_SECRET_ACCESS_KEY:
      kind: secret
      name: aws-credentials
      key: aws_secret_access_key

    POSTGRES_PASSWORD:
      kind: secret
      name: postgres-credentials
      key: postgres_password

    GITHUB_TOKEN:
      kind: secret
      name: token-credential
      key: token
```

We were talking about different ways to use libraries in this project. One of them is the requirements.txt, the other one is this one.

```yaml
  extraPipPackages: 
    - "apache-airflow-providers-amazon>=2.5.0"
    - "apache-airflow-providers-postgres"
    - "sqlalchemy"
    - "boto3"
    - "pandas"
    - "pygithub"
```

I recommend check the entire [file](https://github.com/jsebastiants/DataOps-aws/blob/main/k8s/charts/airflow/values.yaml)

**Remember to create before and connect to your kubernetes cluster before doing the commands below!**

```sh

$ aws emr create-default-roles

$ aws eks --region us-east-1 update-kubeconfig --name your-cluster-name

```
Let's do a port-forward to access our argocd.

```sh
$ kubectl port-forward svc/argocd-server -n argocd 8181:443
```

By going to `localhost:8181`, you will find this splash screen. With this command you can get your password and login with the username `admin`.

```sh
$ kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

![argocd](https://github.com/jsebastiants/DataOps-aws/assets/49937878/d9c5bcf3-7d36-4c52-ac98-6a7b6505b502)
