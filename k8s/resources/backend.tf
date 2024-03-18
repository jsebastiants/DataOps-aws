terraform {
    backend "s3" {
        bucket = "tfstate-torres-etl-aws"
        key = "terraform/tfstate"
        region = "us-east-1"
    }
}
