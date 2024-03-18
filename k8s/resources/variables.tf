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