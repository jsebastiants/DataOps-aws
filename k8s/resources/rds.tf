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