resource "aws_s3_bucket" "emr_codes_bucket" {
  bucket = "emr-code-zone-torres-etl-aws"
  force_destroy = true
}

resource "aws_s3_bucket" "athena-results" {
  bucket = "athena-results-torres-etl-aws"
  force_destroy = true
}

resource "aws_s3_object" "codes_object" {
  for_each = fileset("../codes/", "*")

  bucket = aws_s3_bucket.emr_codes_bucket.id
  key = each.key
  source = "../codes/${each.key}"
  force_destroy = true

  depends_on = [ aws_s3_bucket.emr_codes_bucket ]
}