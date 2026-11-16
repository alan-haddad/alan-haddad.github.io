# AWS security lab: a deliberately vulnerable web server, a Nessus scanner and
# an attack platform in one VPC, with web logs shipped to a private S3 bucket.
#
# Usage:
#   terraform init
#   terraform apply -var 'key_name=my-key-pair'
#   terraform destroy        # when you're done, so nothing vulnerable stays up

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

variable "region" {
  description = "AWS region to deploy the lab in."
  type        = string
  default     = "us-east-1"
}

variable "key_name" {
  description = "Name of an existing EC2 key pair used for SSH to all three instances."
  type        = string
}

variable "admin_cidr" {
  description = "CIDR allowed to reach SSH, the Nessus UI and the target's HTTP port. Leave null to use the public IP of the machine running Terraform."
  type        = string
  default     = null
}

variable "web_instance_type" {
  description = "Instance type for the target web server."
  type        = string
  default     = "t3.micro"
}

variable "nessus_instance_type" {
  description = "Instance type for the Nessus scanner. Nessus needs about 4 GB of memory."
  type        = string
  default     = "t3.medium"
}

variable "attack_instance_type" {
  description = "Instance type for the attack platform (Kali in Docker)."
  type        = string
  default     = "t3.small"
}

# ---------------------------------------------------------------------------
# Provider and lookups
# ---------------------------------------------------------------------------

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "security-lab"
      ManagedBy = "terraform"
    }
  }
}

# Public IP of whoever runs Terraform, used when admin_cidr is not set.
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com/"
}

# Latest Ubuntu 24.04 LTS image published by Canonical.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  admin_cidr = coalesce(var.admin_cidr, "${chomp(data.http.my_ip.response_body)}/32")
}

# Random suffix so the bucket name is unique per deployment.
resource "random_id" "bucket_id" {
  byte_length = 4
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "MainVPC"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "MainInternetGateway"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Log bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "log_bucket" {
  bucket = "cybersecurity-lab-logs-${random_id.bucket_id.hex}"

  # Lets `terraform destroy` remove the bucket even when it still holds logs.
  force_destroy = true

  tags = {
    Name = "CybersecurityLabLogs"
  }
}

# Bucket-owner-enforced ownership disables ACLs entirely; access is by policy only.
resource "aws_s3_bucket_ownership_controls" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Refuse any request that does not use TLS.
resource "aws_s3_bucket_policy" "log_bucket_tls_only" {
  bucket = aws_s3_bucket.log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.log_bucket.arn,
          "${aws_s3_bucket.log_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.log_bucket]
}

# ---------------------------------------------------------------------------
# IAM: the web server may write logs to the one bucket, and nothing else
# ---------------------------------------------------------------------------

resource "aws_iam_role" "web_server_role" {
  name = "WebServerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "s3_logging_policy" {
  name        = "S3LoggingPolicy"
  description = "Write-only log uploads to the lab log bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.log_bucket.arn}/*"
      },
      {
        # `aws s3 sync` lists the destination to decide what to upload.
        Sid      = "ListForSync"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.log_bucket.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.web_server_role.name
  policy_arn = aws_iam_policy.s3_logging_policy.arn
}

resource "aws_iam_instance_profile" "web_server_profile" {
  name = "WebServerInstanceProfile"
  role = aws_iam_role.web_server_role.name
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "nessus_sg" {
  name_prefix = "nessus-"
  description = "Nessus scanner: UI and SSH from the operator only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Nessus UI from the operator"
    from_port   = 8834
    to_port     = 8834
    protocol    = "tcp"
    cidr_blocks = [local.admin_cidr]
  }

  ingress {
    description = "SSH from the operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.admin_cidr]
  }

  egress {
    description = "Outbound for plugin updates and scanning"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "NessusSecurityGroup"
  }
}

resource "aws_security_group" "attack_sg" {
  name_prefix = "attack-"
  description = "Attack platform: SSH from the operator only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from the operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.admin_cidr]
  }

  egress {
    description = "Outbound for tooling and attacks on the target"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "AttackPlatformSG"
  }
}

# The target is deliberately vulnerable, so it is never open to the internet.
# Only the operator, the scanner and the attack platform can reach it.
resource "aws_security_group" "web_sg" {
  name_prefix = "web-"
  description = "Vulnerable target: reachable only by the operator and the lab"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from the operator"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.admin_cidr]
  }

  ingress {
    description = "HTTP from the operator"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [local.admin_cidr]
  }

  ingress {
    description     = "Any TCP port from the scanner and the attack platform"
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.nessus_sg.id, aws_security_group.attack_sg.id]
  }

  egress {
    description = "Outbound for package installs and log uploads"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "WebServerSG"
  }
}

# ---------------------------------------------------------------------------
# Instances
# ---------------------------------------------------------------------------

resource "aws_instance" "web_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.web_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = var.key_name
  iam_instance_profile   = aws_iam_instance_profile.web_server_profile.name
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # IMDSv2 only. A hop limit of 1 keeps role credentials away from anything
  # that reaches the metadata service through a forwarded or proxied request.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "WebServer"
  }
}

resource "aws_instance" "nessus_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.nessus_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.nessus_sg.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_size = 30 # Nessus plugins need more than the default 8 GB
  }

  tags = {
    Name = "NessusServer"
  }
}

# Ubuntu host; Kali runs on it in Docker.
resource "aws_instance" "attack_platform" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.attack_instance_type
  subnet_id              = aws_subnet.public.id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.attack_sg.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_size = 30 # room for the Kali image and tools
  }

  tags = {
    Name = "AttackPlatform"
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "admin_cidr" {
  description = "CIDR allowed to administer the lab."
  value       = local.admin_cidr
}

output "web_server_public_ip" {
  description = "Public IP of the target web server."
  value       = aws_instance.web_server.public_ip
}

output "web_server_private_ip" {
  description = "Private IP of the target, for scans and attacks from inside the VPC."
  value       = aws_instance.web_server.private_ip
}

output "nessus_url" {
  description = "Nessus UI."
  value       = "https://${aws_instance.nessus_server.public_ip}:8834"
}

output "attack_platform_public_ip" {
  description = "Public IP of the attack platform."
  value       = aws_instance.attack_platform.public_ip
}

output "log_bucket" {
  description = "Name of the S3 bucket that receives the web server logs."
  value       = aws_s3_bucket.log_bucket.bucket
}
