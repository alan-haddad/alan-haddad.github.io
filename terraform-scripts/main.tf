# Define the AWS Provider
provider "aws" {
  region = "us-east-1" # Specify your region
}

# Random ID for unique resource names
resource "random_id" "bucket_id" {
  byte_length = 4
}

# Create a Virtual Private Cloud (VPC)
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "MainVPC"
  }
}

# Create a Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "PublicSubnet"
  }
}

# Create an Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "MainInternetGateway"
  }
}

# Create a Route Table
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

# Associate the Route Table with the Subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Create an S3 Bucket for Logs
resource "aws_s3_bucket" "log_bucket" {
  bucket = "cybersecurity-lab-logs-${random_id.bucket_id.hex}" # Unique bucket name
  acl    = "private"

  tags = {
    Name = "CybersecurityLabLogs"
  }
}

# Security Group for Web Server
resource "aws_security_group" "web_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SSH access
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTP access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "WebServerSG"
  }
}

# Web Server Instance
resource "aws_instance" "web_server" {
  ami           = "ami-12345678" # Replace with a valid Ubuntu AMI
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id
  key_name      = "your-key-pair" # Replace with your key pair
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "WebServer"
  }
}

# Security Group for Nessus
resource "aws_security_group" "nessus_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 8834
    to_port     = 8834
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Nessus Web Access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "NessusSecurityGroup"
  }
}

# Nessus Server Instance
resource "aws_instance" "nessus_server" {
  ami           = "ami-12345678" # Replace with a valid Ubuntu AMI
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id
  key_name      = "your-key-pair" # Replace with your key pair
  vpc_security_group_ids = [aws_security_group.nessus_sg.id]

  tags = {
    Name = "NessusServer"
  }
}

