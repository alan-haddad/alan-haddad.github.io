# Define the AWS Provider
provider "aws" {
  region = "us-east-1" # Specify your region
}

# Fetch User's Public IP Address
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com/"
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

# IAM Role for Web Server
resource "aws_iam_role" "web_server_role" {
  name = "WebServerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "s3_logging_policy" {
  name        = "S3LoggingPolicy"
  description = "Policy to allow log uploads to S3"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
        Effect   = "Allow",
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.log_bucket.bucket}/*",
          "arn:aws:s3:::${aws_s3_bucket.log_bucket.bucket}"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "web_server_profile" {
  name = "WebServerInstanceProfile"
  role = aws_iam_role.web_server_role.name
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.web_server_role.name
  policy_arn = aws_iam_policy.s3_logging_policy.arn
}

# Security Group for Web Server
resource "aws_security_group" "web_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.body)}/32"] # SSH restricted to user's IP
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow HTTP from anywhere
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

# Web Server Instance with Log Sync to S3
resource "aws_instance" "web_server" {
  ami           = "ami-12345678" # Replace with a valid Ubuntu AMI
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id
  key_name      = "your-key-pair" # Replace with your key pair
  iam_instance_profile = aws_iam_instance_profile.web_server_profile.name
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "WebServer"
  }

  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("~/.ssh/your-private-key.pem")
      host        = self.public_ip
    }

    inline = [
      "sudo apt update && sudo apt install -y apache2 awscli",
      "sudo mkdir -p /var/log/apache2 && sudo chmod -R 755 /var/log/apache2",
      "(crontab -l ; echo '*/5 * * * * aws s3 sync /var/log/apache2 s3://${aws_s3_bucket.log_bucket.bucket}') | crontab -",
      "sudo systemctl start apache2 && sudo systemctl enable apache2"
    ]
  }
}

# Security Group for Nessus Server
resource "aws_security_group" "nessus_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 8834
    to_port     = 8834
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.body)}/32"] # Nessus UI access restricted
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.body)}/32"] # SSH restricted to user's IP
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

# Security Group for Attack Platform
resource "aws_security_group" "attack_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.body)}/32"] # SSH restricted to user's IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "AttackPlatformSG"
  }
}

# Attack Platform Instance
resource "aws_instance" "attack_platform" {
  ami           = "ami-12345678" # Replace with a valid Kali AMI
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public.id
  key_name      = "your-key-pair" # Replace with your key pair
  vpc_security_group_ids = [aws_security_group.attack_sg.id]

  tags = {
    Name = "AttackPlatform"
  }
}
