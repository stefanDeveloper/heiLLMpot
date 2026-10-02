# ──────────────────────────────────────────────────────────────────────────────
# AWS Orchestrator Module — Security Group + EC2 Instance
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_security_group" "orchestrator" {
  name_prefix = "heillmpot-orchestrator-sg-"
  description = "Security group for heiLLMpot orchestrator node"
  vpc_id      = var.vpc_id

  tags = merge(
    {
      Name = "heillmpot-orchestrator-sg"
      Role = "orchestrator"
    },
    var.tags
  )
}

# ─── Security Group Rules ─────────────────────────────────────────────────────

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
  security_group_id = aws_security_group.orchestrator.id
  description       = "Admin SSH access"
}

resource "aws_security_group_rule" "http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.orchestrator.id
  description       = "HTTP port (redirect to HTTPS)"
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.orchestrator.id
  description       = "HTTPS port (mTLS ingestion + API)"
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.orchestrator.id
  description       = "Allow all outbound traffic"
}

# ─── EC2 Instance ─────────────────────────────────────────────────────────────

resource "aws_instance" "orchestrator" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name != "" ? var.key_name : null
  subnet_id     = var.subnet_id

  vpc_security_group_ids = [aws_security_group.orchestrator.id]

  # Enforce IMDSv2 (Security Best Practice)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Enforce encrypted root volume
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    db_name              = var.db_name
    db_user              = var.db_user
    db_password          = var.db_password
    jwt_secret           = var.jwt_secret
    orchestrator_api_key = var.orchestrator_api_key
    ssl_ca_cert          = var.ssl_ca_cert
    ssl_server_crt       = var.ssl_server_crt
    ssl_server_key       = var.ssl_server_key
    git_repo             = var.git_repo
    git_branch           = var.git_branch
  })

  tags = merge(
    {
      Name = "heillmpot-orchestrator"
      Role = "orchestrator"
    },
    var.tags
  )

  lifecycle {
    # Prevent accidental destruction of orchestrator containing the postgres db
    prevent_destroy = false
  }
}
