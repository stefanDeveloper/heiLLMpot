# ──────────────────────────────────────────────────────────────────────────────
# honeybot-node-aws — EC2 instance + security group
# ──────────────────────────────────────────────────────────────────────────────

locals {
  resource_prefix = "heillmpot-${var.node_id}"

  merged_tags = merge(var.tags, {
    Project = "heiLLMpot"
    Role    = "honeybot"
    NodeId  = var.node_id
  })
}

# ── Security group ────────────────────────────────────────────────────────────

resource "aws_security_group" "honeybot" {
  name_prefix = "${local.resource_prefix}-"
  description = "heiLLMpot honeybot node ${var.node_id}"
  vpc_id      = var.vpc_id

  tags = merge(local.merged_tags, {
    Name = "${local.resource_prefix}-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Ingress: HTTP (80) — honeypot lure traffic
resource "aws_security_group_rule" "http_ingress" {
  security_group_id = aws_security_group.honeybot.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTP honeypot traffic"
}

# Ingress: HTTPS (443) — honeypot lure traffic
resource "aws_security_group_rule" "https_ingress" {
  security_group_id = aws_security_group.honeybot.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS honeypot traffic"
}

# Ingress: SSH honeypot (2222) — only when enabled
resource "aws_security_group_rule" "ssh_honeypot_ingress" {
  count = var.ssh_honeypot_enabled ? 1 : 0

  security_group_id = aws_security_group.honeybot.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 2222
  to_port           = 2222
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "SSH honeypot traffic"
}

# Ingress: Admin SSH (22) — restricted to admin CIDR
resource "aws_security_group_rule" "admin_ssh_ingress" {
  security_group_id = aws_security_group.honeybot.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = [var.admin_cidr]
  description       = "Admin SSH access"
}

# Egress: allow all outbound (Docker pulls, orchestrator API, DNS, NTP)
resource "aws_security_group_rule" "all_egress" {
  security_group_id = aws_security_group.honeybot.id
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow all outbound traffic"
}

# ── Cloud-init user data ─────────────────────────────────────────────────────

data "cloudinit_config" "honeybot" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "cloud-init.yaml"
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/cloud-init.yaml.tpl", {
      node_id          = var.node_id
      region           = var.region
      orchestrator_url = var.orchestrator_url
      api_key          = var.orchestrator_api_key
      honeybot_image   = var.honeybot_image
      ssh_enabled      = var.ssh_honeypot_enabled ? "true" : "false"
      ssl_ca_cert      = var.ssl_ca_cert
      ssl_client_crt   = var.ssl_client_crt
      ssl_client_key   = var.ssl_client_key
      active_site      = var.active_site
      git_repo         = var.git_repo
      git_branch       = var.git_branch
    })
  }
}

# ── EC2 instance ──────────────────────────────────────────────────────────────

resource "aws_instance" "honeybot" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.honeybot.id]
  associate_public_ip_address = var.associate_public_ip
  key_name                    = var.key_name != "" ? var.key_name : null
  user_data_base64            = data.cloudinit_config.honeybot.rendered

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only — security best practice
    http_endpoint = "enabled"
  }

  tags = merge(local.merged_tags, {
    Name = local.resource_prefix
  })

  volume_tags = local.merged_tags

  lifecycle {
    ignore_changes = [ami] # Prevent destroy on AMI updates
  }
}
