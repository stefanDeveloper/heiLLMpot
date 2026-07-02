data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

data "aws_ami" "ubuntu_arm64" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*"]
  }
}

resource "tls_private_key" "generated" {
  count     = local.key_name == "" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "random_id" "key_suffix" {
  count       = local.key_name == "" ? 1 : 0
  byte_length = 4
}

resource "aws_key_pair" "generated" {
  count      = local.key_name == "" ? 1 : 0
  key_name   = "heillmpot-generated-key-${random_id.key_suffix[0].hex}"
  public_key = tls_private_key.generated[0].public_key_openssh
}

resource "local_sensitive_file" "private_key" {
  count           = local.key_name == "" ? 1 : 0
  content         = tls_private_key.generated[0].private_key_pem
  filename        = "${path.module}/../../../deploy/heillmpot-generated-key.pem"
  file_permission = "0400"
}

# ─── mTLS PKI Generation ─────────────────────────────────────────────────────

resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem   = tls_private_key.ca.private_key_pem
  is_ca_certificate = true

  subject {
    common_name  = "Honeypot-CA"
    organization = "Research"
    country      = "DE"
  }

  validity_period_hours = 87600 # 10 years
  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

resource "tls_private_key" "orchestrator_cert" {
  count     = local.deploy_orchestrator ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "orchestrator_cert" {
  count           = local.deploy_orchestrator ? 1 : 0
  private_key_pem = tls_private_key.orchestrator_cert[0].private_key_pem

  subject {
    common_name  = "orchestrator"
    organization = "Research"
    country      = "DE"
  }

  dns_names    = ["localhost", "orchestrator"]
  ip_addresses = ["127.0.0.1", aws_eip.orchestrator[0].public_ip]
}

resource "aws_eip" "orchestrator" {
  count  = local.deploy_orchestrator ? 1 : 0
  domain = "vpc"
}

resource "aws_eip_association" "orchestrator" {
  count         = local.deploy_orchestrator ? 1 : 0
  instance_id   = module.orchestrator[0].instance_id
  allocation_id = aws_eip.orchestrator[0].id
}

resource "tls_locally_signed_cert" "orchestrator_cert" {
  count              = local.deploy_orchestrator ? 1 : 0
  cert_request_pem   = tls_cert_request.orchestrator_cert[0].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 19800 # ~2.5 years
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "tls_private_key" "honeybot_cert" {
  count     = local.honeybot_amount
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_cert_request" "honeybot_cert" {
  count           = local.honeybot_amount
  private_key_pem = tls_private_key.honeybot_cert[count.index].private_key_pem

  subject {
    common_name  = "node-${count.index + 1}"
    organization = "Research"
    country      = "DE"
  }
}

resource "tls_locally_signed_cert" "honeybot_cert" {
  count              = local.honeybot_amount
  cert_request_pem   = tls_cert_request.honeybot_cert[count.index].cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 19800
  allowed_uses = [
    "digital_signature",
    "client_auth",
  ]
}

module "orchestrator" {
  count  = local.deploy_orchestrator ? 1 : 0
  source = "../../modules/orchestrator-aws"

  instance_type        = local.orchestrator_instance_type
  ami_id               = local.orchestrator_ami_id != "" ? local.orchestrator_ami_id : data.aws_ami.ubuntu.id
  vpc_id               = local.orchestrator_vpc_id != "" ? local.orchestrator_vpc_id : data.aws_vpc.default.id
  subnet_id            = local.orchestrator_subnet_id != null ? local.orchestrator_subnet_id : data.aws_subnets.default.ids[0]
  key_name             = local.effective_key_name
  admin_cidr           = local.admin_cidr
  git_repo             = local.git_repo
  git_branch           = local.git_branch
  db_name              = var.db_name
  db_user              = var.db_user
  db_password          = var.db_password
  jwt_secret           = var.jwt_secret
  orchestrator_api_key = var.orchestrator_api_key

  ssl_ca_cert    = tls_self_signed_cert.ca.cert_pem
  ssl_server_crt = local.deploy_orchestrator ? tls_locally_signed_cert.orchestrator_cert[0].cert_pem : ""
  ssl_server_key = local.deploy_orchestrator ? tls_private_key.orchestrator_cert[0].private_key_pem : ""

  tags = local.extra_tags
}

module "honeybot" {
  count  = local.honeybot_amount
  source = "../../modules/honeybot-node-aws"

  node_id = "node-${count.index + 1}"
  region  = local.aws_region

  orchestrator_url = local.deploy_orchestrator ? "https://${aws_eip.orchestrator[0].public_ip}" : local.orchestrator_url

  orchestrator_api_key = var.orchestrator_api_key
  honeybot_image       = local.honeybot_image
  ssh_honeypot_enabled = local.ssh_honeypot_enabled
  tags                 = local.extra_tags
  active_site          = local.active_site

  ami_id        = data.aws_ami.ubuntu.id
  vpc_id        = data.aws_vpc.default.id
  subnet_id     = data.aws_subnets.default.ids[count.index % length(data.aws_subnets.default.ids)]
  instance_type = local.honeybot_instance_type
  key_name      = local.effective_key_name
  admin_cidr    = local.admin_cidr

  git_repo             = local.git_repo
  git_branch           = local.git_branch

  ssl_ca_cert    = tls_self_signed_cert.ca.cert_pem
  ssl_client_crt = tls_locally_signed_cert.honeybot_cert[count.index].cert_pem
  ssl_client_key = tls_private_key.honeybot_cert[count.index].private_key_pem
}

resource "null_resource" "honeybot_status" {
  count = local.honeybot_amount
  depends_on = [module.honeybot]

  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = tls_private_key.generated[0].private_key_pem
    host        = module.honeybot[count.index].public_ip
  }

  provisioner "file" {
    source      = "${path.module}/../../../generated_sites"
    destination = "/tmp"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo mkdir -p /app",
      "sudo cp -r /tmp/generated_sites /app/ || true",
      "sudo chown -R root:root /app/generated_sites",
      "while [ ! -f /var/log/cloud-init-output.log ]; do sleep 2; done",
      "tail -n +1 -f /var/log/cloud-init-output.log | while read line; do",
      "  case \"$line\" in",
      "    *\"Orchestrator is not ready, honeybots are waiting...\"*) echo \"[Orchestrator is still starting]\" ;;",
      "    *\"Honeybots are pulling the image now...\"*) echo \"[Honeybots are connected and image is pulling]\" ;;",
      "    *\"heiLLMpot honeybot bootstrap complete\"*)",
      "      echo \"[Honeybot deployment complete!]\"",
      "      pkill -f cloud-init-output.log || true",
      "      break",
      "      ;;",
      "  esac",
      "done"
    ]
  }
}
