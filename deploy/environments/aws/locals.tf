
locals {
  config = jsondecode(file("${path.module}/config.json"))


  aws_region             = local.config.aws_region
  orchestrator_url       = lookup(local.config, "orchestrator_url", "")
  honeybot_image         = local.config.honeybot_image
  honeybot_amount        = lookup(local.config, "honeybot_amount", 1)
  honeybot_instance_type = lookup(local.config, "honeybot_instance_type", "t3.small")
  key_name               = lookup(local.config, "key_name", "")
  effective_key_name     = local.key_name != "" ? local.key_name : (length(aws_key_pair.generated) > 0 ? aws_key_pair.generated[0].key_name : "")
  admin_cidr             = lookup(local.config, "admin_cidr", "0.0.0.0/0")
  ssh_honeypot_enabled   = lookup(local.config, "ssh_honeypot_enabled", false)
  extra_tags             = lookup(local.config, "extra_tags", {})
  active_site            = lookup(local.config, "active_site", "")


  deploy_orchestrator        = lookup(local.config, "deploy_orchestrator", false)
  orchestrator_ami_id        = lookup(local.config, "orchestrator_ami_id", "")
  orchestrator_instance_type = lookup(local.config, "orchestrator_instance_type", "t3.small")
  orchestrator_vpc_id        = lookup(local.config, "orchestrator_vpc_id", "")
  orchestrator_subnet_id     = lookup(local.config, "orchestrator_subnet_id", null)
  git_repo                   = lookup(local.config, "git_repo", "https://github.com/stefanDeveloper/heiLLMpot.git")
  git_branch                 = lookup(local.config, "git_branch", "main")

  external_ca_cert_path      = lookup(local.config, "external_ca_cert_path", "")
  external_client_crt_path   = lookup(local.config, "external_client_crt_path", "")
  external_client_key_path   = lookup(local.config, "external_client_key_path", "")
}

