

output "nodes" {
  description = "Summary of all deployed honeybot nodes."
  value = {
    for idx, mod in module.honeybot : "node-${idx + 1}" => {
      public_ip         = mod.public_ip
      public_dns        = mod.public_dns
      instance_id       = mod.instance_id
      security_group_id = mod.security_group_id
      availability_zone = mod.availability_zone
    }
  }
}

output "node_ips" {
  description = "Map of node_id → public IP for quick reference."
  value = {
    for idx, mod in module.honeybot : "node-${idx + 1}" => mod.public_ip
  }
}

output "node_ssh_cmds" {
  description = "Ready-to-use SSH commands for all honeybot nodes."
  value = {
    for idx, mod in module.honeybot : "node-${idx + 1}" => "ssh ${local.key_name == "" ? "-i ${abspath(path.module)}/../../heillmpot-generated-key.pem " : ""}-o StrictHostKeyChecking=no ubuntu@${mod.public_ip}"
  }
}

output "orchestrator_public_ip" {
  description = "Public IP of the central orchestrator (if deployed)"
  value       = local.deploy_orchestrator ? aws_eip.orchestrator[0].public_ip : null
}

output "orchestrator" {
  description = "Details of the deployed central orchestrator base."
  value = local.deploy_orchestrator ? {
    public_ip         = aws_eip.orchestrator[0].public_ip
    public_dns        = module.orchestrator[0].public_dns
    instance_id       = module.orchestrator[0].instance_id
    security_group_id = module.orchestrator[0].security_group_id
    dashboard_ssh_cmd = "ssh ${local.key_name == "" ? "-i ${abspath(path.module)}/../../heillmpot-generated-key.pem " : ""}-L 8090:127.0.0.1:8090 ubuntu@${aws_eip.orchestrator[0].public_ip}"
  } : null

}
