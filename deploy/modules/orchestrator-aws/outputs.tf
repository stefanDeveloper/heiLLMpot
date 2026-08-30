# ──────────────────────────────────────────────────────────────────────────────
# AWS Orchestrator Module Outputs
# ──────────────────────────────────────────────────────────────────────────────

output "instance_id" {
  description = "The EC2 instance ID of the orchestrator"
  value       = aws_instance.orchestrator.id
}

output "public_ip" {
  description = "The public IP address of the orchestrator"
  value       = aws_instance.orchestrator.public_ip
}

output "public_dns" {
  description = "The public DNS name of the orchestrator"
  value       = aws_instance.orchestrator.public_dns
}

output "security_group_id" {
  description = "The ID of the security group created for the orchestrator"
  value       = aws_security_group.orchestrator.id
}
