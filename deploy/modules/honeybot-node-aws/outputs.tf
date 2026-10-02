# ──────────────────────────────────────────────────────────────────────────────
# honeybot-node-aws — Outputs
# ──────────────────────────────────────────────────────────────────────────────

# ── Provider-agnostic outputs (required by interface contract) ────────────────

output "node_id" {
  description = "The node_id of this honeybot instance."
  value       = var.node_id
}

output "public_ip" {
  description = "Public IPv4 address of the honeybot EC2 instance."
  value       = aws_instance.honeybot.public_ip
}

# ── AWS-specific outputs ─────────────────────────────────────────────────────

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.honeybot.id
}

output "public_dns" {
  description = "Public DNS hostname of the honeybot EC2 instance."
  value       = aws_instance.honeybot.public_dns
}

output "security_group_id" {
  description = "Security group ID attached to the honeybot instance."
  value       = aws_security_group.honeybot.id
}

output "availability_zone" {
  description = "Availability zone of the honeybot instance."
  value       = aws_instance.honeybot.availability_zone
}
