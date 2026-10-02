# ──────────────────────────────────────────────────────────────────────────────
# honeybot-node-aws — AWS-specific variables
# ──────────────────────────────────────────────────────────────────────────────

# ── Provider-agnostic variables (from interface contract) ─────────────────────

variable "node_id" {
  description = "Unique identifier for this honeybot node (e.g. node-us-east-1)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$", var.node_id))
    error_message = "node_id must be 1-63 alphanumeric characters, hyphens, dots, or underscores."
  }
}

variable "region" {
  description = "Logical region label stored in the orchestrator (e.g. us-east-1)."
  type        = string
}

variable "orchestrator_url" {
  description = "Base URL of the heiLLMpot orchestrator API."
  type        = string
}

variable "orchestrator_api_key" {
  description = "Shared API key used to register the node with the orchestrator."
  type        = string
  sensitive   = true
}

variable "honeybot_image" {
  description = "Fully-qualified Docker image for the honeybot."
  type        = string
}

variable "ssh_honeypot_enabled" {
  description = "Whether to open port 2222 and start the SSH honeypot module."
  type        = bool
  default     = false
}

variable "ssl_ca_cert" {
  description = "CA certificate for mTLS"
  type        = string
  default     = ""
}

variable "ssl_client_crt" {
  description = "Client certificate for mTLS"
  type        = string
  default     = ""
}

variable "ssl_client_key" {
  description = "Client key for mTLS"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to assign to the instance"
  type        = map(string)
  default     = {}
}

variable "active_site" {
  description = "The specific site name to deploy/activate"
  type        = string
  default     = ""
}

  variable "git_repo" {
    description = "Git repository to clone for building honeybot."
    type        = string
  }

  variable "git_branch" {
    description = "Git branch to clone for building honeybot."
    type        = string
  }

# ── AWS-specific variables ────────────────────────────────────────────────────

variable "instance_type" {
  description = "EC2 instance type for the honeybot node."
  type        = string
  default     = "t3.small"
}

variable "ami_id" {
  description = "AMI ID for Ubuntu (must match the target AWS region)."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID in which to create the honeybot security group."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the EC2 instance. Must be a public subnet with auto-assign public IP."
  type        = string
}

variable "key_name" {
  description = "Name of an existing EC2 key pair for admin SSH access."
  type        = string
  default     = ""
}

variable "admin_cidr" {
  description = "CIDR block allowed to SSH into the instance on port 22 for administration."
  type        = string
  default     = "0.0.0.0/0"
}

variable "root_volume_size_gb" {
  description = "Size of the root EBS volume in GiB."
  type        = number
  default     = 20
}

variable "associate_public_ip" {
  description = "Whether to associate a public IPv4 address with the instance."
  type        = bool
  default     = true
}
