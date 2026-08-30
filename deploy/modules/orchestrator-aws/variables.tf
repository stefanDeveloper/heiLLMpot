# ──────────────────────────────────────────────────────────────────────────────
# AWS Orchestrator Module Variables
# ──────────────────────────────────────────────────────────────────────────────

variable "instance_type" {
  description = "EC2 instance type for the orchestrator"
  type        = string
  default     = "t3.small"
}

variable "ami_id" {
  description = "Ubuntu Noble 24.04 LTS AMI ID"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the orchestrator instance and security group will be created"
  type        = string
}

variable "subnet_id" {
  description = "VPC subnet ID to launch the instance into (must be public or have NAT)"
  type        = string
  default     = null
}

variable "key_name" {
  description = "Name of the SSH key pair to associate with the instance for admin access"
  type        = string
  default     = ""
}

variable "admin_cidr" {
  description = "CIDR block allowed to access SSH (port 22)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "git_repo" {
  description = "GitHub repository URL to clone and run"
  type        = string
  default     = "https://github.com/stefanDeveloper/heiLLMpot.git"
}

variable "git_branch" {
  description = "Branch/tag of the Git repository to check out"
  type        = string
  default     = "main"
}

# ─── Secrets / Env variables ──────────────────────────────────────────────────

variable "db_name" {
  description = "Postgres database name"
  type        = string
  default     = "honeypot_db"
}

variable "db_user" {
  description = "Postgres database user name"
  type        = string
  default     = "orchestrator_app"
}

variable "db_password" {
  description = "Postgres database password"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "Secret key for JWT validation/generation"
  type        = string
  sensitive   = true
}

variable "orchestrator_api_key" {
  description = "API key required by nodes to register"
  type        = string
  sensitive   = true
}

# ─── PKI / Certificates (contents passed as strings) ─────────────────────────

variable "ssl_ca_cert" {
  description = "Content of ca.crt certificate file"
  type        = string
}

variable "ssl_server_crt" {
  description = "Content of server.crt certificate file"
  type        = string
}

variable "ssl_server_key" {
  description = "Content of server.key private key file"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Additional tags to apply to created resources"
  type        = map(string)
  default     = {}
}
