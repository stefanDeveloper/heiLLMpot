

variable "orchestrator_api_key" {
  description = "Shared API key for node registration. Set via TF_VAR_orchestrator_api_key."
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.orchestrator_api_key) >= 16
    error_message = "orchestrator_api_key must be at least 16 characters. Generate with: openssl rand -hex 32"
  }
}

variable "db_name" {
  description = "Postgres database name. Set via TF_VAR_db_name."
  type        = string
  default     = "honeypot_db"
}

variable "db_user" {
  description = "Postgres database user name. Set via TF_VAR_db_user."
  type        = string
  default     = "orchestrator_app"
}

variable "db_password" {
  description = "Postgres database password. Set via TF_VAR_db_password."
  type        = string
  sensitive   = true
  default     = ""
}

variable "jwt_secret" {
  description = "Secret key for JWT validation/generation. Set via TF_VAR_jwt_secret."
  type        = string
  sensitive   = true
  default     = ""
}

