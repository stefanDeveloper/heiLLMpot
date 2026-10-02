

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = ">= 2.3, < 3.0"
    }
  }

  # Uncomment and configure for remote state storage:
  # backend "s3" {
  #   bucket = "heillmpot-tfstate"
  #   key    = "aws/honeybot-nodes.tfstate"
  #   region = "eu-central-1"
  # }
}
