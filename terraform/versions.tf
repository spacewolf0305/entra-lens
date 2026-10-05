terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Lab uses local state. In production, use a remote backend with locking,
  # e.g. an encrypted Azure Storage container:
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-tfstate"
  #   storage_account_name = "tfstateentralens"
  #   container_name       = "tfstate"
  #   key                  = "entra-lens.tfstate"
  # }
}
