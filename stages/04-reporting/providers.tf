terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "azurerm" {
    key              = "04-reporting.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {
    # Terraform manages storage through Azure Resource Manager only and never opens the
    # storage data plane. Two reasons: (1) separation of duties, since the deployer and
    # the plan-only CI identity have no business reading evidence contents, only the
    # collector and reporter do; (2) it works from any authenticated shell, including
    # Azure Cloud Shell, whose managed-identity token cannot target a single storage
    # account. Every storage setting this repo uses (blob service properties, containers,
    # the WORM policy) is an ARM resource, so nothing is lost.
    storage {
      data_plane_available = false
    }
  }
  storage_use_azuread = true
}

data "terraform_remote_state" "foundation" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "01-foundation.tfstate"
    use_azuread_auth     = true
  }
}

data "terraform_remote_state" "evidence" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "03-evidence-store.tfstate"
    use_azuread_auth     = true
  }
}
