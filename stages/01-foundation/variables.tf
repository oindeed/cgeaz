variable "location" {
  description = "Azure region for foundation resources."
  type        = string
  default     = "eastus"
}

variable "owner_email" {
  description = "Owner tag applied to governed resource groups; the POA&M generator resolves finding owners from it."
  type        = string
}

variable "environment" {
  description = "Environment name used in tags and resource names."
  type        = string
  default     = "dev"
}

variable "tag_policy_effect" {
  description = "Effect for the require-env-tag policy (Audit while onboarding, Deny once clean)."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.tag_policy_effect)
    error_message = "tag_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "public_blob_policy_effect" {
  description = "Effect for the deny-public-blob-access policy. This one has earned Deny."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.public_blob_policy_effect)
    error_message = "public_blob_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "classification_tag_effect" {
  description = "Effect for cge-require-data-classification. New control: Audit until the inventory is clean, then Deny by reviewed PR."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.classification_tag_effect)
    error_message = "classification_tag_effect must be Audit, Deny, or Disabled."
  }
}

variable "restricted_network_policy_effect" {
  description = "Effect for cge-deny-public-network-restricted. Binary rule on a self-declared label, so it earns Deny from day one."
  type        = string
  default     = "Deny"
  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.restricted_network_policy_effect)
    error_message = "restricted_network_policy_effect must be Audit, Deny, or Disabled."
  }
}

variable "tripwire_enabled" {
  description = "Run the hourly out-of-band change alert (tripwire.tf). Read-only; false pauses it without deleting the rule's history."
  type        = bool
  default     = true
}
