variable "tenant_id" {
  description = "Entra ID tenant (directory) ID of the lab."
  type        = string
}

variable "break_glass_upn" {
  description = <<-EOT
    UPN of the break-glass admin to EXCLUDE from the MFA and legacy-auth policies,
    so a policy misconfiguration can never lock every admin out. Use your own
    tenant admin account.
  EOT
  type        = string
}

variable "policy_state" {
  description = <<-EOT
    How the Conditional Access policies are deployed:
      enabledForReportingButNotEnforced - report-only; logs impact, enforces nothing (SAFE DEFAULT)
      enabled                           - actively enforced
      disabled                          - created but off
    Deploy report-only first, confirm the sign-in logs look right, then flip to enabled.
  EOT
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabled", "disabled", "enabledForReportingButNotEnforced"], var.policy_state)
    error_message = "policy_state must be enabled, disabled, or enabledForReportingButNotEnforced."
  }
}

variable "enable_conditional_access" {
  description = <<-EOT
    Deploy the Conditional Access policies. These require Entra ID P1/P2, so leave
    this false on a free lab tenant (plan still validates them). Set to true on a
    licensed tenant to actually create them.
  EOT
  type        = bool
  default     = false
}

variable "admin_role_template_ids" {
  description = "Directory role template IDs treated as privileged and required to use MFA."
  type        = list(string)
  default = [
    "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", # User Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", # Conditional Access Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
  ]
}
