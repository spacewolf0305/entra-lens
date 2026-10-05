output "policy_state" {
  description = "The state the policies were deployed in (report-only by default)."
  value       = var.policy_state
}

output "break_glass_excluded" {
  description = "The account excluded from both policies."
  value       = data.azuread_user.break_glass.user_principal_name
}

output "policies" {
  description = "Conditional Access policy IDs (null until deployed on a P1/P2 tenant via enable_conditional_access)."
  value = {
    require_mfa_for_admins = one(azuread_conditional_access_policy.require_mfa_for_admins[*].id)
    block_legacy_auth      = one(azuread_conditional_access_policy.block_legacy_auth[*].id)
  }
}

output "managed_reader" {
  description = "The least-privilege account provisioned as code (free tier)."
  value = {
    upn  = azuread_user.lab_reader.user_principal_name
    role = "Global Reader"
  }
}
