# Enforcement as code: the two Conditional Access policies that correct the
# findings the analyzer reports. Both exclude the break-glass admin and default
# to report-only, so applying them can never lock you out.

# Break-glass account to exclude, looked up by UPN so no object ID is hard-coded.
data "azuread_user" "break_glass" {
  user_principal_name = var.break_glass_upn
}

# 1. Require MFA for anyone holding a privileged directory role.
#    Fixes the "privileged account, no MFA" finding at the tenant level.
resource "azuread_conditional_access_policy" "require_mfa_for_admins" {
  count = var.enable_conditional_access ? 1 : 0

  display_name = "ENTRA-LENS - Require MFA for admins"
  state        = var.policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_roles = var.admin_role_template_ids
      excluded_users = [data.azuread_user.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# 2. Block legacy authentication for everyone. Legacy protocols can't do MFA, so
#    they're the usual way attackers sidestep it.
resource "azuread_conditional_access_policy" "block_legacy_auth" {
  count = var.enable_conditional_access ? 1 : 0

  display_name = "ENTRA-LENS - Block legacy authentication"
  state        = var.policy_state

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = [data.azuread_user.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
