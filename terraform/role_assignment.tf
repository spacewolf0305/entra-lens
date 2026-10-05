# Right-sized role assignment as code (works on the FREE tier).
#
# Provisions a dedicated least-privilege account and grants it ONLY Global Reader
# - read-only, nothing more. This is the "least privilege as code" half of the
# enforcement story, and unlike Conditional Access it needs no premium licence,
# so it exercises the full init -> plan -> apply -> destroy lifecycle end to end.

resource "random_password" "reader" {
  length           = 20
  special          = true
  override_special = "!@#$%*-_"
}

# The tenant's initial *.onmicrosoft.com domain, for the new account's UPN.
data "azuread_domains" "default" {
  only_initial = true
}

resource "azuread_user" "lab_reader" {
  user_principal_name   = "entralens.reader@${data.azuread_domains.default.domains[0].domain_name}"
  display_name          = "ENTRA-LENS Lab Reader (managed by Terraform)"
  mail_nickname         = "entralens.reader"
  password              = random_password.reader.result
  account_enabled       = true
  force_password_change = true
}

# Activate the built-in Global Reader role so it can be assigned.
resource "azuread_directory_role" "global_reader" {
  display_name = "Global Reader"
}

# Grant the account read-only access - right-sized, as code.
resource "azuread_directory_role_assignment" "reader" {
  role_id             = azuread_directory_role.global_reader.template_id
  principal_object_id = azuread_user.lab_reader.object_id
}
