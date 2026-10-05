# The azuread provider authenticates with the same app registration the collector
# uses, via environment variables so no secret is ever written to a .tf file:
#   ARM_TENANT_ID, ARM_CLIENT_ID, ARM_CLIENT_SECRET
#
# The app also needs the application permission Policy.ReadWrite.ConditionalAccess
# (admin-consented) to manage Conditional Access. See README.md.

provider "azuread" {
  tenant_id = var.tenant_id
}
