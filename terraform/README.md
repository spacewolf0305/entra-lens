# ENTRA-LENS — Phase 3: enforcement as code

Terraform that enforces the corrections the analyzer surfaces, as version-controlled,
reviewable code gated by Checkov. Two Conditional Access policies:

- **Require MFA for admins** — anyone in a privileged directory role must use MFA.
- **Block legacy authentication** — legacy protocols (which can't do MFA) are blocked.

Both **exclude a break-glass admin** and deploy **report-only** by default, so applying
them can't lock you out.

## Prerequisites

1. **Entra ID P1/P2** on the tenant. Conditional Access does not exist on the Free
   tier — start the P2 free trial first.
2. **One extra app permission.** Add to the `entra-lens-collector` app (API permissions
   → Microsoft Graph → Application permissions), then **Grant admin consent**:
   - `Policy.ReadWrite.ConditionalAccess`
   - `Policy.Read.All`
   If `terraform apply` returns 403 on the policies, also assign the app the
   **Conditional Access Administrator** role (Entra → Roles & admins).
3. **Terraform** ≥ 1.5 installed (`terraform -version`).

## Configure

```powershell
copy terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: tenant_id and break_glass_upn (your admin account)

# Auth for the azuread provider - same app the collector uses (PowerShell):
$env:ARM_TENANT_ID    = "b8ccfdcf-743d-45b2-857c-8d88c1e24fb5"
$env:ARM_CLIENT_ID    = "f4027541-f61a-48b8-a46b-2ce7d4ec8147"
$env:ARM_CLIENT_SECRET = "<the client secret value>"
```

(In cmd.exe use `set ARM_TENANT_ID=...` instead of `$env:`.)

## Deploy

Conditional Access is behind the `enable_conditional_access` toggle (default
**false**), so on a free tenant `apply` creates only the least-privilege reader
account and succeeds cleanly:

```bash
terraform init      # re-run after adding the random provider
terraform fmt
terraform validate
terraform plan      # free tier: the reader account + role assignment
terraform apply     # type yes
terraform destroy   # tear the lab resources back down
```

On a **P1/P2-licensed** tenant, also deploy the Conditional Access policies:

```bash
terraform apply -var="enable_conditional_access=true"   # adds the 2 CA policies, report-only
```

Check the result in Entra admin center → Protection → Conditional Access. Both
policies appear in **Report-only**. Review the report-only impact under sign-in logs,
then flip to enforced:

```bash
# set policy_state = "enabled" in terraform.tfvars, then
terraform apply
```

Tear down when you're done demoing:

```bash
terraform destroy
```

## The gate (Checkov / CI)

Scan the Terraform the same way SENTINEL-SC scans app code:

```bash
pip install checkov
checkov -d .
```

`.github/workflows/terraform.yml` runs `fmt`, `validate` and Checkov on every pull
request, so insecure or malformed IaC can't merge.

## Licensing note

Conditional Access is an Entra ID **P1/P2** feature. On a free lab tenant,
`terraform plan` validates the configuration against the real azuread provider
(resources, role targeting, break-glass exclusion all resolve), but `terraform
apply` returns `AccessDenied: your tenant is not licensed for this feature`.
Lab tenants created from a consumer Microsoft account cannot start the P2 trial
(the M365 admin center rejects consumer users), so this is validated via `plan`;
on any P1/P2-licensed tenant the same config applies unchanged.

The role-assignment resources below (`role_assignment.tf`) do NOT need premium
and apply on the free tier, so the full init -> plan -> apply -> destroy
lifecycle can still be demonstrated end to end.

## How this closes the loop

The analyzer finds the gaps → this Terraform enforces the fix as code → Checkov gates
the Terraform → re-running the collector and analyzer shows the posture improve. Find →
fix → prove, with your own scanner guarding the fix.
