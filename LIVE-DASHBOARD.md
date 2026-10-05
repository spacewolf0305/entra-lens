# Live dashboard — setup (GitHub Pages + OIDC, no stored secret)

A scheduled GitHub Action scans the tenant and publishes the dashboard to a public
GitHub Pages URL. It authenticates to Microsoft Graph with **OIDC federation**, so
**no client secret is stored anywhere** — GitHub proves its identity to Entra and
gets a short-lived token for that run only.

```
GitHub Actions (daily cron + Run-now)
  → GitHub OIDC token  ──exchange──▶  Entra  →  short-lived Graph token
  → collector.py → analyzer.py → dashboard.py
  → publish site/index.html to GitHub Pages
```

## One-time setup

### 1. Push the project to a PUBLIC GitHub repo
```bash
git init && git add . && git commit -m "ENTRA-LENS"
git branch -M main
git remote add origin https://github.com/<you>/entra-lens.git
git push -u origin main
```
`.gitignore` already excludes `.env`, snapshots, reports and Terraform state, so no
secrets or tenant data are committed.

### 2. Add two repo variables (NOT secrets — neither is sensitive)
GitHub repo → **Settings → Secrets and variables → Actions → Variables → New variable**:
- `TENANT_ID` = `b8ccfdcf-743d-45b2-857c-8d88c1e24fb5`
- `CLIENT_ID` = `f4027541-f61a-48b8-a46b-2ce7d4ec8147`

### 3. Add a federated credential on the app (this is what replaces the secret)
Entra admin center → your `entra-lens-collector` app → **Certificates & secrets →
Federated credentials → + Add credential**:
- Scenario: **GitHub Actions deploying Azure resources**
- Organization: `<your-github-username>`  ·  Repository: `entra-lens`
- Entity type: **Environment**  ·  Environment name: **`github-pages`**
- Name: `github-pages-oidc`
- Audience: leave the default `api://AzureADTokenExchange`

This trusts exactly this repo's `github-pages` environment to sign in as the app —
nothing else can.

> The app only needs its **read-only** Graph permissions (Directory.Read.All,
> RoleManagement.Read.Directory, AuditLog.Read.All). The seeding write permissions
> can stay removed — CI never writes.

### 4. Enable Pages
GitHub repo → **Settings → Pages → Build and deployment → Source: GitHub Actions**.

## Run it

GitHub repo → **Actions → live-dashboard → Run workflow**. When it finishes, the
**deploy** step prints the public URL (also under Settings → Pages), e.g.
`https://<you>.github.io/entra-lens/`. After this first manual run it also runs
itself **daily** on the cron.

## What's published (and what isn't)

- Published: the dashboard HTML only, with `REDACT_DOMAIN=1` so the tenant domain is
  masked (`…@lab.onmicrosoft.com`). The seeded users are synthetic.
- Never published: `.env`, the raw snapshot JSON, Terraform state — all git-ignored.

## Troubleshooting

- **OIDC exchange failed** in the "Mint a Microsoft Graph token" step → the federated
  credential's repo/environment doesn't match, or `TENANT_ID`/`CLIENT_ID` variables
  are wrong. The subject must be `repo:<you>/entra-lens:environment:github-pages`.
- **403 on the Graph calls** → the app's read-only permissions aren't admin-consented.
- **Pages 404** → Pages source isn't set to "GitHub Actions" (step 4).
