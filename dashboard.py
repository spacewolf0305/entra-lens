"""
ENTRA-LENS dashboard.

Turns the analyzer's findings into a single, self-contained HTML page you can open
in a browser and screenshot - risk-ranked identities, a severity breakdown, and
per-account detail. Reuses the analyzer's logic, so it runs on the latest snapshot
with no extra input:

    python dashboard.py

Writes reports/dashboard-<timestamp>.html (no external assets, works offline).
"""

import os
import html
import datetime as dt

from analyzer import (
    load_latest_snapshot, build_identities, analyze, section, is_privileged,
)

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")

# Risk tier -> reserved status color (paired with a text label everywhere, so
# identity is never carried by color alone).
TIER_COLOR = {
    "critical": "var(--critical)",
    "high": "var(--serious)",
    "medium": "var(--warning)",
    "reader": "var(--good)",
    "other": "var(--neutral)",
    None: "var(--neutral)",
}
TIER_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "reader": "Read-only", "other": "Other", None: "No role",
}


# When published publicly (CI), set REDACT_DOMAIN=1 to mask the tenant domain so a
# real *.onmicrosoft.com handle isn't exposed on a public page.
REDACT = bool(os.environ.get("REDACT_DOMAIN"))


def esc(s):
    return html.escape(str(s if s is not None else ""))


def account_label(r):
    s = r["upn"] or r["displayName"] or r["id"]
    if REDACT and "@" in s:
        s = s.split("@", 1)[0] + "@lab.onmicrosoft.com"
    return s


def page(results, snapshot, snap_name, mfa_ok, sign_in_ok):
    flagged = [r for r in results if r["findings"]]
    priv = sum(1 for r in results if is_privileged(r["roles"]))
    top_score = max((r["score"] for r in results), default=0)
    tenant = "lab tenant" if REDACT else snapshot.get("tenant_id", "unknown")
    today = dt.date.today().isoformat()

    # Stat tiles.
    tiles = [
        ("Identities analyzed", len(results)),
        ("Privileged accounts", priv),
        ("Accounts flagged", len(flagged)),
        ("Highest risk score", top_score),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="tile-num">{v}</div>'
        f'<div class="tile-label">{esc(l)}</div></div>'
        for l, v in tiles
    )

    # Risk-ranked bars (magnitude per identity, colored by tier + labeled).
    rows = ""
    for r in results:
        name = esc(account_label(r))
        tier = r["top_tier"]
        color = TIER_COLOR.get(tier, "var(--neutral)")
        label = TIER_LABEL.get(tier, "Other")
        width = max(r["score"], 2)  # keep a sliver visible at 0
        rows += f"""
        <div class="bar-row">
          <div class="bar-name" title="{name}">{name}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{width}%;background:{color}"></div>
          </div>
          <div class="bar-score">{r['score']}</div>
          <div class="bar-tier"><span class="dot" style="background:{color}"></span>{esc(label)}</div>
        </div>"""

    # Detail cards for flagged accounts.
    detail = ""
    for r in flagged:
        name = esc(account_label(r))
        color = TIER_COLOR.get(r["top_tier"], "var(--neutral)")
        finds = "".join(f"<li>{esc(f)}</li>" for f in r["findings"])
        factors = ", ".join(f"{esc(l)} (+{p})" for l, p in r["factors"])
        detail += f"""
        <div class="card" style="border-left:4px solid {color}">
          <div class="card-head">
            <span class="card-name">{name}</span>
            <span class="card-score" style="background:{color}">{r['score']}</span>
          </div>
          <ul class="finds">{finds}</ul>
          <div class="factors">score: {esc(factors)}</div>
        </div>"""

    notes = ""
    if not mfa_ok:
        notes += "<li>MFA-gap check skipped — needs the Entra ID P2 MFA registration report.</li>"
    if not sign_in_ok:
        notes += "<li>Stale-account check skipped — needs Entra ID P2 sign-in activity.</li>"
    notes_html = f'<ul class="notes">{notes}</ul>' if notes else ""

    return f"""<!doctype html>
<html lang="en" data-palette="#c0362c,#c2410c,#b45309,#15803d">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ENTRA-LENS — Identity findings</title>
<style>
  :root {{
    --bg:#f6f7f9; --surface:#ffffff; --ink:#15181e; --muted:#5b6472; --border:#e4e7ec;
    --critical:#c0362c; --serious:#c2410c; --warning:#b45309; --good:#15803d; --neutral:#8a93a2;
    --track:#eef1f5;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0e1116; --surface:#161a21; --ink:#e8ebf0; --muted:#9aa3b2; --border:#262c36;
      --critical:#f0675b; --serious:#f08a4b; --warning:#e0a93a; --good:#53b981; --neutral:#7e8794;
      --track:#20262f;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:32px 16px 64px; }}
  header h1 {{ margin:0 0 4px; font-size:24px; letter-spacing:-0.01em; }}
  header .sub {{ color:var(--muted); font-size:13px; }}
  header .sub code {{ background:var(--track); padding:1px 6px; border-radius:4px; }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0; }}
  .tile {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px; }}
  .tile-num {{ font-size:30px; font-weight:650; letter-spacing:-0.02em; }}
  .tile-label {{ color:var(--muted); font-size:12px; margin-top:2px; }}
  h2 {{ font-size:15px; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted);
    margin:28px 0 12px; font-weight:600; }}
  .panel {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:8px 16px; }}
  .bar-row {{ display:grid; grid-template-columns:200px 1fr 36px 110px; align-items:center;
    gap:12px; padding:8px 0; border-bottom:1px solid var(--border); }}
  .bar-row:last-child {{ border-bottom:0; }}
  .bar-name {{ font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .bar-track {{ background:var(--track); border-radius:5px; height:12px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:5px; }}
  .bar-score {{ font-variant-numeric:tabular-nums; font-weight:650; text-align:right; }}
  .bar-tier {{ font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; }}
  .dot {{ width:9px; height:9px; border-radius:50%; display:inline-block; flex:none; }}
  .card {{ background:var(--surface); border:1px solid var(--border); border-radius:10px;
    padding:14px 16px; margin-bottom:12px; }}
  .card-head {{ display:flex; justify-content:space-between; align-items:center; }}
  .card-name {{ font-weight:600; font-size:14px; }}
  .card-score {{ color:#fff; font-weight:650; font-size:13px; padding:2px 10px; border-radius:20px; }}
  .finds {{ margin:10px 0 6px; padding-left:18px; }}
  .finds li {{ margin:3px 0; font-size:13px; }}
  .factors {{ color:var(--muted); font-size:12px; }}
  .notes {{ color:var(--muted); font-size:12px; padding-left:18px; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:28px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>ENTRA-LENS — Identity findings</h1>
    <div class="sub">Tenant <code>{esc(tenant)}</code> · snapshot <code>{esc(snap_name)}</code> · generated {today}</div>
  </header>

  <div class="tiles">{tiles_html}</div>

  <h2>Risk by identity</h2>
  <div class="panel">{rows}</div>

  <h2>Flagged accounts — detail</h2>
  {detail or '<div class="panel">No accounts flagged.</div>'}

  {f'<h2>Coverage notes</h2><div class="panel">{notes_html}</div>' if notes_html else ''}

  <footer>
    ENTRA-LENS · read-only analysis of a lab tenant · risk score is additive and explainable
    (role sensitivity, standing privilege, MFA gaps, stale accounts).
  </footer>
</div>
</body>
</html>"""


def main():
    snapshot, snap_path = load_latest_snapshot()
    identities, mfa_ok = build_identities(snapshot)
    _, sign_in_ok = section(snapshot, "sign_ins")
    results = analyze(identities, mfa_ok, sign_in_ok)

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.join(REPORT_DIR, f"dashboard-{stamp}.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(page(results, snapshot, os.path.basename(snap_path), mfa_ok, sign_in_ok))
    print(f"Dashboard written to {out}")
    print("Open it in your browser (double-click the file).")


if __name__ == "__main__":
    main()
