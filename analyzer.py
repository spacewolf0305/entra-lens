"""
ENTRA-LENS analysis engine.

Reads the latest snapshot in ./snapshots and turns it into prioritized identity
findings: over-privilege (standing admin roles), MFA gaps, stale accounts, and an
explainable risk score per identity. Writes a console summary plus a Markdown and
JSON report into ./reports.

Runs entirely offline on the snapshot — no tenant calls, nothing uploaded.

Graceful degradation: MFA-gap and stale-account checks need the MFA registration
report and sign-in activity, which are Entra ID P1/P2 features. When the snapshot
shows those sections as skipped, the analyzer says so and still produces the
role-based findings and risk scores.
"""

import os
import re
import csv
import glob
import json
import datetime as dt

SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "snapshots")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
STALE_DAYS = 90

# Role privilege tiers. Points feed the risk score; READER roles are not treated
# as privileged, so a read-only account is never flagged for over-privilege.
TIER_POINTS = {"critical": 50, "high": 35, "medium": 20, "reader": 5, "other": 15}

ROLE_TIERS = {
    # critical — control plane
    "global administrator": "critical",
    "privileged role administrator": "critical",
    "privileged authentication administrator": "critical",
    # high — identity, security, and app management
    "security administrator": "high",
    "user administrator": "high",
    "authentication administrator": "high",
    "conditional access administrator": "high",
    "application administrator": "high",
    "cloud application administrator": "high",
    "exchange administrator": "high",
    "sharepoint administrator": "high",
    "intune administrator": "high",
    "hybrid identity administrator": "high",
    "password administrator": "high",
    # medium — scoped operational admin
    "helpdesk administrator": "medium",
    "groups administrator": "medium",
    "teams administrator": "medium",
    "billing administrator": "medium",
    "reports administrator": "medium",
    # reader — read-only
    "global reader": "reader",
    "security reader": "reader",
    "reports reader": "reader",
    "message center reader": "reader",
    "directory readers": "reader",
}


def tier_of(role_name):
    return ROLE_TIERS.get(role_name.lower(), "other")


# ---------------------------------------------------------------------------
def load_latest_snapshot(path=None):
    if path is None:
        files = sorted(glob.glob(os.path.join(SNAPSHOT_DIR, "snapshot-*.json")))
        if not files:
            raise SystemExit("No snapshot found in ./snapshots - run collector.py first.")
        path = files[-1]
    with open(path, encoding="utf-8") as f:
        return json.load(f), path


def section(snapshot, key):
    """Return (list, ok) for a snapshot section, tolerating skipped sections."""
    sec = snapshot.get(key, {})
    return sec.get("value", []), sec.get("status") == "ok"


# ---------------------------------------------------------------------------
def build_identities(snapshot):
    """One record per principal: who they are, the roles they hold, MFA and sign-in."""
    role_defs, _ = section(snapshot, "role_definitions")
    assignments, _ = section(snapshot, "role_assignments")
    users, _ = section(snapshot, "users")
    mfa_rows, mfa_ok = section(snapshot, "mfa_registration")

    def_name = {rd["id"]: rd.get("displayName", "Unknown role") for rd in role_defs}

    identities = {}

    def ensure(pid, display=None, upn=None, ptype="user"):
        rec = identities.setdefault(
            pid,
            {"id": pid, "displayName": display, "upn": upn, "type": ptype,
             "roles": [], "mfa_registered": None, "last_sign_in": None,
             "account_enabled": None, "user_type": None, "created": None},
        )
        if display and not rec["displayName"]:
            rec["displayName"] = display
        if upn and not rec["upn"]:
            rec["upn"] = upn
        return rec

    # Users first, so accounts with no roles are still evaluated (stale / MFA).
    for u in users:
        rec = ensure(u["id"], u.get("displayName"), u.get("userPrincipalName"), "user")
        rec["account_enabled"] = u.get("accountEnabled")
        rec["user_type"] = u.get("userType")
        rec["created"] = u.get("createdDateTime")
        sia = u.get("signInActivity") or {}
        rec["last_sign_in"] = sia.get("lastSignInDateTime")

    # Role assignments (principal is expanded in the collector query).
    for a in assignments:
        pid = a.get("principalId")
        if not pid:
            continue
        p = a.get("principal") or {}
        ptype = (p.get("@odata.type", "") or "").split(".")[-1] or "user"
        rec = ensure(pid, p.get("displayName"), p.get("userPrincipalName"), ptype)
        role_name = def_name.get(a.get("roleDefinitionId"), "Unknown role")
        rec["roles"].append({"name": role_name, "tier": tier_of(role_name),
                             "scope": a.get("directoryScopeId", "/")})

    # MFA registration report (P2): map isMfaRegistered onto identities.
    if mfa_ok:
        for m in mfa_rows:
            rec = identities.get(m.get("id"))
            if rec is not None:
                rec["mfa_registered"] = m.get("isMfaRegistered")

    return identities, mfa_ok


# ---------------------------------------------------------------------------
def highest_tier(roles):
    order = ["critical", "high", "medium", "reader", "other"]
    best = None
    for r in roles:
        if best is None or order.index(r["tier"]) < order.index(best):
            best = r["tier"]
    return best


def is_privileged(roles):
    """A role above read-only counts as privileged."""
    return any(r["tier"] in ("critical", "high", "medium", "other") for r in roles)


def looks_read_only(display, upn):
    """Heuristic: does the account's NAME imply it should only read?"""
    text = f"{display or ''} {upn or ''}".lower()
    return bool(re.search(r"report|analyst|read|viewer|audit|dashboard|bi\b", text))


def analyze(identities, mfa_ok, sign_in_ok):
    results = []
    for rec in identities.values():
        factors = []     # (label, points) making up the score
        findings = []    # human-readable finding strings
        score = 0
        priv = is_privileged(rec["roles"])
        top = highest_tier(rec["roles"]) if rec["roles"] else None

        # 1. Standing privileged role (active, not PIM-eligible).
        if priv:
            pts = TIER_POINTS.get(top, 15)
            score += pts
            factors.append((f"standing {top} role", pts))
            role_list = ", ".join(sorted({r["name"] for r in rec["roles"]
                                          if r["tier"] != "reader"}))
            findings.append(f"over-privilege: holds {role_list} as standing (not PIM) access")

        # 2. Over-privilege by name vs. role (reporting/analyst with real admin).
        if priv and top in ("critical", "high") and looks_read_only(rec["displayName"], rec["upn"]):
            score += 15
            factors.append(("name implies read-only but holds admin", 15))
            findings.append("over-privilege: name suggests a read-only function but account holds a powerful admin role")

        # 3. Multiple privileged roles.
        priv_roles = [r for r in rec["roles"] if r["tier"] != "reader"]
        if len(priv_roles) > 1:
            score += 10
            factors.append((f"{len(priv_roles)} privileged roles", 10))
            findings.append(f"over-privilege: {len(priv_roles)} privileged roles on one account")

        # 4. MFA gap on a privileged account (needs the P2 MFA report).
        if priv and mfa_ok:
            if rec["mfa_registered"] is False:
                score += 25
                factors.append(("privileged, no MFA", 25))
                findings.append("mfa-gap: privileged account with no MFA registered")

        # 5. Stale account (needs P2 sign-in activity).
        if sign_in_ok and rec["account_enabled"]:
            if rec["last_sign_in"] is None:
                score += 20
                factors.append(("enabled, never signed in", 20))
                findings.append("stale: enabled account that has never signed in")
            else:
                days = (dt.datetime.now(dt.timezone.utc) -
                        dt.datetime.fromisoformat(rec["last_sign_in"].replace("Z", "+00:00"))).days
                if days > STALE_DAYS:
                    score += 15
                    factors.append((f"no sign-in in {days} days", 15))
                    findings.append(f"stale: no interactive sign-in in {days} days")

        # 6. Guest account with privilege.
        if priv and rec["user_type"] == "Guest":
            score += 10
            factors.append(("guest with privilege", 10))
            findings.append("guest account holding a privileged role")

        rec["score"] = min(score, 100)
        rec["factors"] = factors
        rec["findings"] = findings
        rec["top_tier"] = top
        results.append(rec)

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
def write_reports(results, snapshot, snap_path, mfa_ok, sign_in_ok):
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    flagged = [r for r in results if r["findings"]]
    priv_count = sum(1 for r in results if is_privileged(r["roles"]))

    # ---- console ----
    print("\nENTRA-LENS findings  (source: %s)\n" % os.path.basename(snap_path))
    print(f"  identities analyzed : {len(results)}")
    print(f"  privileged accounts : {priv_count}")
    print(f"  accounts flagged    : {len(flagged)}")
    if not mfa_ok:
        print("  note: MFA-gap check skipped - needs the Entra ID P2 MFA registration report")
    if not sign_in_ok:
        print("  note: stale-account check skipped - needs Entra ID P2 sign-in activity")
    print("\n  risk  account                         top role    findings")
    print("  ----  ------------------------------  ----------  --------")
    for r in results:
        name = (r["upn"] or r["displayName"] or r["id"])[:30]
        print(f"  {r['score']:>4}  {name:<30}  {str(r['top_tier'] or '-'):<10}  "
              f"{len(r['findings'])}")

    # ---- JSON ----
    json_path = os.path.join(REPORT_DIR, f"findings-{stamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
             "snapshot": os.path.basename(snap_path),
             "tenant_id": snapshot.get("tenant_id"),
             "summary": {"identities": len(results), "privileged": priv_count,
                         "flagged": len(flagged),
                         "mfa_evaluated": mfa_ok, "sign_in_evaluated": sign_in_ok},
             "identities": [
                 {"account": r["upn"] or r["displayName"], "type": r["type"],
                  "score": r["score"], "top_tier": r["top_tier"],
                  "roles": sorted({x["name"] for x in r["roles"]}),
                  "factors": r["factors"], "findings": r["findings"]}
                 for r in results]},
            f, indent=2, ensure_ascii=False)

    # ---- Markdown ----
    md_path = os.path.join(REPORT_DIR, f"report-{stamp}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# ENTRA-LENS identity findings\n\n")
        f.write(f"- Snapshot: `{os.path.basename(snap_path)}`\n")
        f.write(f"- Generated: {dt.date.today().isoformat()}\n")
        f.write(f"- Identities analyzed: **{len(results)}** · "
                f"privileged: **{priv_count}** · flagged: **{len(flagged)}**\n")
        if not mfa_ok:
            f.write("- _MFA-gap check skipped (needs Entra ID P2 MFA report)._\n")
        if not sign_in_ok:
            f.write("- _Stale-account check skipped (needs Entra ID P2 sign-in activity)._\n")
        f.write("\n## Ranked identities\n\n")
        f.write("| Risk | Account | Top role | Findings |\n|---:|---|---|---|\n")
        for r in results:
            f.write(f"| {r['score']} | {r['upn'] or r['displayName']} | "
                    f"{r['top_tier'] or '-'} | {len(r['findings'])} |\n")
        f.write("\n## Detail\n\n")
        for r in results:
            if not r["findings"]:
                continue
            f.write(f"### {r['upn'] or r['displayName']}  — risk {r['score']}\n\n")
            for fnd in r["findings"]:
                f.write(f"- {fnd}\n")
            f.write("\n  _score_: " +
                    ", ".join(f"{lbl} (+{pts})" for lbl, pts in r["factors"]) + "\n\n")

    print(f"\n  reports written:\n    {md_path}\n    {json_path}")
    return md_path, json_path


# ---------------------------------------------------------------------------
def main():
    snapshot, snap_path = load_latest_snapshot()
    identities, mfa_ok = build_identities(snapshot)
    _, sign_in_ok = section(snapshot, "sign_ins")
    results = analyze(identities, mfa_ok, sign_in_ok)
    write_reports(results, snapshot, snap_path, mfa_ok, sign_in_ok)


if __name__ == "__main__":
    main()
