"""
ENTRA-LENS collector.

Reads the current state of an Entra ID tenant through Microsoft Graph and writes
one timestamped JSON snapshot to ./snapshots/. The analysis engine (Phase 2)
runs against these snapshots, so collection stays strictly read-only — this is
the least-privilege half of the project.

Required application permissions (admin-consented), all read-only:
  Directory.Read.All            users, groups, service principals
  RoleManagement.Read.Directory role definitions and assignments
  AuditLog.Read.All             sign-in and directory audit logs (premium tenant)

Endpoints that need an Entra ID P1/P2 licence (sign-in logs, MFA registration
report) are collected when available and skipped with a clear note otherwise, so
the collector still runs on a free tenant.
"""

import os
import json
import datetime as dt

from graph_client import client_from_env, GraphError

SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "snapshots")


def _try(label, fn):
    """Run a collection step; on a permission/premium error, record why and go on."""
    try:
        data = fn()
        print(f"  [ok]   {label}: {len(data)} records")
        return {"status": "ok", "count": len(data), "value": data}
    except GraphError as e:
        note = "needs an Entra ID P1/P2 licence or a missing permission" if e.status in (401, 403) else str(e)
        print(f"  [skip] {label}: {e.status} ({note})")
        return {"status": "skipped", "http_status": e.status, "note": note, "value": []}


def collect(graph):
    print("Collecting tenant snapshot...")

    users = _try(
        "users",
        lambda: graph.get_all(
            "/users",
            params={
                "$select": "id,displayName,userPrincipalName,accountEnabled,"
                "createdDateTime,userType,signInActivity",
                "$top": "999",
            },
        ),
    )
    # signInActivity silently needs premium; if the whole call failed, retry lean
    # so we still capture the user list on a free tenant.
    if users["status"] == "skipped":
        users = _try(
            "users (without signInActivity)",
            lambda: graph.get_all(
                "/users",
                params={
                    "$select": "id,displayName,userPrincipalName,accountEnabled,createdDateTime,userType",
                    "$top": "999",
                },
            ),
        )

    role_definitions = _try(
        "role definitions",
        lambda: graph.get_all("/roleManagement/directory/roleDefinitions"),
    )
    role_assignments = _try(
        "role assignments",
        lambda: graph.get_all(
            "/roleManagement/directory/roleAssignments",
            params={"$expand": "principal"},
        ),
    )
    groups = _try(
        "groups",
        lambda: graph.get_all("/groups", params={"$select": "id,displayName,securityEnabled,groupTypes"}),
    )
    service_principals = _try(
        "service principals",
        lambda: graph.get_all(
            "/servicePrincipals",
            params={"$select": "id,appId,displayName,servicePrincipalType,accountEnabled"},
        ),
    )
    sign_ins = _try(
        "sign-in logs (last 1000)",
        lambda: graph.get_all("/auditLogs/signIns", params={"$top": "1000"}),
    )
    directory_audits = _try(
        "directory audit logs (last 1000)",
        lambda: graph.get_all("/auditLogs/directoryAudits", params={"$top": "1000"}),
    )
    mfa_registration = _try(
        "MFA registration report",
        lambda: graph.get_all("/reports/authenticationMethods/userRegistrationDetails"),
    )

    return {
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tenant_id": graph.tenant_id,
        "users": users,
        "groups": groups,
        "role_definitions": role_definitions,
        "role_assignments": role_assignments,
        "service_principals": service_principals,
        "sign_ins": sign_ins,
        "directory_audits": directory_audits,
        "mfa_registration": mfa_registration,
    }


def save(snapshot):
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(SNAPSHOT_DIR, f"snapshot-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
    return path


def main():
    graph = client_from_env()
    snapshot = collect(graph)
    path = save(snapshot)
    print(f"\nSnapshot written to {path}")
    print("Summary:")
    for key in ("users", "groups", "role_assignments", "service_principals", "sign_ins"):
        section = snapshot[key]
        print(f"  {key:20s} {section['status']:8s} {section['count'] if section['status']=='ok' else '-'}")


if __name__ == "__main__":
    main()
