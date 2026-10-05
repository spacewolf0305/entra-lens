"""
ENTRA-LENS lab seeder.

Populates an EMPTY lab tenant with test users, groups and role assignments that
contain deliberate, realistic problems for the analysis engine to find. Run this
ONCE against a throwaway lab tenant you own.

This script is lab setup, not part of the product, so it needs WRITE permissions
that the read-only collector does not. Grant the seeding app (or a second app):
  User.ReadWrite.All
  Group.ReadWrite.All
  RoleManagement.ReadWrite.Directory

The deliberate problems it plants:
  - Over-privileged roles : accounts given Global Admin / Privileged Role Admin
                            whose names imply they only need read access.
  - Admins without MFA    : every seeded user starts with no MFA registered.
  - Stale accounts        : users created that never sign in.
  - Standing privilege    : all assignments are permanent (not PIM-eligible).

Note on Microsoft's protection of privileged roles: assigning Global
Administrator via an app can be refused unless the seeding app itself holds a
privileged role. The script catches that, reports it, and you can either grant
the seeding app the "Privileged Role Administrator" role or assign those one or
two roles by hand in the portal. The lower-privilege over-privilege examples
seed without that.
"""

import os
import time
from graph_client import client_from_env, GraphError

# Well-known built-in role template IDs (stable across every tenant).
ROLES = {
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Groups Administrator": "fdd7a751-b60b-444a-984c-02652fe8fa1c",
    "Global Reader": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
}

# displayName, mailNickname, intended role (or None), and the problem it seeds.
PEOPLE = [
    ("Alice Admin",       "alice.admin",      "Global Administrator",          "admin without MFA"),
    ("Bob Reporting",     "bob.reporting",    "Global Administrator",          "OVER-PRIVILEGED: name implies read-only"),
    ("Carol Helpdesk",    "carol.helpdesk",   "Helpdesk Administrator",        "appropriate (control case)"),
    ("Dave Security",     "dave.security",    "Privileged Role Administrator", "OVER-PRIVILEGED: sensitive standing role"),
    ("Erin Analyst",      "erin.analyst",     "Global Reader",                 "appropriate read-only (control case)"),
    ("Frank Stale",       "frank.stale",      None,                            "stale account: created, never signs in"),
    ("Grace Contractor",  "grace.contractor", "User Administrator",            "OVER-PRIVILEGED: contractor with standing admin"),
    ("Svc Automation",    "svc.automation",   "Groups Administrator",          "service account with permanent privilege"),
]

GROUPS = ["IT Admins", "All Staff"]


def default_domain(graph):
    orgs = graph.get_all("/organization")
    for org in orgs:
        for dom in org.get("verifiedDomains", []):
            if dom.get("isDefault"):
                return dom["name"]
    raise SystemExit("Could not determine the tenant default domain.")


def ensure_group(graph, name):
    try:
        created = graph.post(
            "/groups",
            {
                "displayName": name,
                "mailEnabled": False,
                "mailNickname": name.replace(" ", "").lower(),
                "securityEnabled": True,
            },
        )
        print(f"  [+] group '{name}'")
        return created.get("id")
    except GraphError as e:
        print(f"  [=] group '{name}' not created ({e.status})")
        return None


def get_user_id(graph, upn):
    """Look up an existing user's id by UPN (used on re-runs)."""
    try:
        return graph.get(f"/users/{upn}?$select=id").get("id")
    except GraphError:
        return None


def ensure_user(graph, display, nickname, domain, password):
    upn = f"{nickname}@{domain}"
    try:
        created = graph.post(
            "/users",
            {
                "accountEnabled": True,
                "displayName": display,
                "mailNickname": nickname,
                "userPrincipalName": upn,
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": False,
                    "password": password,
                },
            },
        )
        print(f"  [+] user {upn}")
        return created.get("id")
    except GraphError as e:
        if e.status == 400 and "already exist" in str(e).lower():
            # On a re-run the user is there already; fetch its id so roles can still be assigned.
            print(f"  [=] user {upn} already exists")
            return get_user_id(graph, upn)
        print(f"  [!] user {upn} failed ({e.status})")
        return None


def assign_role(graph, principal_id, role_name):
    """Assign a directory role, retrying on 404 (newly created principals replicate with a lag)."""
    if not principal_id:
        return
    for attempt in range(4):
        try:
            graph.post(
                "/roleManagement/directory/roleAssignments",
                {
                    "roleDefinitionId": ROLES[role_name],
                    "principalId": principal_id,
                    "directoryScopeId": "/",
                },
            )
            print(f"      -> assigned {role_name}")
            return
        except GraphError as e:
            if e.status == 409 or "already exist" in str(e).lower():
                print(f"      -> {role_name} already assigned")
                return
            if e.status == 404 and attempt < 3:
                time.sleep(10)  # wait for the principal to replicate, then retry
                continue
            print(f"      -> could NOT assign {role_name} ({e.status}); "
                  f"assign it by hand in the portal, or grant the seeding app a privileged role")
            return


def main():
    password = os.environ.get("SEED_USER_PASSWORD", "Lab-Passw0rd-Change-Me!")
    graph = client_from_env()
    domain = default_domain(graph)
    print(f"Seeding lab tenant on domain @{domain}\n")

    print("Groups:")
    for g in GROUPS:
        ensure_group(graph, g)

    print("\nUsers and roles:")
    for display, nickname, role, problem in PEOPLE:
        uid = ensure_user(graph, display, nickname, domain, password)
        if role:
            assign_role(graph, uid, role)
        print(f"      problem seeded: {problem}")

    print("\nDone. Now run:  python collector.py")
    print("Reminder: no MFA is registered for any seeded user - that absence is itself a finding.")


if __name__ == "__main__":
    main()
