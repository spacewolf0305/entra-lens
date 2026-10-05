"""
Minimal Microsoft Graph client for ENTRA-LENS.

Kept deliberately small and dependency-light (msal + requests) so every call is
visible and explainable in an interview. Uses the OAuth2 client-credentials
flow: the app authenticates as itself with its own permissions, no user present.
"""

import os
import time
import requests
import msal

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# .default means "every application permission already consented for this app".
SCOPES = ["https://graph.microsoft.com/.default"]


class GraphError(Exception):
    """Raised for a non-recoverable Graph response (so callers can catch 403s)."""

    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class GraphClient:
    def __init__(self, tenant_id, client_id, client_secret, access_token=None):
        self.tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        # A pre-obtained Graph token (e.g. minted by CI via OIDC federation).
        # When present, no client secret is used at all.
        self._static_token = access_token
        self._app = None  # built lazily on first token request (no network at construction)
        self._token = None
        self._token_expires_at = 0

    # --- auth -------------------------------------------------------------
    def _ensure_app(self):
        if self._app is None:
            self._app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
                client_credential=self._client_secret,
            )
        return self._app

    def _access_token(self):
        # A CI-provided token (OIDC) short-circuits MSAL entirely.
        if self._static_token:
            return self._static_token
        # Reuse the cached token until ~60s before it expires.
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        result = self._ensure_app().acquire_token_for_client(scopes=SCOPES)
        if "access_token" not in result:
            raise GraphError(
                401,
                f"Token request failed: {result.get('error')} - "
                f"{result.get('error_description')}",
            )
        self._token = result["access_token"]
        self._token_expires_at = time.time() + int(result.get("expires_in", 3600))
        return self._token

    def _headers(self, extra=None):
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        if extra:
            headers.update(extra)
        return headers

    # --- requests ---------------------------------------------------------
    def get(self, path, params=None, advanced=False):
        """Single GET. `path` may be a relative path or a full URL (nextLink)."""
        url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
        # Some queries ($count, advanced $filter) require the ConsistencyLevel header.
        extra = {"ConsistencyLevel": "eventual"} if advanced else None
        for attempt in range(5):
            resp = requests.get(url, headers=self._headers(extra), params=params, timeout=60)
            if resp.status_code == 429:  # throttled -> honour Retry-After
                wait = int(resp.headers.get("Retry-After", 5))
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                raise GraphError(resp.status_code, f"{resp.status_code} on {url}: {resp.text[:400]}")
            return resp.json()
        raise GraphError(429, f"Throttled repeatedly on {url}")

    def get_all(self, path, params=None, advanced=False):
        """GET that follows @odata.nextLink and returns the combined 'value' list."""
        items = []
        page = self.get(path, params=params, advanced=advanced)
        items.extend(page.get("value", []))
        while page.get("@odata.nextLink"):
            page = self.get(page["@odata.nextLink"])
            items.extend(page.get("value", []))
        return items

    def post(self, path, body):
        url = f"{GRAPH_BASE}{path}"
        resp = requests.post(
            url, headers=self._headers({"Content-Type": "application/json"}), json=body, timeout=60
        )
        if resp.status_code >= 400:
            raise GraphError(resp.status_code, f"{resp.status_code} on POST {url}: {resp.text[:400]}")
        return resp.json() if resp.text else {}


def client_from_env():
    """
    Build a GraphClient from the environment.

    Two modes:
      - CI / OIDC: GRAPH_ACCESS_TOKEN (+ TENANT_ID) is set, so no secret is needed.
      - Local: TENANT_ID / CLIENT_ID / CLIENT_SECRET from .env (client credentials).
    """
    from dotenv import load_dotenv

    load_dotenv()
    tenant = os.environ.get("TENANT_ID")
    token = os.environ.get("GRAPH_ACCESS_TOKEN")

    if token:
        if not tenant:
            raise SystemExit("GRAPH_ACCESS_TOKEN is set but TENANT_ID is missing.")
        return GraphClient(tenant, None, None, access_token=token)

    client = os.environ.get("CLIENT_ID")
    secret = os.environ.get("CLIENT_SECRET")
    missing = [n for n, v in [("TENANT_ID", tenant), ("CLIENT_ID", client), ("CLIENT_SECRET", secret)] if not v]
    if missing:
        raise SystemExit(f"Missing env vars: {', '.join(missing)}. Copy .env.example to .env and fill it in.")
    return GraphClient(tenant, client, secret)
