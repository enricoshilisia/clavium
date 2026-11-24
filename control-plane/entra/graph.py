"""A small Microsoft Graph client (standard library only).

Clavium's Entra app is multi-tenant and uses application permissions:
  User.Read.All          names, emails, whether the account is enabled
  GroupMember.Read.All   groups and who is in them
Both are read-only. A customer's admin grants them once through the
admin consent screen; Clavium then gets tokens for that tenant with the
client credentials flow. Nothing is ever written to the customer's
directory, and no user ever signs in through this path.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings
from django.core.cache import cache


class GraphError(Exception):
    def __init__(self, message, status=None, code=""):
        super().__init__(message)
        self.status = status
        self.code = code


def configured() -> bool:
    return bool(settings.CLAVIUM_MS_CLIENT_ID and settings.CLAVIUM_MS_CLIENT_SECRET)


def admin_consent_url(redirect_uri: str, state: str) -> str:
    q = urllib.parse.urlencode(
        {
            "client_id": settings.CLAVIUM_MS_CLIENT_ID,
            "scope": "https://graph.microsoft.com/.default",
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    return f"{settings.CLAVIUM_MS_AUTHORITY}/organizations/v2.0/adminconsent?{q}"


def _request(method, url, *, data=None, headers=None, timeout=20):
    body = None
    headers = dict(headers or {})
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b"{}")
        except ValueError:
            payload = {}
        return e.code, dict(e.headers or {}), payload
    except (urllib.error.URLError, TimeoutError) as e:
        raise GraphError(f"Could not reach Microsoft: {e}") from e


class GraphClient:
    """Graph calls for one customer tenant."""

    PAGE = 999

    def __init__(self, tenant_id: str):
        if not configured():
            raise GraphError("Microsoft 365 integration is not configured on this server.")
        self.tenant_id = tenant_id

    # ---- auth ----
    def _token(self) -> str:
        key = f"entra-token:{self.tenant_id}"
        tok = cache.get(key)
        if tok:
            return tok
        status, _, body = _request(
            "POST",
            f"{settings.CLAVIUM_MS_AUTHORITY}/{urllib.parse.quote(self.tenant_id)}/oauth2/v2.0/token",
            data={
                "client_id": settings.CLAVIUM_MS_CLIENT_ID,
                "client_secret": settings.CLAVIUM_MS_CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        if status != 200 or "access_token" not in body:
            code = body.get("error", "")
            desc = (body.get("error_description") or "").split("\r\n")[0]
            if code in ("unauthorized_client", "invalid_client") or "AADSTS7000229" in desc or "AADSTS65001" in desc:
                msg = "Clavium no longer has permission in this Microsoft 365 tenant. Connect again to re-approve it."
            else:
                msg = f"Microsoft refused the sign-in ({code or status}). {desc}".strip()
            raise GraphError(msg, status=status, code=code)
        cache.set(key, body["access_token"], max(60, int(body.get("expires_in", 3600)) - 300))
        return body["access_token"]

    def _get(self, path_or_url: str, *, params=None, eventual=False):
        url = path_or_url if path_or_url.startswith("https://") else f"{settings.CLAVIUM_MS_GRAPH}/v1.0{path_or_url}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        if eventual:
            headers["ConsistencyLevel"] = "eventual"
        for attempt in range(5):
            status, resp_headers, body = _request("GET", url, headers=headers)
            if status == 200:
                return body
            if status in (429, 503, 504) and attempt < 4:
                time.sleep(min(int(resp_headers.get("Retry-After", 2 ** attempt) or 1), 30))
                continue
            err = body.get("error", {}) if isinstance(body, dict) else {}
            if status == 401:
                cache.delete(f"entra-token:{self.tenant_id}")
            if status == 403:
                raise GraphError("Clavium is missing a Microsoft permission. Connect again so an admin can approve it.", status, err.get("code", ""))
            if status == 404:
                raise GraphError("Not found in Microsoft 365 (was it deleted?).", status, err.get("code", ""))
            raise GraphError(f"Microsoft Graph error {status}: {err.get('message', '')}".strip(), status, err.get("code", ""))
        raise GraphError("Microsoft Graph kept throttling the request. Try again in a few minutes.", 429)

    def _all(self, path, params=None, eventual=False, limit=100_000):
        out = []
        body = self._get(path, params=params, eventual=eventual)
        while True:
            out.extend(body.get("value", []))
            nxt = body.get("@odata.nextLink")
            if not nxt or len(out) >= limit:
                return out
            body = self._get(nxt, eventual=eventual)

    # ---- reads ----
    def check(self) -> None:
        """Proves consent works: one cheap call needing each permission."""
        self._get("/users", params={"$top": 1, "$select": "id"})
        self._get("/groups", params={"$top": 1, "$select": "id"})

    def search_groups(self, query: str, limit: int = 25):
        params = {"$select": "id,displayName,description,mail", "$top": limit, "$count": "true", "$orderby": "displayName"}
        query = query.replace('"', "").strip()
        if query:
            params["$search"] = f'"displayName:{query}"'
        body = self._get("/groups", params=params, eventual=True)
        return [{"id": g["id"], "name": g.get("displayName") or g["id"], "description": g.get("description") or "", "mail": g.get("mail") or ""} for g in body.get("value", [])]

    def group(self, group_id: str):
        g = self._get(f"/groups/{urllib.parse.quote(group_id)}", params={"$select": "id,displayName"})
        return {"id": g["id"], "name": g.get("displayName") or g["id"]}

    def group_users(self, group_id: str):
        """Every user in the group, including through nested groups."""
        users = self._all(
            f"/groups/{urllib.parse.quote(group_id)}/transitiveMembers/microsoft.graph.user",
            params={"$select": "id,displayName,mail,userPrincipalName,accountEnabled,userType", "$top": self.PAGE},
        )
        return [
            {
                "id": u["id"],
                "name": u.get("displayName") or "",
                "email": (u.get("mail") or u.get("userPrincipalName") or "").strip().lower(),
                "enabled": u.get("accountEnabled") is not False,
                "guest": (u.get("userType") or "").lower() == "guest",
            }
            for u in users
        ]


def client_for(tenant_id: str) -> GraphClient:
    """Indirection so tests can swap in a fake."""
    return GraphClient(tenant_id)
