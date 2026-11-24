"""Have I Been Pwned breached-account lookups (server side, needs a key).

Password checks do not use this: they run on the person's device with the
free k-anonymity range API and never send a password or full hash.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings


class HibpError(Exception):
    pass


def configured() -> bool:
    return bool(settings.CLAVIUM_HIBP_API_KEY)


def breaches_for(email: str) -> list:
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    req = urllib.request.Request(url, headers={"hibp-api-key": settings.CLAVIUM_HIBP_API_KEY, "user-agent": "Clavium-Breach-Monitor"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read() or b"[]")
                break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            if e.code == 429 and attempt < 2:
                time.sleep(min(int(e.headers.get("retry-after", "7") or 7), 60))
                continue
            if e.code in (401, 403):
                raise HibpError("the Have I Been Pwned API key was refused")
            raise HibpError(f"Have I Been Pwned answered {e.code}")
        except (urllib.error.URLError, TimeoutError) as e:
            raise HibpError(f"could not reach Have I Been Pwned: {e}")
    else:
        raise HibpError("Have I Been Pwned kept rate limiting")
    out = [
        {
            "name": b.get("Name", ""),
            "title": b.get("Title") or b.get("Name", ""),
            "domain": b.get("Domain", ""),
            "date": b.get("BreachDate", ""),
            "data": b.get("DataClasses", [])[:12],
        }
        for b in data
        if not b.get("IsSpamList") and not b.get("IsFabricated")
    ]
    out.sort(key=lambda b: b["date"], reverse=True)
    return out
