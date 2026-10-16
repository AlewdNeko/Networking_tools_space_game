"""
Live RDAP fallback - only used when an IP isn't covered by the bundled
offline database (geolookup.py), which should be rare since the DB-IP
Lite tables are exhaustive over the public address space. RDAP is the
modern, standard, keyless successor to WHOIS; rdap.org transparently
redirects each query to the correct regional registry (ARIN/RIPE/APNIC/
LACNIC/AFRINIC).

Every result (including failures) is cached in memory, so a given IP is
only ever looked up once per run - repeat packets to/from the same host
never trigger another network call.
"""

import json
import urllib.request

RDAP_TIMEOUT = 3.0
_cache = {}


def _fetch(ip_str):
    url = f"https://rdap.org/ip/{ip_str}"
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _extract_org(data):
    for entity in data.get("entities", []):
        vcard = entity.get("vcardArray")
        if not vcard or len(vcard) < 2:
            continue
        for item in vcard[1]:
            if item and item[0] == "fn" and len(item) >= 4 and item[3]:
                return str(item[3])
    return data.get("name")  # short registry handle as a last resort


def lookup(ip_str):
    """Returns {"country": str|None, "org": str|None} or None on failure.
    Cached - safe to call repeatedly for the same IP."""
    if ip_str in _cache:
        return _cache[ip_str]

    result = None
    try:
        data = _fetch(ip_str)
        country = data.get("country")
        org = _extract_org(data)
        if country or org:
            result = {"country": country, "org": org}
    except Exception:
        result = None

    _cache[ip_str] = result
    return result
