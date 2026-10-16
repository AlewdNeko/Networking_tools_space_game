"""
Offline IP -> country / organization lookup, built from the compiled
geodata/geo.pkl (see build_geodata.py). Pure in-memory binary search
over sorted IP-range tables - no network calls, no external services.

If an IP isn't covered by the offline data (rare - these tables are
exhaustive over the allocated address space), callers should fall back
to the RDAP live lookup in rdap_lookup.py.
"""

import bisect
import ipaddress
import pickle
from pathlib import Path

GEO_PKL_PATH = Path(__file__).parent / "geodata" / "geo.pkl"

_data = None


def _load():
    global _data
    if _data is None:
        with open(GEO_PKL_PATH, "rb") as f:
            _data = pickle.load(f)
    return _data


def _ip_to_int(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, None
    return int(ip), 4 if ip.version == 4 else 6


def _lookup(table, ip_int, version):
    starts = table["v4_starts"] if version == 4 else table["v6_starts"]
    labels = table["v4_labels"] if version == 4 else table["v6_labels"]
    if not starts:
        return None
    idx = bisect.bisect_right(starts, ip_int) - 1
    if idx < 0:
        return None
    return labels[idx]


def is_private_or_reserved(ip_str):
    """True for LAN/loopback/link-local/reserved addresses - these are
    never in the public ASN/country allocation tables, so looking them
    up there would return nonsense (nearest unrelated public range)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def country_for_ip(ip_str):
    """Returns a 2-letter country code, or None if not found offline."""
    if is_private_or_reserved(ip_str):
        return None
    data = _load()
    ip_int, version = _ip_to_int(ip_str)
    if ip_int is None:
        return None
    label = _lookup(data["country"], ip_int, version)
    if label in (None, "ZZ"):  # ZZ = DB-IP's "unknown/unallocated" marker
        return None
    return label


def org_for_ip(ip_str):
    """Returns (asn, organization_name), or None if not found offline."""
    if is_private_or_reserved(ip_str):
        return None
    data = _load()
    ip_int, version = _ip_to_int(ip_str)
    if ip_int is None:
        return None
    return _lookup(data["asn"], ip_int, version)
