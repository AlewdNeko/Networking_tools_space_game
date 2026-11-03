"""
Reverse-DNS hostname resolution for remote IPs - the same thing Windows'
own Resource Monitor does in its Network tab (it shows e.g.
"pw-in-f95.1e100.net" instead of a raw IP). Uses the OS's own resolver
(socket.gethostbyaddr), which checks the local DNS cache first, so
repeat lookups for an IP you've already resolved elsewhere (browser,
Resource Monitor, etc.) are often instant.

Every result (including failures) is cached in memory for the life of
the process, so each unique IP only triggers one resolution attempt.
"""

import socket

_cache = {}


def lookup(ip_str, timeout=2.0):
    """Returns the resolved hostname, or None if it doesn't reverse-resolve.
    Cached - safe to call repeatedly for the same IP."""
    if ip_str in _cache:
        return _cache[ip_str]

    result = None
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        result = hostname
    except (socket.herror, socket.gaierror, OSError):
        result = None
    finally:
        socket.setdefaulttimeout(old_timeout)

    _cache[ip_str] = result
    return result
