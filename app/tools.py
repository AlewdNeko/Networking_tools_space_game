"""
Mission Control tools - three small, dependency-free network checks that
the UI presents as space missions:

  ping        "Sonar Ping"     - is the planet alive, and how far away?
  portscan    "Planet Survey"  - which landing sites (TCP ports) are open?
  traceroute  "Flight Path"    - which waypoints (hops) lead there?

Safety: ping and traceroute may target any host. The port survey only
targets private / loopback / link-local addresses, i.e. networks you
control - it refuses public internet hosts.
"""

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

import portnames

IS_WINDOWS = platform.system() == "Windows"
# hide the console window flash on Windows when shelling out
_NOWINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-:]{0,251}[A-Za-z0-9])?$")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 515, 631,
    993, 995, 1433, 1723, 3306, 3389, 5000, 5060, 5432, 5900, 6379, 8000,
    8080, 8443, 9100,
]


def clean_host(host):
    """Return a safe host string or raise ValueError. Rejects anything
    that could be mistaken for a command-line flag or shell syntax."""
    host = (host or "").strip()
    if not host or host.startswith("-") or not _HOST_RE.match(host):
        raise ValueError("Enter a valid IP address or hostname")
    return host


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        raise ValueError(f"Could not resolve {host}")


def is_local_network(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local


_TIME_RE = re.compile(r"time\s*([=<])\s*([\d.]+)\s*ms", re.I)


def ping(host, count=4):
    host = clean_host(host)
    ip = resolve(host)
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 2 + 5,
                             creationflags=_NOWINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    times = [float(m.group(2)) if m.group(1) == "=" else 0.5
             for m in _TIME_RE.finditer(out)]
    return {
        "host": host, "ip": ip, "sent": count, "received": len(times),
        "loss_pct": round(100 * (count - len(times)) / count),
        "min": min(times) if times else None,
        "avg": round(sum(times) / len(times), 1) if times else None,
        "max": max(times) if times else None,
    }


def port_scan(host, ports=None):
    host = clean_host(host)
    ip = resolve(host)
    if not is_local_network(ip):
        raise ValueError("Planet Survey only targets networks you control "
                         "(private / local addresses), not public hosts")
    ports = ports or COMMON_PORTS

    def probe(port):
        try:
            with socket.create_connection((ip, port), timeout=0.6):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        found = sorted(p for p in pool.map(probe, ports) if p)
    return {
        "host": host, "ip": ip, "scanned": len(ports),
        "open": [{"port": p, "service": portnames.service_for_port(p) or "unknown"}
                 for p in found],
    }


_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MS_RE = re.compile(r"([\d.]+)\s*ms|<\s*1\s*ms", re.I)


def parse_traceroute(text):
    hops = []
    for line in text.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ip = _IP_RE.search(rest)
        times = [float(t.group(1)) if t.group(1) else 0.5 for t in _MS_RE.finditer(rest)]
        hops.append({
            "hop": int(m.group(1)),
            "ip": ip.group(1) if ip else None,
            "ms": round(sum(times) / len(times), 1) if times else None,
        })
    return hops


def traceroute(host, max_hops=20):
    host = clean_host(host)
    ip = resolve(host)
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * 4 + 10,
                             creationflags=_NOWINDOW).stdout
    except FileNotFoundError:
        raise ValueError("traceroute is not available on this system")
    except subprocess.TimeoutExpired:
        out = ""
    return {"host": host, "ip": ip, "hops": parse_traceroute(out)}


TOOLS = {"ping": ping, "portscan": port_scan, "traceroute": traceroute}


def run(tool, host):
    """Entry point used by the server. Always returns a dict; errors are
    reported as {"error": "..."} so a bad target never breaks the stream."""
    fn = TOOLS.get(tool)
    if not fn:
        return {"error": "Unknown tool"}
    try:
        return fn(host)
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:  # never let a tool crash the backend
        return {"error": f"{type(e).__name__}: {e}"}
