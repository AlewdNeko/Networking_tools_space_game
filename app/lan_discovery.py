"""
LAN device discovery for Sol View: finds every device currently alive on
the local subnet, the same way tools like nmap -sn / Fing / Advanced IP
Scanner do it - an active sweep (so devices that haven't talked to this
host recently still show up), then reading the OS's own ARP table for
IP -> MAC mappings, then a MAC vendor lookup so each device reads as
"Apple, Inc." or "Samsung Electronics" instead of a bare address.

This only touches devices on your own local subnet - it does not send
anything outside your network, and does not intercept or alter any
device's traffic. It's the discovery step only; nothing here captures
another device's packets.
"""

import ipaddress
import pickle
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OUI_PKL_PATH = Path(__file__).parent / "geodata" / "oui.pkl"
_oui_table = None


def _load_oui():
    global _oui_table
    if _oui_table is None:
        try:
            with open(OUI_PKL_PATH, "rb") as f:
                _oui_table = pickle.load(f)
        except FileNotFoundError:
            _oui_table = {}
    return _oui_table


def vendor_for_mac(mac):
    """mac like 'aa:bb:cc:dd:ee:ff' -> vendor name, or None."""
    if not mac:
        return None
    table = _load_oui()
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return table.get(prefix)


def get_local_network_info():
    """Returns (own_ip, netmask, gateway_ip) for the real uplink adapter,
    or (None, None, None) if it can't be determined.

    On a machine with only one active adapter this is trivial, but a
    machine with a VPN connected or multiple NICs (common in an office)
    can have several adapters with routable-looking IPs. Picking
    "whichever psutil lists first" would silently sweep the wrong
    network. Instead, this parses every adapter block from `ipconfig`
    and picks the one that actually has a Default Gateway set - virtual/
    isolated adapters (loopback, link-local, most VPN tunnel interfaces)
    don't have one, so this reliably lands on the real LAN connection.
    """
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        ).stdout
    except Exception:
        return None, None, None

    blocks = re.split(r"\r?\n\r?\n", out)
    for block in blocks:
        gw_match = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", block)
        if not gw_match:
            continue
        ip_match = re.search(r"IPv4 Address[ .]*:\s*([\d.]+)", block)
        mask_match = re.search(r"Subnet Mask[ .]*:\s*([\d.]+)", block)
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1), gw_match.group(1)

    return None, None, None


def _subnet_hosts(own_ip, netmask):
    try:
        iface = ipaddress.ip_interface(f"{own_ip}/{netmask}")
        network = iface.network
        # cap sweep size for safety/speed - a /24 (254 hosts) is the
        # common case; anything bigger just sweeps the first 512 hosts
        hosts = list(network.hosts())
        return hosts[:512]
    except ValueError:
        return []


def _ping(ip_str, timeout_ms=300):
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), str(ip_str)],
            capture_output=True, timeout=(timeout_ms / 1000) + 1,
        )
    except Exception:
        pass


def _read_arp_table():
    """Returns {ip: mac} from the OS ARP cache."""
    result = {}
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            m = re.match(r"\s*([\d.]+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if m:
                ip, mac, kind = m.groups()
                if kind.lower() == "dynamic":
                    result[ip] = mac.replace("-", ":").lower()
    except Exception:
        pass
    return result


def discover_devices(max_workers=64):
    """Active sweep of the local subnet. Returns a list of
    {ip, mac, vendor, is_self, is_gateway} dicts. Takes a few seconds.

    Runs two passes: phones and tablets in a WiFi power-saving state
    often miss the first ping, so addresses that didn't answer get one
    more try before being written off."""
    own_ip, netmask, gateway_ip = get_local_network_info()
    if not own_ip:
        return [], None, None

    hosts = _subnet_hosts(own_ip, netmask)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(_ping, hosts))

    arp_table = _read_arp_table()

    missing = [h for h in hosts if str(h) not in arp_table]
    if missing:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            list(pool.map(lambda h: _ping(h, timeout_ms=500), missing))
        arp_table = _read_arp_table()

    devices = []
    for ip, mac in arp_table.items():
        try:
            if ipaddress.ip_address(ip) not in ipaddress.ip_interface(f"{own_ip}/{netmask}").network:
                continue
        except ValueError:
            continue
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor_for_mac(mac),
            "is_self": ip == own_ip,
            "is_gateway": ip == gateway_ip,
        })

    # make sure our own host and the gateway are always present even if
    # ARP didn't happen to have them cached
    if not any(d["is_self"] for d in devices):
        devices.append({"ip": own_ip, "mac": None, "vendor": None,
                         "is_self": True, "is_gateway": False})
    if gateway_ip and not any(d["is_gateway"] for d in devices):
        devices.append({"ip": gateway_ip, "mac": None, "vendor": None,
                         "is_self": False, "is_gateway": True})

    return devices, own_ip, gateway_ip
