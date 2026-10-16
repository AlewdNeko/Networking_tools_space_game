"""
THE GATE - backend.

Real per-packet network visibility, the same way tools like TCPView or
Wireshark get it:

  1. A packet-capture layer (WinDivert, via pydivert) sniffs real IP
     packets as they cross the network stack - this requires
     Administrator privileges on Windows. Capture is read-only (SNIFF
     mode): packets are copied to us and continue on their way
     unmodified, so this never blocks or alters actual traffic.
  2. A live connection table (psutil.net_connections) is refreshed
     continuously and maps each (protocol, local ip:port, remote
     ip:port) tuple to the exact owning process - the same table
     netstat/TCPView read. A short grace window keeps recently-closed
     connections matchable too, since fast request/response traffic can
     otherwise close before the next refresh.
  3. Every captured packet is matched against that table by its real
     4-tuple, so each one is attributed to its real process - not a
     guess, not a random sample.
  4. Every packet's remote IP is enriched with country + organization
     from a bundled offline database (DB-IP Lite - no network calls),
     with a live RDAP lookup (the modern, keyless WHOIS successor) as a
     background fallback only for the rare IP that database doesn't
     cover. Remote port is matched against well-known service names.

If packet capture isn't available (not running as Administrator, or
pydivert/WinDivert failed to load), this falls back to aggregate OS
counters with no per-packet attribution, and tells the frontend so the
UI can say so honestly instead of pretending it has exact data it doesn't.
"""

import asyncio
import json
import os
import queue
import socket as socket_module
import threading
import time
import uuid

import psutil
import websockets

import geolookup
import history
import hostname_lookup
import lan_discovery
import portnames
import rdap_lookup

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False

POLL_INTERVAL = 0.1
HOST = "localhost"
PORT = 8765
CONN_TABLE_REFRESH = 0.1
CONN_TABLE_GRACE = 2.0  # seconds a closed connection stays matchable
DEVICE_SCAN_INTERVAL = 25.0  # seconds between LAN device sweeps
BLOCK_RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "block_rules.json")

_proc_name_cache = {}

# ---- Sol View: periodic LAN device discovery (Sun = router, planets = devices) ----

device_list = []
gateway_ip_cache = None
device_list_lock = threading.Lock()
_known_device_ips = set()  # for first-seen detection, this run only


def device_discovery_worker():
    global gateway_ip_cache
    first_scan = True
    while not _stop.is_set():
        try:
            devices, own_ip, gateway_ip = lan_discovery.discover_devices()
            with device_list_lock:
                device_list[:] = devices
                gateway_ip_cache = gateway_ip

            # log newly-appeared devices to history - skip the very first
            # scan so launching the app doesn't log your entire LAN as
            # "new" all at once
            if not first_scan:
                for d in devices:
                    if d["ip"] in _known_device_ips or d["is_self"] or d["is_gateway"]:
                        continue
                    label = d["vendor"] or d["ip"]
                    history.log_event("device", label, f"IP {d['ip']}, MAC {d['mac'] or 'unknown'}")
            _known_device_ips.update(d["ip"] for d in devices)
            first_scan = False
        except Exception as e:
            print(f"[lan discovery] scan failed: {e}")
        _stop.wait(DEVICE_SCAN_INTERVAL)


def _svchost_service_name(pid):
    """svchost.exe hosts many Windows services under one generic name -
    pull the actual service name out of its command line (the -s flag)
    so it reads as e.g. 'Windows (Dnscache)' instead of just 'svchost.exe'."""
    try:
        cmdline = psutil.Process(pid).cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    for i, arg in enumerate(cmdline):
        if arg == "-s" and i + 1 < len(cmdline):
            return f"Windows ({cmdline[i + 1]})"
    return None


def process_name(pid):
    if pid is None:
        return "unknown"
    if pid in _proc_name_cache:
        return _proc_name_cache[pid]
    try:
        name = psutil.Process(pid).name()
        if name.lower() == "svchost.exe":
            friendly = _svchost_service_name(pid)
            if friendly:
                name = friendly
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = "unknown"
    _proc_name_cache[pid] = name
    return name


# ---- exact attribution: live 4-tuple -> process table, with a short ----
# ---- grace window so fast connections aren't missed between refreshes ---

conn_table = {}  # key -> (process, last_seen_monotonic)
conn_table_lock = threading.Lock()
_stop = threading.Event()


def conn_table_refresher():
    while not _stop.is_set():
        try:
            raw = psutil.net_connections(kind="inet")
            now = time.monotonic()
            with conn_table_lock:
                for c in raw:
                    if not c.raddr or not c.laddr or not c.pid:
                        continue
                    proto = "tcp" if c.type == socket_module.SOCK_STREAM else "udp"
                    key = (proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                    conn_table[key] = (process_name(c.pid), now)

                # purge entries past the grace window
                cutoff = now - CONN_TABLE_GRACE
                stale = [k for k, (_, seen) in conn_table.items() if seen < cutoff]
                for k in stale:
                    del conn_table[k]
        except (psutil.AccessDenied, PermissionError):
            pass
        _stop.wait(CONN_TABLE_REFRESH)


def lookup_process(key):
    with conn_table_lock:
        entry = conn_table.get(key)
    return entry[0] if entry else "unknown"


# ---- reversible traffic blocking ----------------------------------------
#
# Blocking is enforced entirely in-process by a SECOND WinDivert handle
# opened at the NETWORK layer WITHOUT the SNIFF flag (see
# block_capture_loop below) - the driver hands us each packet and waits
# for us to either resend it (allow) or do nothing (drop). There is no
# Windows Firewall rule, no persistent OS-level state of any kind: the
# block-list below is just an in-memory list checked per packet. This
# means:
#   - Unblocking takes effect on the very next packet - no lingering state.
#   - If THE GATE isn't running, this second handle isn't open, so nothing
#     is blocked - the network reverts to fully open the instant the app
#     exits or crashes. That's the safest possible failure mode.
#   - The JSON file below is a convenience (so rules survive an app
#     restart), never a requirement - a missing or corrupt file just means
#     starting with an empty block-list, never a crash.

block_rules = {}  # id -> {"id", "remote_ip", "org", "process_name", "created_at"}
block_rules_lock = threading.Lock()
_block_handle = None   # set once the intercept WinDivert handle is open
_sniff_handle = None   # set once the sniff (read-only capture) handle is open


def load_block_rules():
    """Best-effort restore of persisted rules. Any problem (missing file,
    corrupt JSON, wrong shape) just leaves the block-list empty - this
    must never be able to crash startup."""
    try:
        with open(BLOCK_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            with block_rules_lock:
                for r in data:
                    if isinstance(r, dict) and r.get("id"):
                        block_rules[r["id"]] = r
            print(f"[block rules] restored {len(block_rules)} rule(s) from disk.")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[block rules] ignoring unreadable {BLOCK_RULES_FILE}: {e}")


def save_block_rules():
    """Best-effort persist. Failing to write must never take down the
    (already-applied, in-memory) block rule - it only means the rule
    won't survive a restart."""
    try:
        with block_rules_lock:
            snapshot = list(block_rules.values())
        with open(BLOCK_RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"[block rules] failed to persist: {e}")


def block_rules_snapshot():
    with block_rules_lock:
        return list(block_rules.values())


def _own_ips():
    ips = set()
    with device_list_lock:
        for d in device_list:
            if d.get("is_self") and d.get("ip"):
                ips.add(d["ip"])
    return ips


def _is_blockable_target(remote_ip):
    """Basic sanity checks, not elaborate ones: never allow a rule that
    could block loopback/this machine, or the LAN gateway - both would
    risk bricking the user's own network access. An org-only umbrella
    rule (remote_ip is None) has no fixed IP to check here; it's still
    safe because get_ip_info() never tags a private/loopback/gateway
    address with a public org in the first place."""
    if not remote_ip:
        return True
    if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return False
    with device_list_lock:
        gw = gateway_ip_cache
    if gw and remote_ip == gw:
        return False
    if remote_ip in _own_ips():
        return False
    return True


def _rule_matches(rule, remote_ip, org, process):
    r_ip = rule.get("remote_ip")
    r_org = rule.get("org")
    r_proc = rule.get("process_name")
    if r_ip and remote_ip != r_ip:
        return False
    if r_org and org != r_org:
        return False
    if r_proc and process != r_proc:
        return False
    return True


def is_blocked(remote_ip, org, process):
    with block_rules_lock:
        rules = list(block_rules.values())
    for rule in rules:
        if _rule_matches(rule, remote_ip, org, process):
            return True
    return False


def add_block_rule(target):
    """target: {"remote_ip": str|None, "org": str|None, "process_name": str|None}.
    remote_ip/org/process_name are all optional, but at least one of
    remote_ip/org must be given - a rule needs something concrete to
    match against. Returns the created rule dict, or None if refused."""
    remote_ip = (target.get("remote_ip") or "").strip() or None
    org = (target.get("org") or "").strip() or None
    process_name = (target.get("process_name") or "").strip() or None

    if not remote_ip and not org:
        print(f"[block rules] refused empty target: {target}")
        return None
    if not _is_blockable_target(remote_ip):
        print(f"[block rules] refused unsafe target: {target}")
        return None

    rule = {
        "id": uuid.uuid4().hex,
        "remote_ip": remote_ip,
        "org": org,
        "process_name": process_name,
        "created_at": time.time(),
    }
    with block_rules_lock:
        block_rules[rule["id"]] = rule
    save_block_rules()
    return rule


def remove_block_rule(rule_id):
    if not rule_id:
        return
    with block_rules_lock:
        block_rules.pop(rule_id, None)
    save_block_rules()


# ---- offline + live IP intelligence: country / organization per IP ----

ip_info_cache = {}  # ip -> {"country": str|None, "org": str|None, "hostname": str|None}
ip_info_lock = threading.Lock()
rdap_queue = queue.Queue()
hostname_queue = queue.Queue()


def get_ip_info(ip):
    with ip_info_lock:
        cached = ip_info_cache.get(ip)
    if cached is not None:
        return cached

    country = geolookup.country_for_ip(ip)
    org_entry = geolookup.org_for_ip(ip)
    org = org_entry[1] if org_entry else None
    info = {"country": country, "org": org, "hostname": None}

    with ip_info_lock:
        ip_info_cache[ip] = info

    if not geolookup.is_private_or_reserved(ip):
        if country is None and org is None:
            rdap_queue.put(ip)
        # hostname resolution (reverse DNS, like Resource Monitor's
        # Network tab shows) is independent of whether geo/org matched -
        # always worth trying for a new public IP
        hostname_queue.put(ip)

    return info


def rdap_worker():
    """Background thread: resolves the rare IPs the offline database
    missed, via a live RDAP lookup. Never blocks packet capture - results
    land in ip_info_cache and apply to that IP's future packets."""
    while not _stop.is_set():
        try:
            ip = rdap_queue.get(timeout=1)
        except queue.Empty:
            continue
        result = rdap_lookup.lookup(ip)
        if result and (result.get("country") or result.get("org")):
            with ip_info_lock:
                existing = ip_info_cache.get(ip, {"hostname": None})
                ip_info_cache[ip] = {
                    "country": result.get("country"),
                    "org": result.get("org"),
                    "hostname": existing.get("hostname"),
                }


def hostname_worker():
    """Background thread: reverse-DNS resolves remote IPs, same info
    Windows' own Resource Monitor shows in its Network tab. Never blocks
    packet capture - results land in ip_info_cache and apply to that
    IP's future packets."""
    while not _stop.is_set():
        try:
            ip = hostname_queue.get(timeout=1)
        except queue.Empty:
            continue
        hostname = hostname_lookup.lookup(ip)
        if hostname:
            with ip_info_lock:
                if ip in ip_info_cache:
                    ip_info_cache[ip]["hostname"] = hostname


# events captured off the wire, drained by the websocket loop:
# each is {"dir": "in"|"out", "process": str, "raddr": str, "rport": int,
#          "country": str|None, "org": str|None, "service": str|None}
packet_events = queue.Queue(maxsize=50000)

_known_processes = set()  # for first-seen detection, this run only
_known_orgs = set()


def _log_first_seen(process, org):
    if process and process != "unknown" and process not in _known_processes:
        _known_processes.add(process)
        history.log_event("process", process, "first traffic seen")
    if org and org not in _known_orgs:
        _known_orgs.add(org)
        history.log_event("org", org, "first contacted")


def packet_capture_loop(opened_event):
    """Runs in its own thread. Sniffs real packets and tags each one with
    its real owning process by matching the live connection table, plus
    country/org/service enrichment for the remote endpoint.

    opened_event is set as soon as the capture handle is open - that's
    the moment we know whether exact attribution will work, not whenever
    this function eventually returns (which is only once capture stops,
    i.e. basically never during normal operation).
    """
    try:
        w = pydivert.WinDivert(
            "ip and (tcp or udp) and tcp.DstPort != 8765 and tcp.SrcPort != 8765",
            layer=pydivert.Layer.NETWORK,
            flags=pydivert.Flag.SNIFF,
        )
        w.open()
    except Exception as e:
        print(f"[packet capture] unavailable ({e}). "
              "Falling back to approximate attribution.")
        opened_event.ok = False
        opened_event.set()
        return

    print("[packet capture] active - real per-packet attribution enabled.")
    opened_event.ok = True
    opened_event.set()
    global _sniff_handle
    _sniff_handle = w

    try:
        for packet in w:
            try:
                if packet.tcp:
                    proto = "tcp"
                elif packet.udp:
                    proto = "udp"
                else:
                    continue

                if packet.is_outbound:
                    local_ip, local_port = packet.src_addr, packet.src_port
                    remote_ip, remote_port = packet.dst_addr, packet.dst_port
                    direction = "out"
                else:
                    local_ip, local_port = packet.dst_addr, packet.dst_port
                    remote_ip, remote_port = packet.src_addr, packet.src_port
                    direction = "in"

                key = (proto, local_ip, local_port, remote_ip, remote_port)
                process = lookup_process(key)
                info = get_ip_info(remote_ip)
                service = portnames.service_for_port(remote_port)
                _log_first_seen(process, info["org"])

                event = {
                    "dir": direction,
                    "process": process,
                    "proto": proto,
                    "bytes": len(packet.raw),
                    "raddr": remote_ip,
                    "rport": remote_port,
                    "country": info["country"],
                    "org": info["org"],
                    "hostname": info["hostname"],
                    "service": service,
                }

                try:
                    packet_events.put_nowait(event)
                except queue.Full:
                    pass
            except Exception:
                continue
            if _stop.is_set():
                break
    finally:
        try:
            w.close()
        except Exception:
            pass


def block_capture_loop(opened_event):
    """Runs in its own thread, entirely separate from packet_capture_loop's
    sniff-mode thread. Opens a SECOND WinDivert handle at the NETWORK
    layer WITHOUT Flag.SNIFF - true intercept mode, where the driver
    withholds each packet until we either resend it (w.send) or let it
    drop (do nothing). Only engages the block-rule check at all when
    there's at least one active rule, so normal traffic is untouched
    (just re-sent immediately) the rest of the time."""
    try:
        w = pydivert.WinDivert(
            "ip and (tcp or udp) and tcp.DstPort != 8765 and tcp.SrcPort != 8765",
            layer=pydivert.Layer.NETWORK,
        )
        w.open()
    except Exception as e:
        print(f"[block engine] unavailable ({e}). Block/unblock toggles will have no effect.")
        opened_event.ok = False
        opened_event.set()
        return

    print("[block engine] active - block rules are now enforced.")
    opened_event.ok = True
    opened_event.set()
    global _block_handle
    _block_handle = w

    try:
        for packet in w:
            try:
                with block_rules_lock:
                    has_rules = bool(block_rules)
                if not has_rules:
                    w.send(packet)
                    if _stop.is_set():
                        break
                    continue

                if packet.tcp:
                    proto = "tcp"
                elif packet.udp:
                    proto = "udp"
                else:
                    w.send(packet)
                    if _stop.is_set():
                        break
                    continue

                if packet.is_outbound:
                    local_ip, local_port = packet.src_addr, packet.src_port
                    remote_ip, remote_port = packet.dst_addr, packet.dst_port
                else:
                    local_ip, local_port = packet.dst_addr, packet.dst_port
                    remote_ip, remote_port = packet.src_addr, packet.src_port

                key = (proto, local_ip, local_port, remote_ip, remote_port)
                process = lookup_process(key)
                # reuses the same cached ip_info_cache the sniff path
                # populates - no duplicate lookups, no extra RDAP calls
                info = get_ip_info(remote_ip)
                org = info.get("org")

                if is_blocked(remote_ip, org, process):
                    pass  # drop: simply never call w.send() for this packet
                else:
                    w.send(packet)
            except Exception:
                # fail OPEN, never closed: if anything above raised, let
                # the packet through rather than silently eating traffic
                # because of a bug in the block-matching logic
                try:
                    w.send(packet)
                except Exception:
                    pass
            if _stop.is_set():
                break
    finally:
        try:
            w.close()
        except Exception:
            pass


def drain_packet_events(max_items=5000):
    events = []
    for _ in range(max_items):
        try:
            events.append(packet_events.get_nowait())
        except queue.Empty:
            break
    return events


HISTORY_REFRESH = 2.0  # seconds between re-reading history.db for the UI


async def traffic_stream(websocket, capture_active):
    last = psutil.net_io_counters()
    last_time = time.monotonic()
    last_history_fetch = 0
    history_snapshot = []

    try:
        while True:
            await asyncio.sleep(POLL_INTERVAL)

            now = psutil.net_io_counters()
            now_time = time.monotonic()
            elapsed = now_time - last_time

            bytes_in = now.bytes_recv - last.bytes_recv
            bytes_out = now.bytes_sent - last.bytes_sent
            bps_in = bytes_in / elapsed if elapsed > 0 else 0
            bps_out = bytes_out / elapsed if elapsed > 0 else 0

            with device_list_lock:
                devices_snapshot = list(device_list)
                gateway_snapshot = gateway_ip_cache

            if now_time - last_history_fetch > HISTORY_REFRESH:
                try:
                    history_snapshot = history.get_recent(100)
                except Exception:
                    pass
                last_history_fetch = now_time

            if capture_active:
                events = drain_packet_events()
                payload = {
                    "t": time.time(),
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "bps_in": bps_in,
                    "bps_out": bps_out,
                    "attribution": "exact",
                    "events": events,
                    "devices": devices_snapshot,
                    "gateway_ip": gateway_snapshot,
                    "history": history_snapshot,
                    "block_rules": block_rules_snapshot(),
                }
            else:
                packets_in = max(0, now.packets_recv - last.packets_recv)
                packets_out = max(0, now.packets_sent - last.packets_sent)
                payload = {
                    "t": time.time(),
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "bps_in": bps_in,
                    "bps_out": bps_out,
                    "attribution": "approximate",
                    "packets_in": packets_in,
                    "packets_out": packets_out,
                    "devices": devices_snapshot,
                    "gateway_ip": gateway_snapshot,
                    "history": history_snapshot,
                    "block_rules": block_rules_snapshot(),
                }

            await websocket.send(json.dumps(payload))

            last = now
            last_time = now_time

    except websockets.exceptions.ConnectionClosed:
        pass


async def command_listener(websocket):
    """Handles commands sent FROM the frontend (history management, and
    the block/unblock toggles). block_add/block_remove don't need to send
    anything back directly - the updated block-list rides on the very
    next traffic_stream tick (every ~100ms) to every connected client, so
    the UI always reflects backend ground truth rather than an optimistic
    local guess."""
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
            except Exception:
                continue
            cmd = data.get("cmd")
            if cmd == "clear_history":
                history.clear_history()
            elif cmd == "open_history_folder":
                history.open_history_folder()
            elif cmd == "block_add":
                add_block_rule(data.get("target") or {})
            elif cmd == "block_remove":
                remove_block_rule(data.get("id"))
    except websockets.exceptions.ConnectionClosed:
        pass


async def main():
    print(f"THE GATE backend running at ws://{HOST}:{PORT}")

    load_block_rules()  # best-effort; never crashes on a missing/corrupt file

    # LAN device discovery for Sol View - independent of packet capture,
    # works whether or not we're running as Administrator
    discovery_thread = threading.Thread(target=device_discovery_worker, daemon=True)
    discovery_thread.start()

    capture_active = False
    if PYDIVERT_AVAILABLE:
        refresher = threading.Thread(target=conn_table_refresher, daemon=True)
        refresher.start()

        worker = threading.Thread(target=rdap_worker, daemon=True)
        worker.start()

        hostname_worker_thread = threading.Thread(target=hostname_worker, daemon=True)
        hostname_worker_thread.start()

        opened_event = threading.Event()
        opened_event.ok = False

        capture_thread = threading.Thread(
            target=packet_capture_loop, args=(opened_event,), daemon=True
        )
        capture_thread.start()

        # wait until the thread tells us whether the handle actually opened,
        # rather than guessing after a fixed delay
        await asyncio.get_event_loop().run_in_executor(
            None, opened_event.wait, 5.0
        )
        capture_active = opened_event.ok

        # second, independent WinDivert handle - true intercept mode, used
        # only to enforce block rules. Its own thread, its own handle;
        # never interferes with the sniff-mode capture thread above.
        block_opened_event = threading.Event()
        block_opened_event.ok = False
        block_thread = threading.Thread(
            target=block_capture_loop, args=(block_opened_event,), daemon=True
        )
        block_thread.start()
    else:
        print("[packet capture] pydivert not installed - "
              "falling back to approximate attribution.")

    if not capture_active:
        print("Run this as Administrator for exact per-packet process "
              "attribution. Continuing with approximate mode.")

    async def handler(websocket):
        await asyncio.gather(
            traffic_stream(websocket, capture_active),
            command_listener(websocket),
        )

    async with websockets.serve(handler, HOST, PORT):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        _stop.set()
        # proactively close both WinDivert handles on clean shutdown -
        # belt-and-suspenders alongside each capture thread's own
        # finally-block close(). Neither handle is a firewall rule or any
        # other OS-level state, so there is nothing left behind either way.
        for handle in (_sniff_handle, _block_handle):
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
