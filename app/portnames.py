"""
Well-known port -> service name mapping (IANA-registered ports). Static
lookup, no network involved - gives every packet a labeled purpose even
when the process/organization can't be identified.
"""

WELL_KNOWN_PORTS = {
    20: "FTP (data)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    43: "WHOIS", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "RPC (Windows)", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IPsec/IKE", 514: "Syslog", 515: "LPD",
    520: "RIP", 587: "SMTP (submission)", 631: "IPP (printing)",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MS SQL Server", 1521: "Oracle DB", 1701: "L2TP",
    1723: "PPTP VPN", 1812: "RADIUS", 1813: "RADIUS",
    1900: "SSDP/UPnP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel (SSL)",
    3074: "Xbox Live", 3306: "MySQL", 3389: "Remote Desktop",
    3478: "STUN/TURN (VoIP, games)", 3479: "STUN/TURN",
    4500: "IPsec NAT-T", 5000: "UPnP / app service", 5060: "SIP (VoIP)",
    5061: "SIP (VoIP, TLS)", 5222: "XMPP (chat)", 5223: "XMPP (SSL)",
    5228: "Google Play Services", 5353: "mDNS (Bonjour)",
    5900: "VNC", 5938: "TeamViewer", 6379: "Redis",
    6665: "IRC", 6666: "IRC", 6667: "IRC", 6697: "IRC (SSL)",
    6881: "BitTorrent", 6882: "BitTorrent", 6883: "BitTorrent",
    6884: "BitTorrent", 6885: "BitTorrent",
    7680: "Windows Update (P2P)", 8080: "HTTP (alt/proxy)",
    8443: "HTTPS (alt)", 8883: "MQTT (SSL)", 9001: "Tor",
    9100: "Printer (JetDirect)", 9443: "HTTPS (alt)",
    27015: "Steam / Source games", 27036: "Steam",
}

# common ephemeral/dynamic high-port ranges don't get individual
# entries - the frontend just shows the raw port number in that case


def service_for_port(port):
    """Returns a short label for a well-known port, or None."""
    return WELL_KNOWN_PORTS.get(port)
