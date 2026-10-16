"""
One-time build step: compiles the raw DB-IP Lite CSV.gz files in geodata/
into a compact pickle (geodata/geo.pkl) that server.py can load instantly
at startup, instead of re-parsing ~1.2 million CSV rows every launch.

Run this once after downloading/updating the source CSVs:
    python build_geodata.py

Source data: DB-IP Lite (country + ASN), CC BY 4.0, https://db-ip.com
"""

import csv
import gzip
import ipaddress
import pickle
import sys
from pathlib import Path

GEODATA_DIR = Path(__file__).parent / "geodata"


def ip_to_int(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, None
    return int(ip), 4 if ip.version == 4 else 6


def build_country_table():
    v4_starts, v4_labels = [], []
    v6_starts, v6_labels = [], []

    path = GEODATA_DIR / "dbip-country-lite.csv.gz"
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for row in csv.reader(f):
            start_ip, end_ip, country = row
            start_int, version = ip_to_int(start_ip)
            if start_int is None:
                continue
            if version == 4:
                v4_starts.append(start_int)
                v4_labels.append(country)
            else:
                v6_starts.append(start_int)
                v6_labels.append(country)

    return {
        "v4_starts": v4_starts, "v4_labels": v4_labels,
        "v6_starts": v6_starts, "v6_labels": v6_labels,
    }


def build_asn_table():
    v4_starts, v4_labels = [], []
    v6_starts, v6_labels = [], []

    path = GEODATA_DIR / "dbip-asn-lite.csv.gz"
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for row in csv.reader(f):
            start_ip, end_ip, asn, org = row
            start_int, version = ip_to_int(start_ip)
            if start_int is None:
                continue
            label = (asn, org)
            if version == 4:
                v4_starts.append(start_int)
                v4_labels.append(label)
            else:
                v6_starts.append(start_int)
                v6_labels.append(label)

    return {
        "v4_starts": v4_starts, "v4_labels": v4_labels,
        "v6_starts": v6_starts, "v6_labels": v6_labels,
    }


def main():
    print("Building country table...")
    country = build_country_table()
    print(f"  {len(country['v4_starts'])} IPv4 ranges, "
          f"{len(country['v6_starts'])} IPv6 ranges")

    print("Building ASN/organization table...")
    asn = build_asn_table()
    print(f"  {len(asn['v4_starts'])} IPv4 ranges, "
          f"{len(asn['v6_starts'])} IPv6 ranges")

    out_path = GEODATA_DIR / "geo.pkl"
    with open(out_path, "wb") as f:
        pickle.dump({"country": country, "asn": asn}, f, protocol=pickle.HIGHEST_PROTOCOL)

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"Wrote {out_path} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
