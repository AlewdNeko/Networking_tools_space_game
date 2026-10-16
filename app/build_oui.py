"""
One-time build step: compiles the raw IEEE OUI registry (geodata/oui.txt)
into a compact pickle (geodata/oui.pkl) for instant MAC-address-to-vendor
lookups (e.g. "a device with MAC 3C:22:FB:.." -> "Apple, Inc.").

Run this once after downloading/updating the source file:
    python build_oui.py

Source: IEEE public OUI registry, https://standards-oui.ieee.org/oui/oui.txt
(public assignment registry - vendor names are not copyrighted facts)
"""

import pickle
import re
from pathlib import Path

GEODATA_DIR = Path(__file__).parent / "geodata"


def build_oui_table():
    table = {}
    path = GEODATA_DIR / "oui.txt"
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.+)$", line.strip())
            if m:
                prefix = m.group(1).upper()
                vendor = m.group(2).strip()
                table[prefix] = vendor
    return table


def main():
    print("Building MAC vendor (OUI) table...")
    table = build_oui_table()
    print(f"  {len(table)} vendor prefixes")

    out_path = GEODATA_DIR / "oui.pkl"
    with open(out_path, "wb") as f:
        pickle.dump(table, f, protocol=pickle.HIGHEST_PROTOCOL)

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"Wrote {out_path} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
