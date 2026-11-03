# THE GATE

Live network visibility, built to feel like a space game. THE GATE shows what your machine is talking to in real time: every packet is attributed to the process that sent it, and every remote address is enriched with country, organization and well-known service names. It also discovers devices on your LAN.

Made for security and networking people who like their tools pretty. Open source and free for everyone to use, learn from and improve.

> Status: early. The network tooling works; the space-game visuals are a work in progress.

## Features
- Per-packet traffic attribution to the owning process (WinDivert via `pydivert`, read-only sniffing, needs Administrator)
- Falls back to approximate OS counters when not elevated, and says so in the UI
- Offline GeoIP / ASN / MAC vendor lookups, with live RDAP as a fallback
- LAN device discovery and hostname lookup
- Connection history stored locally in SQLite

## Run it (Windows)
1. Install Python 3.12 and `pip install -r app/requirements.txt`
2. Build the lookup data once: download the DB-IP Lite country and ASN CSVs into `app/geodata/`, then run `python app/build_geodata.py` and `python app/build_oui.py`
3. Double-click `THE GATE.bat` (approve the Administrator prompt)

## Credits
- IP geolocation data by [DB-IP.com](https://db-ip.com) (Lite, CC BY 4.0)
- [WinDivert](https://reqrypt.org/windivert.html) and [pydivert](https://github.com/ffalcinelli/pydivert), [psutil](https://github.com/giampaolo/psutil), [websockets](https://github.com/python-websockets/websockets)

## License
GPL-3.0. See [LICENSE](LICENSE).
