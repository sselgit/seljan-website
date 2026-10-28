#!/usr/bin/env python3
"""Rebuild site/data/oui.json, the offline MAC vendor list, from the IEEE Registration Authority public listings.

The IEEE publishes three registries: MA-L (24-bit blocks), MA-M (28-bit) and MA-S (36-bit). The site file keeps
only the prefix and the organisation name, with each distinct name stored once to keep the download small.

Usage: python scripts/build_oui.py        (downloads about 5 MB)
Run it every few months, then commit the new site/data/oui.json.
"""
import csv
import datetime
import io
import json
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "site", "data", "oui.json")
SOURCES = {
    "L": "https://standards-oui.ieee.org/oui/oui.csv",
    "M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "S": "https://standards-oui.ieee.org/oui36/oui36.csv",
}


def fetch(url):
    # The IEEE site rejects some browser-like user agents, so identify as a plain command-line client.
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    return urllib.request.urlopen(req, timeout=120).read().decode("utf-8", "replace")


def main():
    vendors, index, tables = [], {}, {}
    for key, url in SOURCES.items():
        table = {}
        for row in csv.DictReader(io.StringIO(fetch(url))):
            prefix = (row.get("Assignment") or "").strip().upper()
            name = re.sub(r"\s+", " ", row.get("Organization Name") or "").strip()
            if not prefix or not name:
                continue
            if name not in index:
                index[name] = len(vendors)
                vendors.append(name)
            table[prefix] = index[name]
        tables[key] = table
        print(key, len(table), "assignments")
    data = {"updated": datetime.date.today().isoformat(),
            "source": "IEEE Registration Authority MA-L, MA-M and MA-S public listings",
            "v": vendors, "L": tables["L"], "M": tables["M"], "S": tables["S"]}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
    print("wrote", os.path.normpath(OUT), os.path.getsize(OUT), "bytes,", len(vendors), "vendors")


if __name__ == "__main__":
    main()
