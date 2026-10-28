#!/usr/bin/env python3
"""Refresh scripts/rdap-cors-hosts.json: the RDAP registry hosts that allow requests from a web page.

A browser can only read a registry's answer if the registry sends an Access-Control-Allow-Origin header, and the
WHOIS pages must name every such host in their Content-Security-Policy. This script reads IANA's RDAP bootstrap
file, sends one test request per registry with an Origin header, and keeps the hosts that allow it.

Run it now and then, then run scripts/gen_toolkit_pages.py to rebuild the pages.
"""
import concurrent.futures as cf
import json
import os
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ORIGIN = "https://seljan.net"


def fetch_bootstrap():
    req = urllib.request.Request("https://data.iana.org/rdap/dns.json", headers={"User-Agent": "Mozilla/5.0"})
    return json.load(urllib.request.urlopen(req, timeout=30))["services"]


def probe(item):
    base, tlds = item
    url = base.rstrip("/") + "/domain/nic." + tlds[0]
    req = urllib.request.Request(url, headers={"Origin": ORIGIN, "Accept": "application/rdap+json", "User-Agent": "Mozilla/5.0"})
    try:
        headers = urllib.request.urlopen(req, timeout=8).headers
    except urllib.error.HTTPError as e:
        headers = e.headers
    except Exception:
        return base, False
    return base, headers.get("Access-Control-Allow-Origin") in ("*", ORIGIN)


def main():
    bases = {}
    for tlds, urls in fetch_bootstrap():
        https = [u for u in urls if u.startswith("https")]
        if https:
            bases.setdefault(https[0], []).extend(tlds)
    with cf.ThreadPoolExecutor(30) as pool:
        results = list(pool.map(probe, bases.items()))
    hosts = sorted({base.split("/")[2] for base, ok in results if ok})
    with open(os.path.join(HERE, "rdap-cors-hosts.json"), "w", encoding="utf-8") as f:
        json.dump(hosts, f, indent=0)
    print("%d of %d registries allow browser requests" % (len(hosts), len({b.split('/')[2] for b in bases})))


if __name__ == "__main__":
    main()
