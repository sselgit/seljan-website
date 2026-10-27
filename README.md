# Seljan Security Tool Stack

Version: 1.2.0

Free, browser-based security helpers served at https://seljan.net:

- **IOC pivot:** paste an IP, domain, URL, file hash, or email address. It cleans up defanged
  text (`hxxp://`, `[.]`), automatically checks free public sources and shows which ones have a
  hit, and gives one-click links to the full reports.
- **Tool directory:** a curated list of reputation, sandbox, email/DNS, and recon tools.
- **Port reference:** what common ports are for and whether they should be exposed.
- **Email checker:** paste a suspicious email and see the warning signs explained.

Everything runs in the browser and there is no server of ours in the middle. With auto-check
on (the default; there is a checkbox), the browser asks the sources directly, and the page lists
them. Private addresses and internal names are never sent, URL lookups drop the query string,
fragment and credentials, and email lookups send only the domain. No cookies, analytics, or
tracking.

## Which sources are checked automatically

| Indicator | Sources |
|---|---|
| IP | Shodan InternetDB, six spam/abuse DNS blocklists, Tor Project (Onionoo), AlienVault OTX, ipinfo |
| Domain, URL host, email domain | Cloudflare malware-filtering DNS, AlienVault OTX, registration age (RDAP), MX/SPF/DMARC for email |
| File hash | Team Cymru malware hash registry (MD5 and SHA-1 only), AlienVault OTX |

VirusTotal, AbuseIPDB, GreyNoise, MalwareBazaar, URLhaus and urlscan don't allow requests from
browser pages (each was tested on 2026-10-27), so they remain click-through links. A "no hit"
means only that the free sources have nothing on the indicator.

## Layout

| Path | What it is |
|---|---|
| `site/` | The website (plain HTML, CSS, JavaScript; no build step) |
| `site/js/lookups.js` | The automatic lookup engine |
| `tests/lookups-test.html` | Browser test page for the engine (not published) |
| `scripts/publish.sh` | Publishes `site/` to the `gh-pages` branch (GitHub Pages) |

## Preview locally

```bash
python -m http.server 8765 --directory site
```

Open http://localhost:8765. To run the lookup tests, serve the repo root instead
(`python -m http.server 8765`) and open http://localhost:8765/tests/lookups-test.html; the
page prints PASS/FAIL for each check.
