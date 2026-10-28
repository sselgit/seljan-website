# Seljan Security Tool Stack

Version: 1.3.0

Free, browser-based security helpers served at https://seljan.net:

- **IOC pivot:** paste an IP, domain, URL, file hash, or email address. It cleans up defanged
  text (`hxxp://`, `[.]`), automatically checks free public sources and shows which ones have a
  hit, and gives one-click links to the full reports.
- **Tool directory:** a curated list of reputation, sandbox, email/DNS, and recon tools.
- **Port reference:** what common ports are for and whether they should be exposed.
- **Email checker:** paste a suspicious email and see the warning signs explained.
- **Analyst toolkit** (`toolkit.html`): decoder (Base64, hex, URL, escapes, XOR, compressed data),
  indicator defang/refang/extract, timestamp converter, IP and CIDR math, hash and file-type checks,
  a hypothesis worksheet, phishing triage, an incident-note builder, reference tables, and a **rule
  tuner** that proposes narrow exclusions for a noisy detection rule (YARA-L, Sigma, Splunk, Kusto,
  regex, or plain language).

Everything runs in the browser and there is no server of ours in the middle. The analyst toolkit pages
go further: their Content-Security-Policy sets `connect-src 'none'`, so they cannot make any network
request at all, and they use no cookies or storage. With auto-check
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
| `site/toolkit.html` and the other toolkit pages | The analyst toolkit (one HTML page per tool, shared `css/toolkit.css` and `js/kit.js`) |
| `site/js/tuner-core.js` | Rule tuner engine: sanitize, parse logs, flag risky activity, propose and write exclusions |
| `site/js/tuner-data.js` | Rule tuner teaching content (risk catalog, examples, sample data) |
| `tests/lookups-test.html` | Browser test page for the lookup engine (not published) |
| `tests/kit-test.html` | Browser test page for the toolkit (not published) |
| `tests/contrast-audit.js` | Dev-only WCAG contrast audit you can load into a page (not published) |
| `scripts/publish.sh` | Publishes `site/` to the `gh-pages` branch (GitHub Pages) |

## Preview locally

```bash
python -m http.server 8765 --directory site
```

Open http://localhost:8765. To run the tests, serve the repo root instead
(`python -m http.server 8765`) and open http://localhost:8765/tests/lookups-test.html or
http://localhost:8765/tests/kit-test.html; each page prints PASS/FAIL for every check. Browsers
cache scripts aggressively while you work, so use a server that sends `Cache-Control: no-store`
or hard-reload before trusting a result.

## Rule tuner guardrails

The rule tuner is a helper, not a judge. By design it:

- replaces IP addresses, emails and user-folder names with generic values on request (the real
  values stay only in the page's memory, and the user must put them back before using a rule)
- locks any exclusion that would hide risky activity (Office starting a shell, encoded commands,
  credential theft patterns, and so on) and explains why
- ranks narrow exclusions above broad ones and shows name-only matching as the weak option
- keeps the rule text locked until the user confirms a historical check, an owner, an attacker
  could not reuse the exclusion, testing, and a review date
- writes starting-point text only; it does not validate syntax for any platform
