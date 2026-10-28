# SOC Analyst Toolkit

Version: 1.7.0

Free, browser-based security helpers served at https://seljan.net:

- **IOC pivot:** paste an IP, domain, URL, file hash, or email address. It cleans up defanged
  text (`hxxp://`, `[.]`), automatically checks free public sources and shows which ones have a
  hit, and gives one-click links to the full reports. As you type, it also **auto-detects** what you
  pasted (MAC address, AS number, encoded text, timestamp, CIDR range, and more) and lists every
  toolkit tool that fits.
- **Tool directory:** a curated list of reputation, sandbox, email/DNS, and recon tools.
- **Port reference:** what common ports are for and whether they should be exposed.
- **Email checker:** paste a suspicious email and see the warning signs explained.
- **Analyst toolkit** (`toolkit.html`), with a "paste anything" search at the top:
  - *Offline tools:* decoder (Base64, hex, URL, escapes, XOR, compressed data), indicator
    defang/refang/extract, timestamp converter, IP and CIDR math, hash and file-type checks, MAC
    vendor lookup, free/disposable email check, a hypothesis worksheet, phishing triage, an
    incident-note builder, reference tables, and a **rule tuner** that proposes narrow exclusions for
    a noisy detection rule (YARA-L, Sigma, Splunk, Kusto, regex, or plain language).
  - *Snort/Suricata tuner* (`ids.html`): load a false-positive capture (and optionally a true-positive
    capture), paste the rule and alert, pick Suricata 6/7, Snort 3 or Snort 2, and get offset, depth,
    distance, within, buffer, flow, payload-size and rate-limit recommendations, each re-checked against
    the captures and written in the chosen engine's syntax.
  - *Lookup tools:* DNS records, DNS report, DNSSEC test, DNS propagation, reverse DNS, WHOIS (via
    RDAP), abuse contacts, and ASN and routing.

## Privacy model

Everything runs in the visitor's browser; there is no server of ours in the middle, and no cookies,
analytics, or tracking.

- **Offline toolkit pages** set `connect-src 'none'` in their Content-Security-Policy, so they cannot
  make any network request. The MAC page allows only its own `data/oui.json`.
- **Lookup pages** list exactly the public sources they use in `connect-src`. They ask those sources
  directly, only when the visitor presses the button (or opens a link from the search box, which
  carries `go=1`). Requests omit cookies and the referrer.
- **Private addresses and internal names are never sent.** `SK.lu.parseTarget` refuses private,
  link-local, loopback, documentation and reserved addresses and names such as `printer.local`; URL
  inputs use only the host and email inputs only the domain. This is covered by tests that were
  checked by deliberately disabling each guard.
- **Values travel in the URL fragment** (`page.html#q=value&k=kind&go=1`), which browsers never send to
  a server, so lookups do not appear in server logs.
- The IOC pivot's auto-check works as before (a checkbox, default on) and its sources are listed below.

## Which sources are used

| Where | Sources |
|---|---|
| IOC pivot, IP | Shodan InternetDB, six spam/abuse DNS blocklists, Tor Project (Onionoo), AlienVault OTX, ipinfo |
| IOC pivot, domain, URL host, email domain | Cloudflare malware-filtering DNS, AlienVault OTX, registration age (RDAP), MX/SPF/DMARC for email |
| IOC pivot, file hash | Team Cymru malware hash registry (MD5 and SHA-1 only), AlienVault OTX |
| DNS records, report, DNSSEC, reverse DNS, free-email MX step | Google Public DNS or Cloudflare 1.1.1.1 (DNS-over-HTTPS) |
| DNS propagation | Google, Cloudflare, DNS.SB, Control D (unfiltered) and RethinkDNS, over the DNS wire format |
| WHOIS | RDAP, through the rdap.org redirector to the registry that holds the record (about 250 registries allow browser requests; see below) |
| Abuse contacts | RDAP, RIPEstat abuse-contact-finder, Google Public DNS |
| ASN | Team Cymru IP-to-ASN mapping (DNS), RDAP, RIPEstat |
| MAC vendor | IEEE MA-L, MA-M and MA-S registries, bundled as `site/data/oui.json` (no lookup) |

VirusTotal, AbuseIPDB, GreyNoise, MalwareBazaar, URLhaus and urlscan don't allow requests from
browser pages (each was tested on 2026-10-27), so they remain click-through links. A "no hit"
means only that the free sources have nothing on the indicator. ViewDNS-style tools that need
server-side data or vantage points (reverse IP, reverse whois, IP history, subdomain discovery, HTTP
headers, port scans, traceroute, global ping, firewall-region tests) are deliberately not built: a
browser cannot do them, and a scanner run from this site could be abused.

## Layout

| Path | What it is |
|---|---|
| `site/` | The website (plain HTML, CSS, JavaScript; no build step) |
| `site/js/lookups.js` | The IOC pivot's automatic lookup engine |
| `site/js/router.js` | Auto-detect: reads pasted text and lists the tools that fit (offline) |
| `site/js/netlookup.js` | Lookup engine: DNS wire-format parser, resolvers, RDAP, ASN, DNSSEC, MAC, email providers |
| `site/js/lookup-ui.js` | Shared page helpers for the lookup tools, including the private-address gate |
| `site/toolkit.html` and the other toolkit pages | One HTML page per tool, shared `css/toolkit.css` and `js/kit.js` |
| `site/js/tuner-core.js`, `tuner-data.js` | Rule tuner engine and teaching content |
| `site/js/pcap.js`, `ids-engine.js`, `ids-tune.js`, `ids-data.js`, `ids-tuner.js`, `pcap-build.js` | Snort/Suricata tuner: capture reader and TCP reassembly, rule parser and match simulator, recommendation engine, teaching content, page, and the builder that makes the example captures |
| `site/js/attack-map.js` (generated), `attack-ui.js` | MITRE ATT&CK suggestions for a rule, shown on both tuners. Rebuild with `scripts/build_attack_map.py` (reads MITRE's public ATT&CK data and refuses IDs that are revoked) |
| `site/data/oui.json` | MAC vendor list built from the IEEE public registries |
| `scripts/gen_toolkit_pages.py` | Regenerates the toolkit HTML pages (the Content-Security-Policy for each page is built here) |
| `scripts/probe_rdap_hosts.py` | Refreshes `scripts/rdap-cors-hosts.json`, the registries allowed in the WHOIS pages' policy |
| `scripts/build_oui.py` | Rebuilds `site/data/oui.json` from IEEE (run every few months) |
| `scripts/publish.sh` | Publishes `site/` to the `gh-pages` branch (GitHub Pages) |
| `tests/lookups-test.html` | Browser test page for the IOC pivot engine (not published) |
| `tests/ids-test.html` | Browser test page for the capture reader, rule engine and Snort/Suricata tuner (not published) |
| `tests/kit-test.html` | Browser test page for the toolkit and lookup engine (not published) |
| `tests/dns-fixtures.js` | Real DNS responses used to test the parser, in wire format and JSON |
| `tests/contrast-audit.js` | Dev-only WCAG contrast audit you can load into a page (not published) |

To change a toolkit page, edit `scripts/gen_toolkit_pages.py` and run `python scripts/gen_toolkit_pages.py`
(the pages are committed as plain HTML, so the site itself still has no build step).

## Preview locally

```bash
python -m http.server 8765 --directory site
```

Open http://localhost:8765. To run the tests, serve the repo root instead
(`python -m http.server 8765`) and open http://localhost:8765/tests/lookups-test.html or
http://localhost:8765/tests/kit-test.html; each page prints PASS/FAIL for every check. Browsers
cache scripts aggressively while you work, so use a server that sends `Cache-Control: no-store`
or hard-reload before trusting a result. Opening the same URL again does not reload the page;
use Reload.

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

## Snort/Suricata tuner guardrails and limits

- Captures are read in the browser only (the page's policy blocks all network requests).
- The matcher is a simulation of a subset of rule options (content with offset, depth, distance, within,
  nocase, startswith, endswith, sticky HTTP buffers, pcre, flow, dsize, isdataat, urilen, bsize). It says when
  a rule uses something it cannot evaluate, and every output points to `suricata -r` or `snort -r` as the
  final check.
- Every recommendation is re-run against both captures and shows the false positives removed and whether the
  true-positive capture still alerts. With no true-positive capture, nothing is marked verified.
- Rule text stays locked behind the same historical-check checklist as the rule tuner. Suppressions and
  negated contents are flagged high risk. IP addresses in the results are masked unless the user unticks it.

## MITRE ATT&CK suggestions

Both tuners suggest ATT&CK techniques from the rule name, its contents, the alert text and (for Snort/Suricata)
the classtype. It is keyword matching with a hand-written table of about 60 rules, so each suggestion is labeled
"good match", "possible match" or "weak hint" and must be confirmed by the analyst. Names and IDs come from
ATT&CK Enterprise v20 and are checked at build time; where v20 renumbered a technique the old ID is shown too.
ATT&CK(R) is a registered trademark of The MITRE Corporation; see https://attack.mitre.org/resources/terms-of-use/.
