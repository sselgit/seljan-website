# Changelog

## 1.4.0 (2026-10-28)

- Eight new lookup tools that ask public sources straight from the browser: DNS records, DNS report
  (name servers, SOA, SPF, DMARC, MTA-STS, CAA, DNSSEC, with ranked findings), DNSSEC test (DS, DNSKEY,
  validation, signature expiry), DNS propagation (five public resolvers over the DNS wire format),
  reverse DNS (with forward confirmation), WHOIS through RDAP (domain, IP and AS number), abuse
  contacts (registrar plus network owner), and ASN and routing
- Two new offline tools: MAC vendor lookup (IEEE MA-L, MA-M and MA-S, bundled as `site/data/oui.json`,
  flags randomized and group addresses) and a free, disposable and ISP email check with an optional
  mail-host step
- Auto-detect: the toolkit hub has a "paste anything" box, and the home page search box now lists
  matching toolkit tools as you type. It recognizes IPs, CIDR ranges, domains, URLs, emails, hashes,
  MAC addresses, AS numbers, timestamps, encoded text, JWTs, CVE IDs and ATT&CK IDs. Tool pages open
  pre-filled from the link; values travel in the URL fragment, never in the query string
- Privacy: private, loopback, link-local, reserved and documentation addresses, and internal names,
  are never sent to outside services (tests were checked by disabling each guard); lookups run only
  when the button is pressed or the link carries `go=1`; each lookup page lists its exact sources in
  its Content-Security-Policy, and offline pages keep `connect-src 'none'`
- Built our own implementations; nothing is copied from third-party sites. Tools that need server-side
  data or vantage points (reverse IP, passive DNS, port scan, traceroute, HTTP headers) are not
  included
- Fixed along the way: IPv6 addresses must stay unencoded in RDAP URLs, RRSIG times arrive as Unix
  seconds from JSON resolvers, error messages no longer blame the network for page bugs, and the
  tuner's number-normalizing regex
- Tests: 505 checks in `tests/kit-test.html`, including the DNS parser against real captured responses
  compared with Cloudflare's own JSON for the same queries
- `scripts/gen_toolkit_pages.py`, `probe_rdap_hosts.py` and `build_oui.py` added to regenerate pages,
  the registry allowlist and the vendor list

## 1.3.0 (2026-10-27)

- New analyst toolkit (`toolkit.html`) with 10 tools, all client-side and all blocked from making
  network requests (`connect-src 'none'`), no cookies, no storage:
  - Decoder: Base64/Base64url, hex, URL, HTML entities, escapes, charcodes, binary, decimal, ROT13,
    reversal, XOR (single byte with optional known text, or your own key), gzip/zlib after Base64,
    automatic layer peeling, UTF-16LE detection (PowerShell -EncodedCommand), hexdump, strings, and
    file signature detection
  - Indicators: defang, refang and extract (URLs, IPv4/IPv6, domains, emails, hashes, CVE and ATT&CK
    IDs) with CSV export and a warning for non-public addresses
  - Timestamps: Unix (s/ms/us/ns), Windows FILETIME, Chrome/WebKit, .NET ticks, Cocoa, Excel serials,
    ISO 8601, Apache, RFC 2822 and syslog text, time zones, all-formats table, time between events
  - IP and CIDR: subnet calculator, range membership, public/private classification (IPv4 and IPv6),
    range to CIDR, subnet splitting, IPv6 compress and expand
  - Hashes and files: hash identification, local MD5/SHA-1/SHA-256/SHA-512/CRC-32 of text or a file
    (up to 256 MB), expected-hash comparison, file type versus extension check
  - Hypothesis worksheet (simplified analysis of competing hypotheses) with Markdown and JSON export
  - Phishing triage with a rough score, next steps by impact, and a ticket note
  - Incident note builder with defanged indicators
  - Reference: Windows Security/System/PowerShell/Sysmon event IDs, logon types, programs to watch,
    ICD 203 estimative language, HTTP status codes
  - Rule tuner: paste an alert, rule and logs; get narrow exclusion candidates for YARA-L, Sigma,
    Splunk, Kusto, regex or plain language, with guardrails (see README)
- Analyst toolkit linked from the Tool Stack page and the Email Checker
- Browser tests for the toolkit (`tests/kit-test.html`, 253 checks), mutation-checked by deliberately
  breaking sanitizing, risk flags, MD5 and defang logic and confirming the tests fail
- Contrast audit across all toolkit pages and states: no text below WCAG AA; phone-width layouts
  checked for horizontal overflow

## 1.2.0 (2026-10-27)

- Dark theme for the whole site (tool stack and email checker): dark navy surfaces, light text,
  red accents kept for the flag-style branding
- Colors are now design tokens (`--surface`, `--heading`, `--link`, ...) instead of hard-coded
  whites and pastels; the old `--navy` is only used for fills, with a separate `--heading` for text
- Status colors (hit / notice / no hit / info) rebuilt for dark backgrounds and checked with a
  browser audit: no text below WCAG contrast (4.5:1, or 3:1 for large text) in any page state
- Form fields get clearer borders (at least 3:1) and a dark native look (`color-scheme: dark`)
- Removed the checker's old rule that forced a white input box on dark-mode browsers

## 1.1.1 (2026-10-27)

- Fixed: the Team Cymru malware-registry row showed a hit with no link. It now offers
  "Verify on VirusTotal" for the same hash (the registry is a DNS service with no page of its own)
- Added a regression test that every planned check offers a link (104 checks total)

## 1.1.0 (2026-10-27)

- IOC pivot now checks free public sources automatically and shows which ones have a hit,
  sorted hits-first, with a one-line summary; a checkbox turns it off (remembered locally)
- Sources: Shodan InternetDB, six spam/abuse DNS blocklists, Tor Project, AlienVault OTX,
  ipinfo, Cloudflare malware-filtering DNS, RDAP registration age, MX/SPF/DMARC, and Team
  Cymru's malware hash registry
- Privacy: private/internal indicators are never sent; URL lookups drop the query string,
  fragment and credentials; email lookups send only the domain; requests omit cookies and referrer
- Failed or timed-out sources show as "Couldn't check" and are counted separately from "No hit"
- Content-Security-Policy connect-src allowlists exactly the hosts used
- Browser test page (tests/lookups-test.html), 82 checks, verified to catch deliberate breakage
- Fixed: the hidden attribute is no longer overridden by button styles

## 1.0.0 (2026-10-27)

- Security Tool Stack: IOC pivot, tool directory, port reference, and email checker
- All client-side; no cookies, analytics, or tracking
