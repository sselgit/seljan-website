# Changelog

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
