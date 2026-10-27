# Changelog

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
