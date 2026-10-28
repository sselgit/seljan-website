#!/usr/bin/env python3
"""Generator for the analyst toolkit pages. Writes plain HTML into the site folder.

Usage: python scripts/gen_toolkit_pages.py [site-dir]

Offline tool pages get connect-src 'none', so they cannot make any network request. Lookup pages list exactly the
public sources they use. The RDAP registry allowlist lives in rdap-cors-hosts.json; refresh it with
probe_rdap_hosts.py when registries change, then run this script again.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SITE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "site")
RDAP_HOSTS = json.load(open(os.path.join(HERE, "rdap-cors-hosts.json"), encoding="utf-8"))

BASE_CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; "
            "connect-src %s; object-src 'none'; base-uri 'self'; form-action 'none'")

DOH_TWO = ["https://dns.google", "https://cloudflare-dns.com"]
DOH_ALL = DOH_TWO + ["https://doh.dns.sb", "https://freedns.controld.com", "https://basic.rethinkdns.com"]
RIR = ["https://rdap.org", "https://rdap.arin.net", "https://rdap.db.ripe.net", "https://rdap.apnic.net",
       "https://rdap.lacnic.net", "https://rdap.afrinic.net", "https://stat.ripe.net"]
REGISTRIES = sorted(set(RIR + ["https://" + h for h in RDAP_HOSTS]))

TOOLS = [
    ("toolkit.html", "All tools"),
    ("tuner.html", "Rule tuner"),
    ("ids.html", "Snort/Suricata"),
    ("decode.html", "Decoder"),
    ("ioc.html", "Indicators"),
    ("time.html", "Timestamps"),
    ("network.html", "IP and CIDR"),
    ("hash.html", "Hashes and files"),
    ("hypothesis.html", "Hypotheses"),
    ("triage.html", "Phishing triage"),
    ("report.html", "Incident note"),
    ("reference.html", "Reference"),
    ("dns.html", "DNS records"),
    ("dnsreport.html", "DNS report"),
    ("dnssec.html", "DNSSEC"),
    ("propagation.html", "Propagation"),
    ("reverse.html", "Reverse DNS"),
    ("whois.html", "WHOIS"),
    ("abuse.html", "Abuse"),
    ("asn.html", "ASN"),
    ("mac.html", "MAC vendor"),
    ("freemail.html", "Free email"),
]

SHIELD = ('<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 4v5c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V7z"/>'
          '<path d="M9 12l2 2 4-4"/></svg>')

PRIVACY = ('<p class="kit-privacy">' + SHIELD +
           '<span><strong>Runs only in your browser.</strong> What you paste or load here is never uploaded, '
           'saved, or sent anywhere. This page cannot make network requests at all, and it uses no cookies or storage. '
           'Reloading or closing the tab clears everything.</span></p>')


STATIC_PRIVACY = ('<p class="kit-privacy">' + SHIELD +
                  '<span><strong>Runs only in your browser.</strong> The vendor list is a file served with this site, '
                  'so nothing you type is sent to anyone. It uses no cookies or storage, and reloading clears everything.</span></p>')


def net_privacy(sources):
    return ('<p class="kit-privacy">' + SHIELD +
            '<span><strong>Looks things up straight from your browser.</strong> When you press the button, '
            'this page asks ' + sources + ' directly, with no cookies and no referrer. We never see the lookup. '
            'Private addresses and internal names are never sent. Nothing is saved, and reloading clears everything.</span></p>')


def page(slug, title, desc, eyebrow, h1, lead, body, scripts, net=None):
    """net: None for an offline page, {'static': True} for a page that only reads its own files,
    or {'hosts': [...], 'sources': 'text'} for a page that queries public sources."""
    if net is None:
        csp, banner = BASE_CSP % "'none'", PRIVACY
    elif net.get("static"):
        csp, banner = BASE_CSP % "'self'", STATIC_PRIVACY
    else:
        csp, banner = BASE_CSP % ("'self' " + " ".join(net["hosts"])), net_privacy(net["sources"])
    nav_links = "\n".join(
        '        <a href="%s"%s>%s</a>' % (href, ' aria-current="page"' if href == slug else "", label)
        for href, label in TOOLS)
    script_tags = "\n".join('  <script src="js/%s" defer></script>' % s for s in (["main.js", "kit.js"] + scripts))
    return f"""<!doctype html>
<html lang="en" class="no-js">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <meta name="referrer" content="no-referrer">
  <title>{title} | SOC Analyst Toolkit</title>
  <meta name="description" content="{desc}">
  <meta name="theme-color" content="#0B1426">
  <meta name="color-scheme" content="dark">
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="css/styles.css">
  <link rel="stylesheet" href="css/tools.css">
  <link rel="stylesheet" href="css/toolkit.css">
</head>
<body>
  <a class="skip-link" href="#main">Skip to content</a>

  <header class="site-header">
    <div class="container header-inner">
      <a class="brand" href="index.html" aria-label="SOC Analyst Toolkit home">
        <span class="brand-text">SOC Analyst <em>Toolkit</em></span>
      </a>
      <button class="nav-toggle" type="button" aria-expanded="false" aria-controls="site-nav">
        <span class="sr-only">Menu</span>
        <svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      </button>
      <nav id="site-nav" class="site-nav" aria-label="Main">
        <a href="index.html#pivot">IOC pivot</a>
        <a href="index.html#directory">Tool directory</a>
        <a href="index.html#ports">Port reference</a>
        <a href="check.html">Email checker</a>
        <a href="toolkit.html" class="btn btn-small">Analyst toolkit</a>
      </nav>
    </div>
  </header>

  <div class="kit-nav">
    <nav class="container kit-nav-inner" aria-label="Analyst toolkit">
{nav_links}
    </nav>
  </div>

  <main id="main">
    <section class="section kit-hero">
      <div class="container">
        <div class="section-head">
          <p class="eyebrow">{eyebrow}</p>
          <h1>{h1}</h1>
          <p>{lead}</p>
        </div>
        <div class="kit-wrap">
{banner}
{body}
        </div>
      </div>
    </section>
  </main>

  <footer class="site-footer">
    <div class="container footer-inner">
      <div class="footer-brand">
        <p class="footer-name">SOC Analyst Toolkit</p>
        <p>A free security tool stack.</p>
      </div>
      <div class="footer-links">
        <a href="index.html">Tool stack</a>
        <a href="toolkit.html">Analyst toolkit</a>
        <a href="tuner.html">Rule tuner</a>
        <a href="check.html">Email checker</a>
      </div>
      <div class="footer-legal">
        <p>&copy; 2026 SOC Analyst Toolkit.</p>
        <p><strong>Privacy:</strong> the analyst toolkit runs in your browser. The offline tools are blocked from
          making any network request. The lookup tools ask the public sources named on each page, directly from your
          browser and only when you press the button. We never receive, store or relay what you type or load.</p>
      </div>
    </div>
  </footer>

{script_tags}
</body>
</html>
"""


def write(slug, html):
    with open(os.path.join(SITE, slug), "w", encoding="utf-8", newline="\n") as f:
        f.write(html)


# ------------------------------------------------------------------ hub
offline_cards = [
    ("tuner.html", "Rule tuner", "Paste an alert, its rule and sample logs. Get narrow exclusion suggestions in YARA-L, Sigma, Splunk, Kusto or regex, with guardrails.", "Featured"),
    ("ids.html", "Snort/Suricata tuner", "Load the false-positive and true-positive captures, paste the rule and alert, and get offset, depth, distance, within and buffer recommendations checked against your traffic.", "Featured"),
    ("decode.html", "Decoder", "Base64, hex, URL, escapes, charcodes, XOR and compressed data. Peels layers automatically and inspects bytes.", ""),
    ("ioc.html", "Indicators", "Defang and refang links and addresses, and pull every indicator out of a block of text.", ""),
    ("time.html", "Timestamps", "Convert Unix, Windows FILETIME, WebKit and more. Handle log formats and time zones, and find the gap between two events.", ""),
    ("network.html", "IP and CIDR", "Subnet math, range checks, private versus public, IPv6 helpers, range to CIDR.", ""),
    ("hash.html", "Hashes and files", "Identify a hash, hash text or a file locally, and check whether a file's contents match its extension.", ""),
    ("mac.html", "MAC vendor", "Who made a network card, from the IEEE list built into the site. Spots randomized private addresses.", ""),
    ("freemail.html", "Free email check", "Is this a free, disposable or internet-provider mail domain? Optionally see who hosts the mail.", ""),
    ("hypothesis.html", "Hypothesis worksheet", "Weigh competing explanations against the evidence so you do not lock onto the first idea.", ""),
    ("triage.html", "Phishing triage", "Walk through the signals, get a rough read and next steps, and copy a ticket note.", ""),
    ("report.html", "Incident note", "Fill in a short form and get a clean Markdown note with defanged indicators.", ""),
    ("reference.html", "Reference", "Windows, Sysmon and PowerShell event IDs, logon types, programs to watch, estimative language.", ""),
]
online_cards = [
    ("dns.html", "DNS records", "A, AAAA, MX, NS, TXT, SOA, CAA, DNSKEY and more from a public resolver.", "Looks up online"),
    ("dnsreport.html", "DNS report", "Name servers, SPF, DMARC, MTA-STS, CAA and DNSSEC with plain-language findings.", "Looks up online"),
    ("dnssec.html", "DNSSEC test", "Does the chain of trust validate? Keys, algorithms and signature expiry.", "Looks up online"),
    ("propagation.html", "DNS propagation", "Compare the answers of five public resolvers to see whether a change has spread.", "Looks up online"),
    ("reverse.html", "Reverse DNS", "PTR records for addresses, and whether each name points back (forward-confirmed).", "Looks up online"),
    ("whois.html", "WHOIS (RDAP)", "Registration, age, expiry, registrar and name servers for a domain, IP or AS number.", "Looks up online"),
    ("abuse.html", "Abuse contacts", "Who to report a domain or IP to: the registrar and the network owner.", "Looks up online"),
    ("asn.html", "ASN and routing", "Which network announces an address or owns an AS number, and what it announces.", "Looks up online"),
]


def card_html(items):
    return "\n".join(
        '          <a class="kit-card" href="%s"><h3>%s</h3><p>%s</p>%s</a>' % (
            h, t, d, ('<span class="kit-tag">%s</span>' % tag) if tag else "")
        for h, t, d, tag in items)


write("toolkit.html", page(
    "toolkit.html", "Analyst Toolkit",
    "Free browser-based tools for security analysts: paste anything and get the right tool. Decoding, indicators, DNS, WHOIS, rule tuning and more.",
    "Analyst toolkit", "Tools for the work between the alert and the answer",
    "Paste anything and we will find the tools that fit. Decode it, look it up, line up the timeline, weigh the explanations, and tune the rule that keeps firing.",
    """          <div class="kit-panel">
            <h2>Paste anything</h2>
            <p class="sub">An IP address, domain, URL, email, hash, MAC address, AS number, timestamp, encoded text, or a block of notes.
              We work out what it is and list every tool that can handle it. Nothing is looked up until you open a tool.</p>
            <label class="kit-label" for="ks-in">What do you have?</label>
            <textarea id="ks-in" class="kit wrap" rows="2" spellcheck="false" autocomplete="off" placeholder="8.8.8.8     login-portal[.]example     00:1A:2B:3C:4D:5E     AS15169     SGVsbG8gV29ybGQ="></textarea>
            <div id="kit-routes" class="kit-routes" hidden></div>
            <p id="ks-empty" class="kit-note" hidden>That does not look like something I recognize. Try the <a href="decode.html">decoder</a> or the <a href="ioc.html">indicator extractor</a>.</p>
          </div>
          <h2 class="kit-h2">Analyze and decode <span class="kit-sub">offline, nothing leaves your browser</span></h2>
          <div class="kit-grid">
%s
          </div>
          <h2 class="kit-h2">Look things up <span class="kit-sub">your browser asks public sources directly</span></h2>
          <div class="kit-grid">
%s
          </div>
          <p class="kit-note">Looking for reputation checks, the port reference, or the email checker?
            Those are in the <a href="index.html">Security Tool Stack</a> and the <a href="check.html">Email Checker</a>.
            Reputation sources such as VirusTotal and AbuseIPDB do not allow requests from web pages, so they stay as links there.</p>""" % (card_html(offline_cards), card_html(online_cards)),
    ["network.js", "router.js", "search.js"]))

# ------------------------------------------------------------------ decoder
write("decode.html", page(
    "decode.html", "Decoder",
    "Decode Base64, hex, URL encoding, escapes, character codes and XOR in your browser. Peels layers automatically.",
    "Decoder", "What is hiding in this string?",
    "Paste an odd-looking string. We try the common encodings, peel layers one after another, and let you inspect the raw bytes.",
    """          <div class="kit-panel">
            <label class="kit-label" for="dec-input">Encoded text</label>
            <textarea id="dec-input" class="kit wrap" rows="6" spellcheck="false" placeholder="Paste Base64, hex, a URL-encoded string, \\u0041 escapes, a PowerShell -EncodedCommand value..."></textarea>
            <div class="kit-row">
              <button type="button" id="dec-run" class="btn">Try every decoding</button>
              <button type="button" id="dec-peel" class="btn btn-ghost">Peel layers automatically</button>
              <label class="btn btn-ghost file-btn">Load a file to inspect<input type="file" id="dec-file" hidden></label>
              <button type="button" id="dec-sample" class="btn btn-ghost">Try a sample</button>
              <button type="button" id="dec-clear" class="btn btn-ghost">Clear</button>
            </div>
            <p id="dec-file-name" class="kit-note"></p>
            <p class="kit-note">Files up to 20 MB are read locally and never uploaded. Be careful with real malware: this tool only reads bytes and
              never runs anything, but handle samples in a safe environment.</p>
          </div>
          <div id="dec-results" class="kit-results" aria-live="polite"></div>
          <div id="dec-peel-out" class="kit-results" aria-live="polite"></div>
          <div id="dec-inspect" class="kit-panel" hidden></div>

          <div class="kit-panel">
            <h2>XOR tester</h2>
            <p class="sub">Some malware and obfuscated data is scrambled with a repeating key. Try every one-byte key, or enter your own key.</p>
            <div class="kit-cols three">
              <div><label class="kit-label" for="xor-mode">The input box above holds</label>
                <select id="xor-mode" class="kit"><option value="text">Plain text</option><option value="hex">Hex bytes</option><option value="base64">Base64</option></select></div>
              <div><label class="kit-label" for="xor-crib">Text you expect to find <small>(optional)</small></label>
                <input id="xor-crib" class="kit" type="text" placeholder="http, This program, MZ" spellcheck="false"></div>
              <div><label class="kit-label" for="xor-key">Your own key <small>(hex like 0a1b or text)</small></label>
                <input id="xor-key" class="kit" type="text" spellcheck="false"></div>
            </div>
            <div class="kit-row"><button type="button" id="xor-run" class="btn">Run XOR</button></div>
            <div id="xor-out" class="kit-results"></div>
          </div>""",
    ["decode.js"]))

# ------------------------------------------------------------------ indicators
write("ioc.html", page(
    "ioc.html", "Indicators",
    "Defang and refang links, IPs and email addresses, and extract indicators from text. Runs in your browser.",
    "Indicators", "Make indicators safe to share, and find them in a pile of text",
    "Defang addresses so they cannot be clicked by accident, restore them for lookups, or paste a whole report and pull out every indicator.",
    """          <div class="kit-panel">
            <label class="kit-label" for="ioc-in">Text with links, addresses, hashes or email</label>
            <textarea id="ioc-in" class="kit wrap tall" spellcheck="false" placeholder="Paste a report, ticket, email body or list of indicators..."></textarea>
            <div class="kit-row">
              <button type="button" id="ioc-defang" class="btn">Defang</button>
              <button type="button" id="ioc-refang" class="btn btn-ghost">Refang</button>
              <button type="button" id="ioc-extract" class="btn btn-ghost">Extract indicators</button>
              <button type="button" id="ioc-sample" class="btn btn-ghost">Try a sample</button>
              <button type="button" id="ioc-clear" class="btn btn-ghost">Clear</button>
            </div>
            <p class="kit-label">Result</p>
            <div id="ioc-out" class="kit-out empty" aria-live="polite"></div>
            <div class="kit-row tight"><button type="button" id="ioc-copy" class="btn btn-small btn-ghost" disabled>Copy result</button></div>
            <p class="kit-note">Defanging changes <code>http://evil.com</code> into <code>hxxp://evil[.]com</code> so it is not clickable. Words that look like
              file names (for example <code>setup.exe</code>) are left alone, so check the result.</p>
          </div>
          <div id="ioc-extract-out"></div>""",
    ["network.js", "ioc.js"]))

# ------------------------------------------------------------------ time
write("time.html", page(
    "time.html", "Timestamps",
    "Convert Unix, Windows FILETIME, Chrome/WebKit and other timestamps, log date formats and time zones.",
    "Timestamps", "What time was that, really?",
    "Paste a timestamp from a log, a database or a file. We show every plausible reading, in UTC and in the zone you choose.",
    """          <div class="kit-panel">
            <label class="kit-label" for="time-in">Timestamp</label>
            <input id="time-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="1700000000   133444736000000000   2026-10-27 13:55:36   27/Oct/2026:13:55:36 -0400">
            <div class="kit-cols two">
              <div><label class="kit-label" for="time-assume">If the text has no time zone, assume</label><select id="time-assume" class="kit"></select></div>
              <div><label class="kit-label" for="time-show">Show times in</label><select id="time-show" class="kit"></select></div>
            </div>
            <div class="kit-row"><button type="button" id="time-now" class="btn btn-ghost">Use the current time</button></div>
            <p class="kit-note">Numbers are read as Unix seconds, milliseconds, microseconds or nanoseconds, Windows FILETIME, Chrome/WebKit time, .NET ticks,
              Apple Cocoa time and Excel serials. Years before 1996 or after 2100 are marked unlikely.</p>
          </div>
          <div id="time-out" class="kit-results" aria-live="polite"></div>
          <div id="time-all" class="kit-panel" hidden></div>
          <div class="kit-panel">
            <h2>Time between two events</h2>
            <div class="kit-cols two">
              <div><label class="kit-label" for="diff-a">First</label><input id="diff-a" class="kit" type="text" spellcheck="false"></div>
              <div><label class="kit-label" for="diff-b">Second</label><input id="diff-b" class="kit" type="text" spellcheck="false"></div>
            </div>
            <div class="kit-row"><button type="button" id="diff-run" class="btn">Find the gap</button></div>
            <div id="diff-out"></div>
          </div>""",
    ["time.js"]))

# ------------------------------------------------------------------ network
write("network.html", page(
    "network.html", "IP and CIDR",
    "Subnet calculator, range checks, public versus private address classification and IPv6 helpers. Runs in your browser.",
    "IP and CIDR", "Network math without the spreadsheet",
    "Work out a subnet, check whether an address sits in a range, tell public from private, and convert a range into CIDR blocks.",
    """          <div class="kit-panel">
            <h2>Subnet calculator</h2>
            <label class="kit-label" for="net-cidr">IPv4 address or CIDR range</label>
            <input id="net-cidr" class="kit" type="text" spellcheck="false" placeholder="10.20.30.0/24">
            <div class="kit-row"><button type="button" id="net-cidr-run" class="btn">Calculate</button></div>
            <div id="net-cidr-out"></div>
          </div>
          <div class="kit-panel">
            <h2>Is this address in these ranges?</h2>
            <div class="kit-cols two">
              <div><label class="kit-label" for="net-in-ips">Addresses <small>(IPv4 or IPv6, spaces or commas)</small></label><textarea id="net-in-ips" class="kit wrap" spellcheck="false" placeholder="10.1.2.3 8.8.8.8"></textarea></div>
              <div><label class="kit-label" for="net-in-ranges">Ranges</label><textarea id="net-in-ranges" class="kit wrap" spellcheck="false" placeholder="10.0.0.0/8 192.168.0.0/16"></textarea></div>
            </div>
            <div class="kit-row"><button type="button" id="net-in-run" class="btn">Check</button></div>
            <div id="net-in-out"></div>
          </div>
          <div class="kit-panel">
            <h2>Public or private?</h2>
            <p class="sub">Paste a list. Private, link-local, documentation and other non-public addresses should not be sent to outside lookup services.</p>
            <textarea id="net-cls-in" class="kit wrap" spellcheck="false" placeholder="One address per line"></textarea>
            <div class="kit-row"><button type="button" id="net-cls-run" class="btn">Classify</button></div>
            <div id="net-cls-out"></div>
          </div>
          <div class="kit-panel">
            <h2>Range to CIDR blocks</h2>
            <div class="kit-cols two">
              <div><label class="kit-label" for="net-range-a">First address</label><input id="net-range-a" class="kit" type="text" spellcheck="false" placeholder="10.0.0.5"></div>
              <div><label class="kit-label" for="net-range-b">Last address</label><input id="net-range-b" class="kit" type="text" spellcheck="false" placeholder="10.0.0.200"></div>
            </div>
            <div class="kit-row"><button type="button" id="net-range-run" class="btn">Convert</button></div>
            <div id="net-range-out"></div>
          </div>
          <div class="kit-panel">
            <h2>Split a subnet</h2>
            <div class="kit-cols two">
              <div><label class="kit-label" for="net-split-cidr">Network</label><input id="net-split-cidr" class="kit" type="text" spellcheck="false" placeholder="10.0.0.0/16"></div>
              <div><label class="kit-label" for="net-split-prefix">Split into prefix length</label><input id="net-split-prefix" class="kit" type="number" min="1" max="32" value="24"></div>
            </div>
            <div class="kit-row"><button type="button" id="net-split-run" class="btn">Split</button></div>
            <div id="net-split-out"></div>
          </div>
          <div class="kit-panel">
            <h2>IPv6 helper</h2>
            <label class="kit-label" for="net-v6">IPv6 address</label>
            <input id="net-v6" class="kit" type="text" spellcheck="false" placeholder="2001:0db8:0000:0000:0000:ff00:0042:8329">
            <div class="kit-row"><button type="button" id="net-v6-run" class="btn">Compress and expand</button></div>
            <div id="net-v6-out"></div>
          </div>""",
    ["network.js"]))

# ------------------------------------------------------------------ hash
write("hash.html", page(
    "hash.html", "Hashes and files",
    "Identify a hash, compute MD5, SHA-1, SHA-256 and SHA-512 locally, and check a file's type against its extension.",
    "Hashes and files", "What kind of hash is this, and is that file what it claims to be?",
    "Identify a hash by its shape, hash text or a file without uploading it, and compare against an expected value.",
    """          <div class="kit-panel">
            <h2>Identify a hash</h2>
            <label class="kit-label" for="hash-id-in">Hash or password-hash string</label>
            <input id="hash-id-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592">
            <div class="kit-row"><button type="button" id="hash-id-run" class="btn">Identify</button></div>
            <div id="hash-id-out"></div>
            <p class="kit-note">Do not paste live passwords or real credential hashes from systems you do not own. Use samples where you can.</p>
          </div>
          <div class="kit-panel">
            <h2>Compute hashes</h2>
            <label class="kit-label" for="hash-text">Text</label>
            <textarea id="hash-text" class="kit wrap" spellcheck="false" placeholder="Type or paste text. It is hashed as UTF-8, so a trailing newline changes the result."></textarea>
            <div class="kit-row">
              <button type="button" id="hash-text-run" class="btn">Hash the text</button>
              <label class="btn btn-ghost file-btn">Hash a file<input type="file" id="hash-file" hidden></label>
            </div>
            <p id="hash-file-name" class="kit-note"></p>
            <label class="kit-label" for="hash-expect">Expected hash to compare <small>(optional)</small></label>
            <input id="hash-expect" class="kit" type="text" spellcheck="false" autocomplete="off">
            <div id="hash-out" aria-live="polite"></div>
            <p class="kit-note">Files up to 256 MB are read in your browser and never uploaded. The file type check also looks at the first bytes of the file
              and tells you whether the extension matches.</p>
          </div>""",
    ["decode.js", "hash.js"]))

# ------------------------------------------------------------------ reference
write("reference.html", page(
    "reference.html", "Reference",
    "Windows Security, System, PowerShell and Sysmon event IDs, logon types, programs worth a second look and estimative language.",
    "Reference", "Look it up fast",
    "Event IDs, logon types, programs that deserve a second look and the words for probability, all searchable in one place.",
    """          <div class="kit-panel">
            <label class="kit-label" for="ref-search">Search all tables</label>
            <input id="ref-search" class="kit" type="search" spellcheck="false" placeholder="4624, lsass, scheduled task, likely...">
            <p class="kit-note">For port numbers and services, use the <a href="index.html#ports">port reference</a> on the Tool Stack page.
              The LOLBAS project (<a href="https://lolbas-project.github.io/" target="_blank" rel="noopener noreferrer">lolbas-project.github.io</a>)
              documents built-in Windows programs that can be misused, in much more detail.</p>
          </div>
          <div id="ref-tables"></div>
          <noscript><p class="kit-note">This page needs JavaScript to show its tables.</p></noscript>""",
    ["reference.js"]))

# ------------------------------------------------------------------ hypothesis
write("hypothesis.html", page(
    "hypothesis.html", "Hypothesis worksheet",
    "A simplified analysis of competing hypotheses: weigh the evidence against each explanation and export your reasoning.",
    "Hypothesis worksheet", "Test your explanation before you commit to it",
    "List the possible explanations, rate each piece of evidence against each one, and see which explanation has the least evidence against it.",
    """          <div class="kit-callout">
            <p><strong>How to use it.</strong> Write the question, then at least two explanations that could be true (for example "phishing" and "legitimate admin task").
              Add evidence you actually observed and mark whether it is consistent with each explanation, inconsistent, or neutral.
              The score counts the weight of evidence <em>against</em> each one, because disproving is stronger than confirming.</p>
            <p>Your work is not saved anywhere. Use <em>Save to file</em> to keep it and <em>Load</em> to continue later.</p>
          </div>
          <div class="kit-panel">
            <label class="kit-label" for="ach-question">The question you are answering</label>
            <input id="ach-question" class="kit" type="text" placeholder="e.g. Why did WS-0142 run a hidden script at 13:41?">
            <div class="kit-row">
              <button type="button" id="ach-add-h" class="btn btn-small btn-ghost">Add hypothesis</button>
              <button type="button" id="ach-add-e" class="btn btn-small btn-ghost">Add evidence</button>
            </div>
            <div id="ach-matrix"></div>
            <h3>Where the evidence points</h3>
            <div id="ach-scores" class="kit-results"></div>
          </div>
          <div class="kit-panel">
            <h2>Assessment</h2>
            <div class="kit-cols three">
              <div><label class="kit-label" for="ach-lead">Leading hypothesis</label><select id="ach-lead" class="kit"></select></div>
              <div><label class="kit-label" for="ach-term">How likely is it?</label><select id="ach-term" class="kit"></select></div>
              <div><label class="kit-label" for="ach-conf">Confidence in your sources and reasoning</label>
                <select id="ach-conf" class="kit"><option value="">(choose)</option><option>Low: thin or conflicting sources</option><option>Moderate: credible sources, some gaps</option><option>High: strong, corroborated sources</option></select></div>
            </div>
            <p class="kit-note">Likelihood and confidence are different things. "Likely, with low confidence" is a fair thing to write when the sources are thin.
              The likelihood words follow the published ICD 203 scale; see the <a href="reference.html">reference page</a>.</p>
            <label class="kit-label" for="ach-change">What would change my mind?</label>
            <textarea id="ach-change" class="kit wrap" rows="3"></textarea>
            <label class="kit-label" for="ach-assume">Assumptions I am making</label>
            <textarea id="ach-assume" class="kit wrap" rows="3"></textarea>
            <label class="kit-label" for="ach-next">Next steps and data still needed</label>
            <textarea id="ach-next" class="kit wrap" rows="3"></textarea>
            <div class="kit-row">
              <button type="button" id="ach-copy" class="btn">Copy as Markdown</button>
              <button type="button" id="ach-md" class="btn btn-ghost">Download Markdown</button>
              <button type="button" id="ach-save" class="btn btn-ghost">Save to file</button>
              <label class="btn btn-ghost file-btn">Load<input type="file" id="ach-load" accept=".json,application/json" hidden></label>
              <button type="button" id="ach-reset" class="btn btn-ghost">Start over</button>
            </div>
          </div>
          <details class="kit-details">
            <summary>Thinking traps to watch for</summary>
            <ul>
              <li><strong>Anchoring:</strong> the first explanation you hear tends to stick. List alternatives before you look for proof.</li>
              <li><strong>Confirmation bias:</strong> we notice evidence that agrees with us. Ask what would prove you wrong.</li>
              <li><strong>Absence of evidence:</strong> a missing log may mean nothing happened, or that nothing was recording.</li>
              <li><strong>Familiar equals safe:</strong> a trusted tool name can still be used by someone else.</li>
              <li><strong>Sunk cost:</strong> if the evidence turns against your theory, say so, even after hours of work.</li>
            </ul>
          </details>""",
    ["hypothesis.js"]))

# ------------------------------------------------------------------ triage
write("triage.html", page(
    "triage.html", "Phishing triage",
    "Answer a few questions about a suspicious email and get a rough assessment, suggested next steps and a ticket note.",
    "Phishing triage", "Is this email a problem, and what do I do next?",
    "Work through the signals one by one. You get a rough read, the steps that fit what happened, and a note you can paste into a ticket.",
    """          <div class="kit-callout">
            <p><strong>This is a guide, not a verdict.</strong> It adds up signals; it cannot open the message for you.
              To have the warning signs found in the raw email automatically, use the <a href="check.html">Email Checker</a> first, then come back here.</p>
          </div>
          <div class="kit-panel">
            <h2>What do you see?</h2>
            <div id="tri-questions"></div>
            <h3>What happened?</h3>
            <div id="tri-impact"></div>
          </div>
          <div class="kit-panel">
            <h2>Result</h2>
            <div id="tri-result" aria-live="polite"></div>
          </div>
          <div class="kit-panel">
            <h2>Ticket note</h2>
            <div class="kit-cols two">
              <div><label class="kit-label" for="tri-ref">Ticket or case number <small>(optional)</small></label><input id="tri-ref" class="kit" type="text"></div>
              <div><label class="kit-label" for="tri-extra">Your own notes <small>(optional)</small></label><input id="tri-extra" class="kit" type="text"></div>
            </div>
            <textarea id="tri-note" class="kit wrap tall" readonly></textarea>
            <div class="kit-row">
              <button type="button" id="tri-copy" class="btn">Copy note</button>
              <button type="button" id="tri-reset" class="btn btn-ghost">Start over</button>
            </div>
          </div>""",
    ["triage.js"]))

# ------------------------------------------------------------------ report
write("report.html", page(
    "report.html", "Incident note",
    "Fill in a short form and get a clean Markdown incident note with defanged indicators.",
    "Incident note", "Write it up once, clearly",
    "Fill in what you know. The note builds as you type, with indicators defanged so they are safe to paste anywhere.",
    """          <div class="kit-panel">
            <label class="kit-label" for="rep-title">Title</label>
            <input id="rep-title" class="kit" type="text" placeholder="e.g. Suspicious PowerShell on WS-0142">
            <div class="kit-cols three">
              <div><label class="kit-label" for="rep-severity">Severity</label><select id="rep-severity" class="kit"><option value="">(choose)</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option></select></div>
              <div><label class="kit-label" for="rep-status">Status</label><select id="rep-status" class="kit"><option value="">(choose)</option><option>Investigating</option><option>Contained</option><option>Resolved</option><option>False positive</option></select></div>
              <div><label class="kit-label" for="rep-analyst">Analyst</label><input id="rep-analyst" class="kit" type="text"></div>
            </div>
            <label class="kit-label" for="rep-detected">First detected (UTC)</label>
            <div class="kit-row tight"><input id="rep-detected" class="kit kit-narrow" type="text" placeholder="2026-10-27T13:55:36Z"><button type="button" id="rep-now" class="btn btn-small btn-ghost">Use now</button></div>
            <label class="kit-label" for="rep-summary">Summary</label>
            <textarea id="rep-summary" class="kit wrap" rows="4" placeholder="What happened, in two or three sentences."></textarea>
            <label class="kit-label" for="rep-impact">Impact and scope</label>
            <textarea id="rep-impact" class="kit wrap" rows="3" placeholder="Which systems, accounts or data are affected?"></textarea>
            <label class="kit-label" for="rep-timeline">Timeline (UTC) <small>one event per line</small></label>
            <textarea id="rep-timeline" class="kit wrap" rows="5" placeholder="13:41 Excel started PowerShell&#10;13:55 Host isolated"></textarea>
            <label class="kit-label" for="rep-indicators">Indicators <small>one per line; shown defanged in the note</small></label>
            <textarea id="rep-indicators" class="kit wrap" rows="4"></textarea>
            <div class="kit-row tight"><button type="button" id="rep-extract" class="btn btn-small btn-ghost">Pull indicators from the summary, timeline and actions</button></div>
            <label class="kit-label" for="rep-actions">Actions taken</label>
            <textarea id="rep-actions" class="kit wrap" rows="3"></textarea>
            <label class="kit-label" for="rep-recommendations">Recommendations</label>
            <textarea id="rep-recommendations" class="kit wrap" rows="3"></textarea>
            <label class="kit-label" for="rep-open">Open questions</label>
            <textarea id="rep-open" class="kit wrap" rows="3"></textarea>
          </div>
          <div class="kit-panel">
            <h2>Your note</h2>
            <div id="rep-out" class="kit-out" aria-live="polite"></div>
            <div class="kit-row">
              <button type="button" id="rep-copy" class="btn">Copy Markdown</button>
              <button type="button" id="rep-download" class="btn btn-ghost">Download .md</button>
            </div>
          </div>""",
    ["network.js", "ioc.js", "report.js"]))

# ------------------------------------------------------------------ tuner
write("tuner.html", page(
    "tuner.html", "Rule Tuner",
    "Paste an alert, its rule and sample logs, and get narrow, guard-railed exclusion suggestions for YARA-L, Sigma, Splunk, Kusto or regex.",
    "Rule tuner", "Cut the noise without cutting the coverage",
    "Paste a noisy alert, the rule behind it and some of the logs. We look for a narrow, defensible exclusion, show what it would hide, and refuse to hide anything that looks like an attack.",
    """          <div class="kit-callout warn">
            <p><strong>Read this first.</strong></p>
            <ul>
              <li><strong>Your logs stay in your browser,</strong> but they can still contain sensitive details. Use <em>Replace my identifying values</em> below. It swaps IP addresses for generic ones
                (like 192.0.2.1), emails for example.com and user folder names for USER1. Put your own values back before you use a rule.</li>
              <li><strong>Tuning is not the same as fixing.</strong> Only exclude activity after you have searched historical data and confirmed what causes it. Rule text stays locked until you confirm that.</li>
              <li><strong>Some activity must never be excluded,</strong> for example an Office program starting PowerShell. These are flagged and locked. See the examples at the bottom of the page.</li>
              <li><strong>This is a helper, not a judge.</strong> It finds patterns in the sample you give it. A person has to check the result and test it.</li>
            </ul>
          </div>

          <div class="kit-panel">
            <h2>1. Choose your rule format</h2>
            <label class="kit-label" for="tn-format">What does your detection platform use?</label>
            <select id="tn-format" class="kit"><option value="">Choose a format...</option></select>
            <p class="kit-note">Suggestions are written in this format. If yours is not listed, pick "Other" and translate the plain-language conditions.</p>
          </div>

          <div class="kit-panel">
            <h2>2. Paste what you have</h2>
            <label class="kit-label" for="tn-alert">The alert <small>(optional: title, severity, counts)</small></label>
            <textarea id="tn-alert" class="kit wrap" rows="3" spellcheck="false"></textarea>
            <label class="kit-label" for="tn-rule">The rule <small>(optional but helpful)</small></label>
            <textarea id="tn-rule" class="kit" rows="8" spellcheck="false"></textarea>
            <label class="kit-label" for="tn-logs">Log events that triggered it <small>(JSON, JSON lines, key=value, CSV, Event Viewer text, or one line per event)</small></label>
            <textarea id="tn-logs" class="kit tall" spellcheck="false"></textarea>
            <div class="kit-row">
              <button type="button" id="tn-sample" class="btn btn-ghost">Load a sample</button>
              <button type="button" id="tn-clear" class="btn btn-ghost">Clear everything</button>
            </div>
          </div>

          <div class="kit-panel">
            <h2>3. Replace my identifying values</h2>
            <p class="sub">Recommended before you share a screen or copy any output. Everything happens in this page.</p>
            <label class="kit-check"><input type="checkbox" id="tn-san-ips" checked> Replace IP addresses with generic ones (192.0.2.x, 198.51.100.x, 2001:db8::x)</label>
            <label class="kit-check"><input type="checkbox" id="tn-san-emails" checked> Replace email addresses</label>
            <label class="kit-check"><input type="checkbox" id="tn-san-users" checked> Replace user folder names (C:\\Users\\name becomes USER1, also elsewhere in the text)</label>
            <label class="kit-label" for="tn-san-terms">Anything else to replace <small>(host names, company names, one per line)</small></label>
            <textarea id="tn-san-terms" class="kit wrap" rows="3" spellcheck="false"></textarea>
            <div class="kit-row"><button type="button" id="tn-san-run" class="btn">Replace in the boxes above</button></div>
            <div id="tn-san-out"></div>
            <p class="kit-note">Version-like numbers such as 1.2.3.4 can look like IP addresses and get replaced. Check the result looks right.</p>
          </div>

          <div class="kit-panel">
            <h2>4. Analyze</h2>
            <div class="kit-row"><button type="button" id="tn-run" class="btn">Find safe exclusions</button></div>
          </div>

          <div id="tn-results" hidden></div>

          <div class="kit-panel">
            <h2>When activity is abnormal</h2>
            <p class="sub">These patterns are the ones attackers rely on. They should be investigated, not tuned away.</p>
            <div id="tn-abnormal"></div>
          </div>
          <div class="kit-panel">
            <h2>When tuning is usually reasonable</h2>
            <p class="sub">Even then, check the history and keep the exclusion narrow.</p>
            <div id="tn-routine"></div>
          </div>
          <div class="kit-panel">
            <h2>How to do the historical check</h2>
            <div id="tn-historical"></div>
          </div>""",
    ["network.js", "attack-map.js", "attack-ui.js", "tuner-data.js", "tuner-core.js", "tuner.js"]))

# ------------------------------------------------------------------ Snort/Suricata tuner
write("ids.html", page(
    "ids.html", "Snort and Suricata Tuner",
    "Load the packet captures and the rule, and get offset, depth, distance, within and buffer recommendations checked against your traffic, for Suricata and Snort.",
    "Snort/Suricata tuner", "Tune a rule with the traffic in hand",
    "Load a capture of the false positive, optionally a capture of the real activity, and the rule. We show why it fired, where the strings sit, and the narrowest rule change that fixes it, re-checked against both captures.",
"""          <div class="kit-callout warn">
            <p><strong>Read this first.</strong></p>
            <ul>
              <li><strong>Your captures stay in your browser.</strong> They are read here and never uploaded. They can still contain sensitive data, so use the address masking below before you share a screen or copy any text.</li>
              <li><strong>The numbers come from a simulation.</strong> It follows Suricata and Snort matching rules for the options it supports and says when it has to guess. The engine is the final judge: the page gives you the command to check every change.</li>
              <li><strong>Tuning is not the same as fixing.</strong> Only change a rule after you have checked the history and know what causes the alert. Rule text stays locked until you confirm that.</li>
              <li><strong>A tuned rule can be dodged.</strong> The narrower the window, the easier it is to move an attack outside it. Each suggestion shows its risk.</li>
            </ul>
          </div>

          <div class="kit-panel">
            <h2>1. Your engine and rule</h2>
            <label class="kit-label" for="ids-engine">Which engine runs the rule?</label>
            <select id="ids-engine" class="kit">
              <option value="">Choose an engine...</option>
              <option value="suricata">Suricata 6 or 7</option>
              <option value="snort3">Snort 3</option>
              <option value="snort2">Snort 2</option>
            </select>
            <label class="kit-label" for="ids-rule">The rule that fired</label>
            <textarea id="ids-rule" class="kit" rows="5" spellcheck="false"></textarea>
            <label class="kit-label" for="ids-alert">The alert <small>(optional: Suricata EVE JSON or fast.log, or Snort alert_fast)</small></label>
            <textarea id="ids-alert" class="kit" rows="3" spellcheck="false"></textarea>
          </div>

          <div class="kit-panel">
            <h2>2. Your captures</h2>
            <label class="kit-label" for="ids-fp-file">False-positive capture <small>(required: traffic that should not have alerted. .pcap, .pcapng or .gz)</small></label>
            <input type="file" id="ids-fp-file" class="kit" accept=".pcap,.pcapng,.cap,.gz">
            <div id="ids-fp-info" class="kit-note"></div>
            <label class="kit-label" for="ids-tp-file">True-positive capture <small>(optional but strongly recommended: the real activity the rule must keep catching)</small></label>
            <input type="file" id="ids-tp-file" class="kit" accept=".pcap,.pcapng,.cap,.gz">
            <div id="ids-tp-info" class="kit-note"></div>
            <p class="kit-note">Without a true-positive capture the page can only describe what matched. It cannot prove a change keeps detecting the attack.</p>
          </div>

          <div class="kit-panel">
            <h2>3. Hide real addresses</h2>
            <label class="kit-check"><input type="checkbox" id="ids-mask" checked> Replace IP addresses in the results with generic ones (192.0.2.x, 2001:db8::x). Untick to see your real addresses.</label>
          </div>

          <div class="kit-panel">
            <h2>4. Analyze</h2>
            <div class="kit-row">
              <button type="button" id="ids-run" class="btn">Find the right offset, depth and distance</button>
              <button type="button" id="ids-clear" class="btn btn-ghost">Clear everything</button>
            </div>
            <p class="sub">Or try an example (it builds a small capture in this page):</p>
            <div class="kit-row" id="ids-examples"></div>
            <p class="kit-note" id="ids-example-note"></p>
          </div>

          <div id="ids-results" hidden></div>

          <div class="kit-panel">
            <h2>What offset, depth, distance and within mean</h2>
            <div id="ids-cheat"></div>
          </div>
          <div class="kit-panel">
            <h2>When network activity is abnormal</h2>
            <p class="sub">These patterns deserve investigation, not tuning.</p>
            <div id="ids-abnormal"></div>
          </div>
          <div class="kit-panel">
            <h2>When tuning is usually reasonable</h2>
            <div id="ids-routine"></div>
          </div>
          <div class="kit-panel">
            <h2>How to do the historical check</h2>
            <div id="ids-historical"></div>
          </div>""",
    ["network.js", "pcap.js", "pcap-build.js", "ids-engine.js", "ids-tune.js", "ids-data.js", "attack-map.js", "attack-ui.js", "ids-tuner.js"]))

# ------------------------------------------------------------------ lookup pages (use public sources)
LOOKUP_SCRIPTS = ["network.js", "router.js", "netlookup.js", "lookup-ui.js"]


def resolver_field(prefix):
    return ('<div><label class="kit-label" for="%s-resolver">Resolver</label>'
            '<select id="%s-resolver" class="kit"></select></div>' % (prefix, prefix))


write("dns.html", page(
    "dns.html", "DNS Records",
    "Look up A, AAAA, MX, NS, TXT, SOA, CAA, DNSKEY and other DNS records for a domain, straight from a public resolver in your browser.",
    "DNS records", "What does DNS say about this domain?",
    "Pick the record types you want and ask a public resolver. Results show the type, name, how long they may be cached, and the data.",
    """          <div class="kit-panel">
            <label class="kit-label" for="dns-in">Domain name</label>
            <input id="dns-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="example.com">
            <p class="kit-label">Record types</p>
            <div id="dns-types" class="kit-row tight"></div>
            <div class="kit-cols two">
              %s
            </div>
            <div class="kit-row"><button type="button" id="dns-run" class="btn">Look up</button></div>
            <p class="kit-note">A URL or an email address works too: the host or domain is used. Internal names such as <code>printer.local</code> are refused.</p>
          </div>
          <div id="dns-out" aria-live="polite"></div>""" % resolver_field("dns"),
    LOOKUP_SCRIPTS + ["dns-tools.js"],
    net={"hosts": DOH_TWO, "sources": "Google Public DNS or Cloudflare, whichever you choose"}))

write("dnsreport.html", page(
    "dnsreport.html", "DNS Report",
    "A plain-language DNS health report: name servers, SOA, mail records, SPF, DMARC, MTA-STS, CAA and DNSSEC, with findings ranked by severity.",
    "DNS report", "Is this domain set up well?",
    "We gather the important records and check them against common good practice, then list problems first and explain each one.",
    """          <div class="kit-panel">
            <label class="kit-label" for="drep-in">Domain name</label>
            <input id="drep-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="example.com">
            <div class="kit-cols two">
              %s
            </div>
            <div class="kit-row"><button type="button" id="drep-run" class="btn">Build the report</button></div>
            <p class="kit-note">This makes about 15 DNS queries. Findings are guidance, not a certification, and some are judgement calls.</p>
          </div>
          <div id="drep-out" aria-live="polite"></div>""" % resolver_field("drep"),
    LOOKUP_SCRIPTS + ["dns-tools.js"],
    net={"hosts": DOH_TWO, "sources": "Google Public DNS or Cloudflare, whichever you choose"}))

write("dnssec.html", page(
    "dnssec.html", "DNSSEC Test",
    "Check whether a domain uses DNSSEC and whether the chain of trust validates: DS and DNSKEY records, algorithms, and signature expiry.",
    "DNSSEC test", "Can resolvers trust this domain's DNS answers?",
    "DNSSEC signs DNS data so forged answers can be detected. We check the DS record at the parent, the keys in the zone, and whether a validating resolver accepts them.",
    """          <div class="kit-panel">
            <label class="kit-label" for="dsec-in">Domain name</label>
            <input id="dsec-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="example.com">
            <div class="kit-cols two">
              %s
            </div>
            <div class="kit-row"><button type="button" id="dsec-run" class="btn">Test DNSSEC</button></div>
          </div>
          <div id="dsec-out" aria-live="polite"></div>""" % resolver_field("dsec"),
    LOOKUP_SCRIPTS + ["dns-tools.js"],
    net={"hosts": DOH_TWO, "sources": "Google Public DNS or Cloudflare, whichever you choose"}))

write("propagation.html", page(
    "propagation.html", "DNS Propagation",
    "Compare DNS answers from five public resolvers (Google, Cloudflare, DNS.SB, Control D, RethinkDNS) to see whether a change has spread.",
    "DNS propagation", "Has my DNS change spread?",
    "Ask five independent public resolvers the same question and see whether they agree. Differences usually mean a resolver is still caching the old answer.",
    """          <div class="kit-panel">
            <div class="kit-cols two">
              <div><label class="kit-label" for="prop-in">Domain name</label>
                <input id="prop-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="example.com"></div>
              <div><label class="kit-label" for="prop-type">Record type</label><select id="prop-type" class="kit"></select></div>
            </div>
            <div class="kit-row"><button type="button" id="prop-run" class="btn">Compare resolvers</button></div>
          </div>
          <div id="prop-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["dns-tools.js"],
    net={"hosts": DOH_ALL, "sources": "five public resolvers (Google, Cloudflare, DNS.SB, Control D and RethinkDNS)"}))

write("reverse.html", page(
    "reverse.html", "Reverse DNS",
    "Find the PTR (reverse DNS) name for IP addresses and check whether each name points back to the same address.",
    "Reverse DNS", "What name does this address claim?",
    "Look up the reverse name of one or more public IP addresses, then check that the name resolves back (forward-confirmed reverse DNS).",
    """          <div class="kit-panel">
            <label class="kit-label" for="rev-in">IP addresses <small>(IPv4 or IPv6, up to 20, one per line)</small></label>
            <textarea id="rev-in" class="kit wrap" rows="4" spellcheck="false" placeholder="8.8.8.8&#10;2606:4700:4700::1111"></textarea>
            <div class="kit-row"><button type="button" id="rev-run" class="btn">Look up</button></div>
            <p class="kit-note">Private and reserved addresses are skipped and never sent to a resolver.</p>
          </div>
          <div id="rev-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["dns-tools.js"],
    net={"hosts": DOH_TWO, "sources": "Google Public DNS"}))

write("whois.html", page(
    "whois.html", "WHOIS (RDAP)",
    "Registration details for a domain, IP address or AS number: registrar, dates, name servers, status and abuse contact, via RDAP.",
    "WHOIS", "Who registered this, and when?",
    "Read the public registration record for a domain, an IP address or an AS number. A brand-new domain is a common sign of phishing.",
    """          <div class="kit-panel">
            <label class="kit-label" for="who-in">Domain, IP address or AS number</label>
            <input id="who-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="example.com    8.8.8.8    AS15169">
            <div class="kit-row"><button type="button" id="who-run" class="btn">Look up</button></div>
            <p class="kit-note">Uses RDAP, the modern replacement for WHOIS. Some registries do not allow lookups from a web page; for those we point you to ICANN's lookup tool.</p>
          </div>
          <div id="who-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["registry-tools.js"],
    net={"hosts": REGISTRIES, "sources": "the rdap.org directory and the registry that holds the record"}))

write("abuse.html", page(
    "abuse.html", "Abuse Contacts",
    "Find where to send an abuse report for a domain or IP address: the registrar and the network or hosting provider.",
    "Abuse contacts", "Who can take this down?",
    "For a domain we find the registrar and the network owner of each address it uses. For an IP address we find the network owner.",
    """          <div class="kit-panel">
            <label class="kit-label" for="ab-in">Domain, URL, email address or IP address</label>
            <input id="ab-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="evil-example.com">
            <div class="kit-row"><button type="button" id="ab-run" class="btn">Find contacts</button></div>
          </div>
          <div id="ab-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["registry-tools.js"],
    net={"hosts": sorted(set(REGISTRIES + DOH_TWO)), "sources": "registry (RDAP) services, RIPEstat and Google Public DNS"}))

write("asn.html", page(
    "asn.html", "ASN and Routing",
    "Find the autonomous system (network) behind an IP address, or details for an AS number: owner, country and announced prefixes.",
    "ASN lookup", "Which network is this?",
    "Enter an AS number or an IP address. We show who announces the address, who owns the AS number, and the address blocks it announces.",
    """          <div class="kit-panel">
            <label class="kit-label" for="asn-in">AS number or IP address</label>
            <input id="asn-in" class="kit" type="text" spellcheck="false" autocomplete="off" placeholder="AS15169    8.8.8.8">
            <div class="kit-row"><button type="button" id="asn-run" class="btn">Look up</button></div>
          </div>
          <div id="asn-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["registry-tools.js"],
    net={"hosts": sorted(set(REGISTRIES + DOH_TWO)), "sources": "Team Cymru's DNS service, registry (RDAP) services and RIPEstat"}))

write("mac.html", page(
    "mac.html", "MAC Vendor Lookup",
    "Find who made a network card from its MAC address, using the IEEE list built into this site. Spots randomized private addresses.",
    "MAC vendor", "Who made this network card?",
    "Paste one or more MAC addresses in any format. The vendor comes from the IEEE registry, served with this site, so nothing is looked up online.",
    """          <div class="kit-panel">
            <label class="kit-label" for="mac-in">MAC addresses <small>(colons, hyphens, dots or plain; one per line; up to 200)</small></label>
            <textarea id="mac-in" class="kit wrap" rows="4" spellcheck="false" placeholder="00:1A:2B:3C:4D:5E&#10;f4-f5-d8-12-34-56&#10;b827.eb12.3456"></textarea>
            <div class="kit-row"><button type="button" id="mac-run" class="btn">Find vendors</button></div>
            <p class="kit-note">The vendor list is about 1.5 MB and loads the first time you search.</p>
          </div>
          <div id="mac-out" aria-live="polite"></div>""",
    ["network.js", "router.js", "netlookup.js", "lookup-ui.js", "mac.js"],
    net={"static": True}))

write("freemail.html", page(
    "freemail.html", "Free Email Check",
    "Check whether an email address or domain belongs to a free, disposable or internet-provider mail service, and who hosts a domain's mail.",
    "Free email check", "Is this a throwaway address?",
    "Free and disposable addresses say little about who a sender is. Paste addresses or domains to classify them, then optionally see who hosts each domain's mail.",
    """          <div class="kit-panel">
            <label class="kit-label" for="fm-in">Email addresses or domains <small>(one per line)</small></label>
            <textarea id="fm-in" class="kit wrap" rows="4" spellcheck="false" placeholder="someone@gmail.com&#10;mailinator.com&#10;sales@example.com"></textarea>
            <div class="kit-row">
              <button type="button" id="fm-run" class="btn">Check</button>
              <button type="button" id="fm-mx" class="btn btn-ghost" hidden>Also see who hosts the mail (looks up online)</button>
            </div>
            <p class="kit-note">The first check uses a list built into the page. The optional second step asks Google Public DNS for each domain's mail servers.</p>
          </div>
          <div id="fm-out" aria-live="polite"></div>
          <div id="fm-mx-out" aria-live="polite"></div>""",
    LOOKUP_SCRIPTS + ["freemail.js"],
    net={"hosts": DOH_TWO, "sources": "Google Public DNS (only if you press the optional mail-server check)"}))

print("wrote", len(TOOLS), "pages")
