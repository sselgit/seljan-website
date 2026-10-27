/* Seljan Security tool stack: automatic lookups.
 *
 * Given an indicator (IP, domain, URL, file hash, or email address), query the free public
 * sources that allow browser requests and report which ones have a hit. Requests go straight
 * from the visitor's browser to each source, never through us.
 *
 * Sources that refuse browser requests or need an API key (VirusTotal, AbuseIPDB, GreyNoise,
 * abuse.ch, urlscan, ...) cannot be queried this way and stay as click-through links.
 *
 * Result statuses:
 *   hit     a source reports this indicator as malicious or abusive
 *   notice  worth knowing (Tor exit, brand-new domain, weak email setup), not a verdict
 *   clear   the source has nothing on it ("no hit"; NOT proof of safety)
 *   info    context only
 *   error   the source could not be reached
 *   skip    not applicable
 */
(function (root) {
  "use strict";

  var TIMEOUT_MS = 9000;

  function enc(s) { return encodeURIComponent(s); }
  function R(status, summary) { return { status: status, summary: summary }; }
  function fail(msg) { var e = new Error(msg); e.userMessage = msg; return e; }

  function httpFail(status) {
    if (status === 429) return fail("Rate limited. Try again in a minute.");
    if (status >= 500) return fail("The service had an error (HTTP " + status + ").");
    return fail("Unexpected response (HTTP " + status + ").");
  }

  function friendlyError(err) {
    if (err && err.userMessage) return err.userMessage;
    if (err && err.name === "AbortError") return "Timed out.";
    return "Blocked or unreachable from this browser.";
  }

  // ---- network ------------------------------------------------------------

  function request(url, opts) {
    opts = opts || {};
    var ctl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, opts.timeout || TIMEOUT_MS);
    var init = {
      method: "GET",
      mode: "cors",
      credentials: "omit",        // never send cookies to third parties
      referrerPolicy: "no-referrer", // never tell them which page the lookup came from
      cache: "no-store",
      headers: opts.headers || {}
    };
    if (ctl) init.signal = ctl.signal;
    return fetch(url, init).then(function (res) {
      clearTimeout(timer);
      return res.text().then(function (text) {
        var json = null;
        try { json = JSON.parse(text); } catch (e) { /* not JSON */ }
        return { status: res.status, ok: res.ok, json: json, text: text };
      });
    }, function (err) { clearTimeout(timer); throw err; });
  }

  var DOH = {
    google: "https://dns.google/resolve",
    cf: "https://cloudflare-dns.com/dns-query",
    cfsec: "https://security.cloudflare-dns.com/dns-query"  // blocks known malware/phishing domains
  };

  function doh(resolver, name, type) {
    return request(DOH[resolver] + "?name=" + enc(name) + "&type=" + type, {
      headers: { Accept: "application/dns-json" }
    }).then(function (r) {
      if (!r.json || typeof r.json.Status !== "number") throw fail("Unexpected DNS response.");
      return r.json;
    });
  }

  function answers(d, type) {
    return (d.Answer || []).filter(function (a) { return a.type === type; })
      .map(function (a) { return a.data; });
  }

  function txtValue(s) {
    return String(s || "").replace(/^"|"$/g, "").replace(/"\s*"/g, "");
  }

  // ---- indicator helpers ---------------------------------------------------

  function isPrivateIPv4(ip) {
    var p = String(ip).split(".").map(Number);
    if (p.length !== 4 || p.some(function (n) { return !(n >= 0 && n <= 255); })) return false;
    var a = p[0], b = p[1], c = p[2];
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224;
  }

  var RESERVED_SUFFIXES = ["local", "localhost", "internal", "lan", "home", "corp", "intranet",
    "localdomain", "test", "invalid", "example", "home.arpa", "arpa"];

  function isReservedHost(h) {
    h = String(h || "").toLowerCase().replace(/\.+$/, "");
    if (!h || h.indexOf(".") < 0) return true; // single-label names are internal
    return RESERVED_SUFFIXES.some(function (s) {
      return h === s || h.slice(-(s.length + 1)) === "." + s;
    });
  }

  var TWO_LEVEL = ["co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.cn", "com.mx", "com.tr", "com.sg",
    "com.hk", "com.ar"];

  function registrable(host) {
    host = String(host || "").toLowerCase().replace(/\.+$/, "");
    var parts = host.split(".");
    if (parts.length <= 2) return host;
    var last2 = parts.slice(-2).join(".");
    return TWO_LEVEL.indexOf(last2) >= 0 ? parts.slice(-3).join(".") : last2;
  }

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ""; }
  }

  var IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  var EMPTY_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ];

  // ---- result evaluators (pure functions; unit tested) ---------------------

  function evalInternetDb(status, j) {
    if (status === 404) return R("clear", "Not seen by Shodan's scanners.");
    if (status !== 200 || !j) throw httpFail(status);
    var tags = j.tags || [], ports = j.ports || [], vulns = j.vulns || [];
    var bad = tags.filter(function (t) { return t === "malware" || t === "compromised"; });
    var warn = tags.filter(function (t) { return t === "scanner" || t === "honeypot" || t === "tor"; });
    var bits = [];
    if (tags.length) bits.push("Tags: " + tags.slice(0, 6).join(", "));
    if (ports.length) bits.push("Open ports: " + ports.slice(0, 12).join(", "));
    if (vulns.length) bits.push(vulns.length + " known CVE" + (vulns.length === 1 ? "" : "s") + " on exposed services");
    var text = (bits.join(". ") || "Seen, but no open ports or tags recorded") + ".";
    if (bad.length) return R("hit", "Shodan tags this IP as " + bad.join(" / ") + ". " + text);
    if (warn.length || vulns.length) return R("notice", text);
    return R("info", text);
  }

  var DNSBLS = [
    ["SpamCop", "bl.spamcop.net"],
    ["DroneBL", "dnsbl.dronebl.org"],
    ["PSBL", "psbl.surriel.com"],
    ["s5h.net", "all.s5h.net"],
    ["UCEPROTECT L1", "dnsbl-1.uceprotect.net"],
    ["Barracuda", "b.barracudacentral.org"]
  ];

  function evalDnsbl(rows) {
    var listed = rows.filter(function (r) { return r.listed; }).map(function (r) { return r.name; });
    var failed = rows.filter(function (r) { return !r.ok; }).length;
    if (failed === rows.length) throw fail("None of the blocklists could be reached.");
    if (listed.length) {
      return R("hit", "Listed on " + listed.length + " of " + rows.length + " spam/abuse blocklists: " +
        listed.join(", ") + ". (These track spam and abuse, so a listing means abusive mail or " +
        "scanning, not necessarily malware.)");
    }
    return R("clear", "Not listed on " + (rows.length - failed) + " spam/abuse blocklists." +
      (failed ? " (" + failed + " could not be reached.)" : ""));
  }

  function evalTor(j, ip) {
    if (!j) throw fail("Unexpected response from the Tor Project.");
    var relays = j.relays || [];
    var exit = relays.filter(function (r) {
      return (r.flags || []).indexOf("Exit") >= 0 && (r.exit_addresses || []).indexOf(ip) >= 0;
    })[0];
    if (exit) {
      return R("notice", "Tor exit node (" + String(exit.nickname || "unnamed").slice(0, 40) +
        "). Traffic from here is anonymized; that alone doesn't make it malicious.");
    }
    if (relays.length) return R("info", "Part of the Tor network, but not an exit relay.");
    return R("clear", "Not a known Tor relay.");
  }

  function evalIpinfo(status, j) {
    if (status !== 200 || !j) throw httpFail(status);
    if (j.bogon) return R("info", "Reserved (bogon) address.");
    var bits = [];
    if (j.org) bits.push(String(j.org).slice(0, 80));
    var loc = [j.city, j.region, j.country].filter(Boolean).join(", ");
    if (loc) bits.push(loc.slice(0, 80));
    if (j.hostname) bits.push("reverse DNS " + String(j.hostname).slice(0, 80));
    return R("info", bits.length ? bits.join(" · ") : "No ownership details published.");
  }

  function evalOtx(status, j) {
    if (status === 404) return R("clear", "Not in AlienVault OTX.");
    if (status !== 200 || !j) throw httpFail(status);
    var count = j.pulse_info && typeof j.pulse_info.count === "number" ? j.pulse_info.count : 0;
    var known = (j.validation || []).some(function (v) {
      return /whitelist|popular|alexa|akamai|rank/i.test([v.name, v.source, v.message].join(" "));
    });
    var plural = count === 1 ? "" : "s";
    if (known) {
      // Quote OTX's own validation text rather than paraphrasing it: a whitelist entry can mean
      // "popular site" or "known test file", and those are very different things.
      var said = (j.validation || []).slice(0, 2)
        .map(function (v) { return String(v.message || v.name || "").slice(0, 70); })
        .filter(Boolean).join("; ");
      return R("info", "OTX notes: " + said + "." +
        (count > 0 ? " (" + count + " pulse" + plural + " mention it, likely incidentally.)" : ""));
    }
    if (count > 0) {
      var names = ((j.pulse_info && j.pulse_info.pulses) || []).slice(0, 2)
        .map(function (p) { return String(p.name || "").slice(0, 70); })
        .filter(Boolean);
      return R("hit", "Mentioned in " + count + " threat-intel pulse" + plural +
        (names.length ? ": " + names.map(function (n) { return "“" + n + "”"; }).join(", ") : "") + ".");
    }
    return R("clear", "Not in any OTX threat-intel pulse.");
  }

  function humanAge(days) {
    if (days < 60) return days + " day" + (days === 1 ? "" : "s");
    if (days < 730) return Math.floor(days / 30) + " months";
    return Math.floor(days / 365) + " years";
  }

  function evalRdap(status, j, nowMs, reg) {
    if (status === 404) {
      return R("notice", "No registration found for " + reg + ". It may be unregistered or expired.");
    }
    if (status !== 200 || !j) throw httpFail(status);
    var events = j.events || [];
    var ev = events.filter(function (e) { return e.eventAction === "registration"; })[0];
    var created = ev && ev.eventDate ? new Date(ev.eventDate) : null;
    var ent = (j.entities || []).filter(function (e) { return (e.roles || []).indexOf("registrar") >= 0; })[0];
    var fn = ent && ent.vcardArray && ent.vcardArray[1] &&
      ent.vcardArray[1].filter(function (x) { return x[0] === "fn"; })[0];
    var registrar = fn ? String(fn[3]).slice(0, 60) : "";
    if (!created || isNaN(created.getTime())) {
      return R("info", "Registered, but the registry doesn't publish a creation date.");
    }
    var days = Math.max(0, Math.floor(((nowMs || Date.now()) - created.getTime()) / 86400000));
    var base = "Registered " + created.toISOString().slice(0, 10) + " (" + humanAge(days) + " ago)" +
      (registrar ? " via " + registrar : "") + ".";
    if (days < 30) return R("notice", base + " Brand-new domains are a common phishing signal.");
    return R("info", base);
  }

  function evalCfBlock(sec, std) {
    var secA = answers(sec, 1), stdA = answers(std, 1);
    var stdReal = stdA.filter(function (a) { return a !== "0.0.0.0"; });
    var blocked = secA.length > 0 && secA.every(function (a) { return a === "0.0.0.0"; });
    if (blocked && stdReal.length) {
      return R("hit", "Blocked by Cloudflare's malware/phishing filter: the filtered DNS refuses it " +
        "while normal DNS resolves it.");
    }
    if (sec.Status === 3 && std.Status === 3) return R("info", "This domain doesn't exist (NXDOMAIN).");
    if (!stdReal.length && !secA.length) return R("info", "No IPv4 address published for this name.");
    return R("clear", "Not blocked by Cloudflare's malware filter (resolves to " +
      stdReal.slice(0, 3).join(", ") + (stdReal.length > 3 ? ", ..." : "") + ").");
  }

  function evalMhr(d) {
    var txt = (d.Answer || []).filter(function (a) { return a.type === 16; })
      .map(function (a) { return txtValue(a.data); })[0];
    if (!txt) return R("clear", "Not in Team Cymru's malware hash registry.");
    var m = txt.match(/^(\d+)\s+(\d+)/);
    if (!m) return R("info", "The registry answered in an unexpected format.");
    var when = new Date(Number(m[1]) * 1000);
    var dateStr = isNaN(when.getTime()) ? "unknown" : when.toISOString().slice(0, 10);
    var pct = Number(m[2]);
    if (pct > 0) {
      return R("hit", "Known malware: detected by about " + pct + "% of antivirus engines (last seen " + dateStr + ").");
    }
    return R("info", "In the registry with 0% detection (last seen " + dateStr + ").");
  }

  function evalMail(mx, txt, dmarc) {
    if (mx.Status === 3) return R("info", "This domain doesn't exist.");
    var hasMx = (mx.Answer || []).some(function (a) {
      return a.type === 15 && a.data && !/^0\s+\.?$/.test(String(a.data).trim());
    });
    var spf = answers(txt, 16).map(txtValue).filter(function (t) { return /^v=spf1/i.test(t); })[0];
    var dm = answers(dmarc, 16).map(txtValue).filter(function (t) { return /^v=DMARC1/i.test(t); })[0];
    var policy = dm ? ((dm.match(/;\s*p=(\w+)/i) || [])[1] || "unknown").toLowerCase() : "";
    var line = "Mail servers: " + (hasMx ? "yes" : "none") + " · SPF: " + (spf ? "present" : "missing") +
      " · DMARC: " + (dm ? "p=" + policy : "missing") + ".";
    if (!hasMx) return R("notice", line + " This domain can't receive email.");
    if (!dm) return R("notice", line + " Without DMARC, anyone can spoof this domain.");
    if (policy === "none") return R("notice", line + " DMARC is monitor-only, so spoofed mail is still delivered.");
    return R("info", line);
  }

  // ---- source checks --------------------------------------------------------

  function chk(id, name, source, href, run) {
    return { id: id, name: name, source: source, href: href || "", run: run };
  }

  function otxCheck(id, name, path, href) {
    return chk(id, name, "otx.alienvault.com", href, function () {
      return request("https://otx.alienvault.com/api/v1/indicators/" + path + "/general")
        .then(function (r) { return evalOtx(r.status, r.json); });
    });
  }

  function dnsblQuery(rev, zone) {
    return doh("google", rev + "." + zone[1], "A").then(function (d) {
      var ok = d.Status === 0 || d.Status === 3;
      var listed = ok && answers(d, 1).some(function (x) { return /^127\.0\.0\.\d{1,3}$/.test(x); });
      return { name: zone[0], ok: ok, listed: listed };
    }, function () { return { name: zone[0], ok: false, listed: false }; });
  }

  function ipChecks(ip) {
    var rev = ip.split(".").reverse().join(".");
    return [
      chk("internetdb", "Shodan InternetDB", "internetdb.shodan.io",
        "https://www.shodan.io/host/" + enc(ip), function () {
          return request("https://internetdb.shodan.io/" + enc(ip))
            .then(function (r) { return evalInternetDb(r.status, r.json); });
        }),
      chk("dnsbl", "Spam/abuse blocklists", "dns.google (DNS lookups)",
        "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + enc(ip) + "&run=toolpage", function () {
          return Promise.all(DNSBLS.map(function (z) { return dnsblQuery(rev, z); })).then(evalDnsbl);
        }),
      chk("tor", "Tor exit list", "onionoo.torproject.org",
        "https://metrics.torproject.org/rs.html#search/" + enc(ip), function () {
          return request("https://onionoo.torproject.org/details?search=" + enc(ip) +
            "&fields=nickname,flags,exit_addresses").then(function (r) {
            if (r.status !== 200) throw httpFail(r.status);
            return evalTor(r.json, ip);
          });
        }),
      otxCheck("otx", "AlienVault OTX", "IPv4/" + enc(ip), "https://otx.alienvault.com/indicator/ip/" + enc(ip)),
      chk("ipinfo", "Owner and location (ipinfo)", "ipinfo.io", "https://ipinfo.io/" + enc(ip), function () {
        return request("https://ipinfo.io/" + enc(ip) + "/json")
          .then(function (r) { return evalIpinfo(r.status, r.json); });
      })
    ];
  }

  function cfCheck(host) {
    return chk("cfblock", "Cloudflare malware filter", "security.cloudflare-dns.com",
      "https://radar.cloudflare.com/domains/domain/" + enc(host), function () {
        return Promise.all([doh("cfsec", host, "A"), doh("cf", host, "A")])
          .then(function (p) { return evalCfBlock(p[0], p[1]); });
      });
  }

  var RDAP_BASE = {
    com: "https://rdap.verisign.com/com/v1/",
    net: "https://rdap.verisign.com/net/v1/",
    org: "https://rdap.publicinterestregistry.org/rdap/",
    info: "https://rdap.identitydigital.services/rdap/",
    ai: "https://rdap.identitydigital.services/rdap/",
    xyz: "https://rdap.centralnic.com/xyz/",
    dev: "https://pubapi.registry.google/rdap/",
    app: "https://pubapi.registry.google/rdap/",
    us: "https://rdap.nic.us/"
  };

  function rdapCheck(host) {
    var reg = registrable(host);
    var tld = reg.split(".").pop();
    var base = RDAP_BASE[tld];
    return chk("rdap", "Domain registration age (RDAP)", base ? hostOf(base) : "",
      "https://lookup.icann.org/en/lookup?name=" + enc(reg), function () {
        if (!base) {
          return Promise.resolve(R("info", "Registration date isn't available in the browser for ." +
            tld + " domains. Use the link to look it up."));
        }
        return request(base + "domain/" + enc(reg))
          .then(function (r) { return evalRdap(r.status, r.json, Date.now(), reg); });
      });
  }

  function mailCheck(domain) {
    return chk("mail", "Email setup (MX, SPF, DMARC)", "dns.google (DNS lookups)",
      "https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a" + enc(domain) + "&run=toolpage", function () {
        return Promise.all([doh("google", domain, "MX"), doh("google", domain, "TXT"),
          doh("google", "_dmarc." + domain, "TXT")])
          .then(function (p) { return evalMail(p[0], p[1], p[2]); });
      });
  }

  function hashChecks(hash) {
    var h = hash.toLowerCase();
    var supported = /^[a-f0-9]{32}$/.test(h) || /^[a-f0-9]{40}$/.test(h);
    return [
      chk("mhr", "Team Cymru malware hash registry", supported ? "dns.google (DNS lookup)" : "", "", function () {
        if (!supported) {
          return Promise.resolve(R("skip", "This registry only takes MD5 or SHA-1. Try the MD5 or SHA-1 of the same file."));
        }
        return doh("google", h + ".malware.hash.cymru.com", "TXT").then(evalMhr);
      }),
      otxCheck("otx", "AlienVault OTX", "file/" + enc(h), "https://otx.alienvault.com/indicator/file/" + enc(h))
    ];
  }

  // ---- planning ---------------------------------------------------------------

  function skip(msg) { return { skip: msg }; }

  function planIp(ip) {
    if (isPrivateIPv4(ip)) {
      return skip("That's a private or reserved address, so public sources have nothing on it.");
    }
    return { checks: ipChecks(ip) };
  }

  function planHost(host) {
    if (isReservedHost(host)) {
      return skip("That looks like an internal or reserved name, so public sources have nothing on it.");
    }
    return { checks: [cfCheck(host), otxCheck("otx", "AlienVault OTX", "domain/" + enc(host),
      "https://otx.alienvault.com/indicator/domain/" + enc(host)), rdapCheck(host)] };
  }

  function planUrl(value) {
    var u;
    try { u = new URL(value); } catch (e) { return skip("That doesn't parse as a URL."); }
    var host = u.hostname.toLowerCase();
    // Privacy: phishing links often carry the victim's email or a token in the query string,
    // so send only scheme + host + path.
    u.username = ""; u.password = ""; u.search = ""; u.hash = "";
    var sent = u.toString();
    var note = "URL lookups send the address without its query string or fragment.";
    var otxUrl = otxCheck("otx-url", "AlienVault OTX (URL)", "url/" + enc(sent),
      "https://otx.alienvault.com/indicator/url/" + enc(sent));
    if (IPV4.test(host)) {
      var ipPlan = planIp(host);
      if (ipPlan.skip) return ipPlan;
      return { checks: ipChecks(host).concat([otxUrl]), note: note };
    }
    if (isReservedHost(host)) return planHost(host);
    var h = planHost(host).checks;
    h[1] = otxCheck("otx-host", "AlienVault OTX (host)", "domain/" + enc(host),
      "https://otx.alienvault.com/indicator/domain/" + enc(host));
    return { checks: [h[0], otxUrl, h[1], h[2]], note: note };
  }

  function planHash(hash) {
    if (EMPTY_HASHES.indexOf(hash.toLowerCase()) >= 0) {
      return skip("That's the hash of an empty (zero-byte) file, so a lookup isn't meaningful.");
    }
    return { checks: hashChecks(hash) };
  }

  function planEmail(addr) {
    var domain = String(addr).split("@").pop().toLowerCase();
    var p = planHost(domain);
    if (p.skip) return p;
    p.checks.push(mailCheck(domain));
    p.note = "Only the domain (" + domain + ") is looked up, never the mailbox name.";
    return p;
  }

  function plan(type, value) {
    value = String(value || "").trim();
    if (type === "ip") return planIp(value);
    if (type === "domain") return planHost(value.toLowerCase());
    if (type === "url") return planUrl(value);
    if (type === "hash") return planHash(value);
    if (type === "email") return planEmail(value);
    return skip("Nothing to check for that kind of indicator.");
  }

  // ---- runner -----------------------------------------------------------------

  /* ui: { onSkip(msg), onPlan(checks, note), onResult(check, result), onDone(results) } */
  function run(type, value, ui) {
    ui = ui || {};
    function call(name, a, b) { if (typeof ui[name] === "function") ui[name](a, b); }
    var p;
    try { p = plan(type, value); } catch (e) {
      call("onSkip", "Couldn't prepare that indicator.");
      return Promise.resolve([]);
    }
    if (p.skip) { call("onSkip", p.skip); return Promise.resolve([]); }
    call("onPlan", p.checks, p.note);
    return Promise.all(p.checks.map(function (c) {
      return Promise.resolve().then(function () { return c.run(); })
        .then(function (res) { return res; }, function (err) { return R("error", friendlyError(err)); })
        .then(function (res) { call("onResult", c, res); return res; });
    })).then(function (results) { call("onDone", results); return results; });
  }

  root.SeljanLookups = {
    run: run,
    plan: plan,
    _test: {
      evalInternetDb: evalInternetDb, evalDnsbl: evalDnsbl, evalTor: evalTor, evalIpinfo: evalIpinfo,
      evalOtx: evalOtx, evalRdap: evalRdap, evalCfBlock: evalCfBlock, evalMhr: evalMhr,
      evalMail: evalMail, isPrivateIPv4: isPrivateIPv4, isReservedHost: isReservedHost,
      registrable: registrable, friendlyError: friendlyError, DNSBLS: DNSBLS
    }
  };
})(typeof window !== "undefined" ? window : this);
