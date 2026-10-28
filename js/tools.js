/* Seljan Security tool stack: IOC pivot, tool directory, and port reference.
 * All client-side. The pivot only builds links; nothing is sent until the user
 * clicks through to a third-party tool.
 */
(function () {
  "use strict";
  document.documentElement.classList.remove("no-js");

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function enc(s) { return encodeURIComponent(s); }

  // ---- refang + detect --------------------------------------------------

  function refang(s) {
    return (s || "").trim()
      .replace(/\s+/g, " ")
      .replace(/h\s*[xX]{2}\s*p(s?)/gi, "http$1")  // hxxp / hxxps
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, ".")
      .replace(/\s+dot\s+/gi, ".")
      .replace(/\[\s*:\s*\]/g, ":")
      .replace(/\[\s*@\s*\]|\s+at\s+/gi, "@")
      .replace(/^\s+|\s+$/g, "");
  }

  var RE = {
    ipv4: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
    md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i,
    url: /^https?:\/\/\S+$/i,
    email: /^[^@\s]+@([a-z0-9-]+\.)+[a-z]{2,}$/i,
    domain: /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
  };

  function detect(value) {
    var v = value.trim();
    if (RE.ipv4.test(v)) return "ip";
    if (RE.md5.test(v) || RE.sha1.test(v) || RE.sha256.test(v)) return "hash";
    if (RE.url.test(v)) return "url";
    if (RE.email.test(v)) return "email";
    if (RE.domain.test(v)) return "domain";
    return "unknown";
  }

  function hostOfUrl(u) { try { return new URL(u).hostname; } catch (e) { return ""; } }
  function registrable(h) {
    h = (h || "").toLowerCase().replace(/\.+$/, "");
    var p = h.split("."); return p.length >= 2 ? p.slice(-2).join(".") : h;
  }

  // ---- link builders per type ------------------------------------------

  var LINKS = {
    ip: function (v) {
      return [
        ["VirusTotal", "https://www.virustotal.com/gui/ip-address/" + enc(v)],
        ["AbuseIPDB", "https://www.abuseipdb.com/check/" + enc(v)],
        ["Shodan", "https://www.shodan.io/host/" + enc(v)],
        ["GreyNoise", "https://viz.greynoise.io/ip/" + enc(v)],
        ["Censys", "https://search.censys.io/hosts/" + enc(v)],
        ["Talos", "https://talosintelligence.com/reputation_center/lookup?search=" + enc(v)],
        ["IPinfo", "https://ipinfo.io/" + enc(v)]
      ];
    },
    domain: function (v) {
      return [
        ["VirusTotal", "https://www.virustotal.com/gui/domain/" + enc(v)],
        ["urlscan.io", "https://urlscan.io/search/#" + enc(v)],
        ["Shodan", "https://www.shodan.io/search?query=hostname:" + enc(v)],
        ["crt.sh (certs)", "https://crt.sh/?q=" + enc(v)],
        ["Censys", "https://search.censys.io/search?resource=hosts&q=" + enc(v)],
        ["Talos", "https://talosintelligence.com/reputation_center/lookup?search=" + enc(v)],
        ["MXToolbox", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + enc(v) + "&run=toolpage"],
        ["URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + enc(v)]
      ];
    },
    url: function (v) {
      var host = hostOfUrl(v);
      return [
        ["urlscan.io", "https://urlscan.io/search/#" + enc(v)],
        ["VirusTotal (search)", "https://www.virustotal.com/gui/search/" + enc(v)],
        ["URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + enc(v)],
        ["Host on VirusTotal", host ? "https://www.virustotal.com/gui/domain/" + enc(host) : ""],
        ["Host certs (crt.sh)", host ? "https://crt.sh/?q=" + enc(registrable(host)) : ""]
      ];
    },
    hash: function (v) {
      return [
        ["VirusTotal", "https://www.virustotal.com/gui/file/" + enc(v)],
        ["MalwareBazaar", "https://bazaar.abuse.ch/browse.php?search=sha256%3a" + enc(v)],
        ["Hybrid Analysis", "https://www.hybrid-analysis.com/search?query=" + enc(v)],
        ["Triage", "https://tria.ge/s?q=" + enc(v)],
        ["Any.Run (search)", "https://any.run/submissions/#filter=" + enc(v)]
      ];
    },
    email: function (v) {
      var dom = v.split("@")[1] || "";
      return [
        ["Domain on VirusTotal", "https://www.virustotal.com/gui/domain/" + enc(dom)],
        ["MXToolbox (deliverability)", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + enc(dom) + "&run=toolpage"],
        ["DMARC lookup", "https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a" + enc(dom) + "&run=toolpage"],
        ["Have I Been Pwned", "https://haveibeenpwned.com/account/" + enc(v)],
        ["Domain certs (crt.sh)", "https://crt.sh/?q=" + enc(dom)]
      ];
    }
  };

  var TYPE_LABEL = {
    ip: "IP address", domain: "domain", url: "URL", hash: "file hash", email: "email address"
  };

  // ---- automatic checks ---------------------------------------------------

  var runToken = 0;          // bumps on every new lookup so late answers from an old one are ignored
  var lastIndicator = null;
  var CHIP = { hit: "Hit", notice: "Notice", clear: "No hit", info: "Info",
    error: "Couldn't check", skip: "Skipped", pending: "Checking…" };
  var RANK = { hit: 0, notice: 1, info: 2, clear: 3, error: 4, skip: 5 };

  function byId(id) { return document.getElementById(id); }

  function autoEnabled() {
    try { return localStorage.getItem("seljan.autocheck") !== "0"; } catch (e) { return true; }
  }
  function saveAuto(on) {
    try { localStorage.setItem("seljan.autocheck", on ? "1" : "0"); } catch (e) { /* storage unavailable */ }
  }

  function clearAuto() {
    runToken++;
    var s = byId("auto-status");
    s.textContent = ""; s.className = "auto-status";
    byId("auto-results").innerHTML = "";
    byId("auto-note").hidden = true;
    byId("auto-now").hidden = true;
  }

  function autoOffMessage() {
    byId("auto-status").textContent = "Auto-check is off. Use the buttons below, or check now.";
    byId("auto-now").hidden = false;
  }

  // All text from remote sources goes in with textContent, never innerHTML.
  function makeRow(check) {
    var li = document.createElement("li");
    li.className = "chk pending";
    var chip = document.createElement("span");
    chip.className = "chip"; chip.textContent = CHIP.pending;
    var body = document.createElement("div");
    body.className = "chk-body";
    var name = document.createElement("strong");
    name.textContent = check.name;
    var sum = document.createElement("span");
    sum.className = "sum";
    sum.textContent = "Asking " + (check.source || "the source") + "…";
    body.appendChild(name); body.appendChild(sum);
    li.appendChild(chip); li.appendChild(body);
    return li;
  }

  function fillRow(li, check, res) {
    li.className = "chk " + res.status;
    li.dataset.rank = String(RANK[res.status]);
    li.querySelector(".chip").textContent = CHIP[res.status];
    li.querySelector(".sum").textContent = res.summary;
    if (check.href && !li.querySelector("a.chk-link")) {
      var a = document.createElement("a");
      a.className = "chk-link";
      a.href = check.href; a.target = "_blank"; a.rel = "noopener noreferrer";
      a.textContent = check.hrefLabel || "Open";
      a.setAttribute("aria-label", (check.hrefLabel || ("Open " + check.name)) + " (opens in a new tab)");
      li.appendChild(a);
    }
  }

  function summarize(c) {
    var parts = [];
    if (c.hit) parts.push(c.hit + (c.hit === 1 ? " hit" : " hits"));
    if (c.notice) parts.push(c.notice + (c.notice === 1 ? " notice" : " notices"));
    if (c.clear) parts.push(c.clear + " no hit");
    if (c.info) parts.push(c.info + " info");
    if (c.error) parts.push(c.error + " couldn't be checked");
    if (!parts.length) return "Nothing to report.";
    return (c.hit ? "" : "No hits. ") + parts.join(" · ");
  }

  function startAutoChecks(type, value) {
    var token = ++runToken;
    var statusEl = byId("auto-status"), listEl = byId("auto-results"), noteEl = byId("auto-note");
    listEl.innerHTML = ""; noteEl.hidden = true;
    byId("auto-now").hidden = true;
    statusEl.className = "auto-status";
    if (!window.SeljanLookups) {
      statusEl.textContent = "Automatic checks couldn't load. Use the buttons below.";
      return;
    }

    var rows = {}, noteText = "";
    var counts = { hit: 0, notice: 0, clear: 0, info: 0, error: 0, skip: 0 };
    statusEl.textContent = "Preparing checks…";

    window.SeljanLookups.run(type, value, {
      onSkip: function (msg) { if (token === runToken) statusEl.textContent = msg; },
      onPlan: function (checks, note) {
        if (token !== runToken) return;
        noteText = note || "";
        var sources = [];
        checks.forEach(function (c) { if (c.source && sources.indexOf(c.source) < 0) sources.push(c.source); });
        statusEl.textContent = "Checking " + checks.length + " sources straight from your browser (" +
          sources.join(", ") + ")…";
        checks.forEach(function (c) { var li = makeRow(c); rows[c.id] = li; listEl.appendChild(li); });
      },
      onResult: function (c, res) {
        if (token !== runToken) return;
        fillRow(rows[c.id], c, res);
        counts[res.status] = (counts[res.status] || 0) + 1;
      },
      onDone: function () {
        if (token !== runToken) return;
        // Findings first: hits, then notices, then context, then no-hit, then failures.
        Array.prototype.slice.call(listEl.children)
          .sort(function (a, b) { return Number(a.dataset.rank) - Number(b.dataset.rank); })
          .forEach(function (li) { listEl.appendChild(li); });
        statusEl.textContent = summarize(counts);
        statusEl.className = "auto-status" + (counts.hit ? " has-hit" : counts.notice ? " has-notice" : "");
        noteEl.hidden = false;
        noteEl.textContent = (noteText ? noteText + " " : "") +
          "“No hit” only means these free sources have nothing on it. VirusTotal, AbuseIPDB, " +
          "GreyNoise and a few others can't be queried from a browser, so use the buttons below for them.";
      }
    });
  }

  function runPivot() {
    var raw = document.getElementById("ioc-input").value;
    var cleaned = refang(raw);
    var type = detect(cleaned);
    var typeEl = document.getElementById("ioc-type");
    var linksEl = document.getElementById("ioc-links");
    var labelEl = byId("links-label");

    clearAuto();
    lastIndicator = null;

    if (!cleaned) {
      typeEl.hidden = true; linksEl.innerHTML = ""; labelEl.hidden = true; return;
    }
    if (type === "unknown") {
      typeEl.hidden = false;
      typeEl.className = "ioc-type unknown";
      typeEl.textContent = "Couldn't recognize that as an IP, domain, URL, or hash. Check for typos.";
      linksEl.innerHTML = "";
      labelEl.hidden = true;
      return;
    }
    typeEl.hidden = false;
    typeEl.className = "ioc-type";
    var shown = cleaned !== raw.trim() ? (" (cleaned: " + cleaned + ")") : "";
    typeEl.innerHTML = "Detected <strong>" + esc(TYPE_LABEL[type]) + "</strong>" + esc(shown);

    var links = LINKS[type](cleaned).filter(function (l) { return l[1]; });
    linksEl.innerHTML = links.map(function (l) {
      return '<a class="ioc-link" href="' + esc(l[1]) + '" target="_blank" rel="noopener noreferrer">' +
        esc(l[0]) + '<span aria-hidden="true">↗</span></a>';
    }).join("");
    labelEl.hidden = false;

    lastIndicator = { type: type, value: cleaned };
    if (autoEnabled()) startAutoChecks(type, cleaned);
    else autoOffMessage();
  }

  // ---- tool directory ---------------------------------------------------

  var DIRECTORY = [
    ["Reputation & lookups", [
      ["VirusTotal", "https://www.virustotal.com/", "Files, URLs, domains, IPs across many engines"],
      ["AbuseIPDB", "https://www.abuseipdb.com/", "Community reports of abusive IP addresses"],
      ["GreyNoise", "https://viz.greynoise.io/", "Tells internet background noise from targeted activity"],
      ["Talos Intelligence", "https://talosintelligence.com/reputation_center", "Cisco's IP/domain reputation"],
      ["AlienVault OTX", "https://otx.alienvault.com/", "Open threat-intel pulses and indicators"]
    ]],
    ["Sandboxes & malware", [
      ["urlscan.io", "https://urlscan.io/", "Safely renders and inspects a URL"],
      ["Hybrid Analysis", "https://www.hybrid-analysis.com/", "Free malware sandbox"],
      ["Any.Run", "https://any.run/", "Interactive malware sandbox"],
      ["Triage", "https://tria.ge/", "Automated malware analysis sandbox"],
      ["MalwareBazaar", "https://bazaar.abuse.ch/", "Malware sample sharing by abuse.ch"],
      ["URLhaus", "https://urlhaus.abuse.ch/", "Malware distribution URLs"]
    ]],
    ["Email & DNS", [
      ["MXToolbox", "https://mxtoolbox.com/", "MX, SPF, DKIM, DMARC, blacklist checks"],
      ["crt.sh", "https://crt.sh/", "Search issued TLS certificates (find subdomains)"],
      ["DNSdumpster", "https://dnsdumpster.com/", "DNS recon and mapping"],
      ["Have I Been Pwned", "https://haveibeenpwned.com/", "Check if an account was in a breach"]
    ]],
    ["Recon & utilities", [
      ["Shodan", "https://www.shodan.io/", "Search internet-exposed devices and services"],
      ["Censys", "https://search.censys.io/", "Internet-wide host and certificate search"],
      ["SecurityTrails", "https://securitytrails.com/", "Historical DNS and domain data"],
      ["CyberChef", "https://gchq.github.io/CyberChef/", "Decode, deobfuscate, and transform data"],
      ["IPinfo", "https://ipinfo.io/", "Geolocation and ownership for an IP"]
    ]]
  ];

  function renderDirectory() {
    var grid = document.getElementById("directory-grid");
    grid.innerHTML = DIRECTORY.map(function (group) {
      var items = group[1].map(function (t) {
        return '<li><a href="' + esc(t[1]) + '" target="_blank" rel="noopener noreferrer">' +
          esc(t[0]) + ' <span aria-hidden="true">↗</span></a>' +
          '<span class="dir-desc">' + esc(t[2]) + '</span></li>';
      }).join("");
      return '<div class="dir-col"><h3>' + esc(group[0]) + '</h3><ul>' + items + '</ul></div>';
    }).join("");
  }

  // ---- port reference ---------------------------------------------------

  var PORTS = [
    [20, "tcp", "FTP data", "Legacy file transfer. Unencrypted; avoid exposing."],
    [21, "tcp", "FTP control", "Unencrypted logins. Prefer SFTP/FTPS; don't expose."],
    [22, "tcp", "SSH / SFTP", "Secure remote admin. Expose only with keys + limits."],
    [23, "tcp", "Telnet", "Plaintext remote login. Obsolete and dangerous; disable."],
    [25, "tcp", "SMTP", "Mail transfer between servers."],
    [53, "tcp/udp", "DNS", "Name resolution. Open resolvers can be abused."],
    [67, "udp", "DHCP server", "Hands out IP addresses on a LAN."],
    [80, "tcp", "HTTP", "Unencrypted web. Redirect to HTTPS (443)."],
    [110, "tcp", "POP3", "Legacy mail retrieval. Prefer IMAP over TLS."],
    [123, "udp", "NTP", "Time sync. Can be abused for amplification if open."],
    [135, "tcp", "MS RPC", "Windows RPC. Never expose to the internet."],
    [137, "udp", "NetBIOS", "Legacy Windows naming. Never expose."],
    [139, "tcp", "NetBIOS session", "Legacy Windows file sharing. Never expose."],
    [143, "tcp", "IMAP", "Mail retrieval. Use the TLS variant (993)."],
    [161, "udp", "SNMP", "Device management. Default community strings are a risk."],
    [389, "tcp", "LDAP", "Directory services. Use LDAPS (636); don't expose."],
    [443, "tcp", "HTTPS", "Encrypted web. The normal public web port."],
    [445, "tcp", "SMB", "Windows file sharing. A top ransomware target; never expose."],
    [465, "tcp", "SMTPS", "Mail submission over TLS."],
    [587, "tcp", "SMTP submission", "Authenticated mail sending with STARTTLS."],
    [636, "tcp", "LDAPS", "Directory services over TLS."],
    [993, "tcp", "IMAPS", "Mail retrieval over TLS."],
    [995, "tcp", "POP3S", "Legacy mail retrieval over TLS."],
    [1433, "tcp", "MS SQL Server", "Database. Never expose to the internet."],
    [1521, "tcp", "Oracle DB", "Database. Never expose."],
    [3306, "tcp", "MySQL / MariaDB", "Database. Never expose; bind to localhost/VPN."],
    [3389, "tcp", "RDP", "Windows remote desktop. A top ransomware entry point; VPN only."],
    [5432, "tcp", "PostgreSQL", "Database. Never expose; bind to localhost/VPN."],
    [5900, "tcp", "VNC", "Remote desktop. Weak auth historically; don't expose."],
    [6379, "tcp", "Redis", "In-memory store. No auth by default; never expose."],
    [8080, "tcp", "HTTP alt / proxy", "Common app/proxy port. Often admin panels."],
    [8443, "tcp", "HTTPS alt", "Common for admin consoles and appliances."],
    [9200, "tcp", "Elasticsearch", "Search/data store. Frequently leaked; never expose."],
    [27017, "tcp", "MongoDB", "Database. Famous for open exposures; never expose."]
  ];

  function renderPorts(query) {
    var el = document.getElementById("port-results");
    var q = (query || "").trim().toLowerCase();
    var rows = PORTS;
    if (q) {
      rows = PORTS.filter(function (p) {
        return String(p[0]) === q || String(p[0]).indexOf(q) === 0 ||
          p[2].toLowerCase().indexOf(q) >= 0 || p[3].toLowerCase().indexOf(q) >= 0;
      });
    } else {
      rows = PORTS.slice(0, 8); // show a few common ones by default
    }
    if (!rows.length) {
      el.innerHTML = '<p class="help-note">No match. Try a number like 3389, or a name like RDP.</p>';
      return;
    }
    var body = rows.map(function (p) {
      var risk = /never expose|don't expose|dangerous|disable|VPN only|ransomware/i.test(p[3]) ? " risky" : "";
      return '<tr class="' + risk.trim() + '"><td class="pnum">' + p[0] + '</td><td>' + esc(p[1]) +
        '</td><td>' + esc(p[2]) + '</td><td>' + esc(p[3]) + '</td></tr>';
    }).join("");
    el.innerHTML = '<table class="port-table"><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Notes</th></tr></thead><tbody>' +
      body + '</tbody></table>' + (!q ? '<p class="help-note">Showing common ports; search to see all.</p>' : '');
  }

  // ---- wire up ----------------------------------------------------------

  function ready() {
    document.getElementById("ioc-btn").addEventListener("click", runPivot);
    document.getElementById("ioc-input").addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); runPivot(); }
    });

    var toggle = byId("auto-toggle");
    toggle.checked = autoEnabled();
    toggle.addEventListener("change", function () {
      saveAuto(toggle.checked);
      if (!lastIndicator) return;
      if (toggle.checked) startAutoChecks(lastIndicator.type, lastIndicator.value);
      else { clearAuto(); autoOffMessage(); }
    });
    byId("auto-now").addEventListener("click", function () {
      if (lastIndicator) startAutoChecks(lastIndicator.type, lastIndicator.value);
    });
    renderDirectory();
    var portInput = document.getElementById("port-input");
    portInput.addEventListener("input", function () { renderPorts(portInput.value); });
    renderPorts("");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else { ready(); }
})();
