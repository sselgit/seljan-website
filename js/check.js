/* Seljan Security email checker.
 *
 * Runs entirely in the browser. It parses a pasted or uploaded email, extracts
 * signals (sender, reply-to, authentication results, links, attachments) and
 * explains each one. It never uploads anything, never fetches links, and never
 * inserts the email's HTML into the page (which could load tracking pixels).
 */
(function () {
  "use strict";
  document.documentElement.classList.remove("no-js");

  // ---- small helpers ----------------------------------------------------

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function domainOfEmail(addr) {
    addr = (addr || "").trim().toLowerCase();
    var at = addr.lastIndexOf("@");
    return at >= 0 ? addr.slice(at + 1).replace(/[>);,]+$/, "") : "";
  }

  // Best-effort registrable domain (last two labels). Good enough for comparison.
  function registrable(host) {
    host = (host || "").toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
    var parts = host.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : host;
  }

  function isIpHost(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(":") >= 0;
  }

  // Parse "Display Name <addr@dom>" -> {name, address}
  function parseAddress(value) {
    value = (value || "").trim();
    var m = value.match(/^(.*)<([^>]+)>\s*$/);
    if (m) return { name: m[1].replace(/^["']|["']$/g, "").trim(), address: m[2].trim() };
    return { name: "", address: value.replace(/[<>]/g, "").trim() };
  }

  // ---- header parsing ---------------------------------------------------

  function splitHeadersBody(raw) {
    raw = raw.replace(/\r\n/g, "\n");
    var idx = raw.indexOf("\n\n");
    if (idx < 0) return { headerText: raw, body: "" };
    return { headerText: raw.slice(0, idx), body: raw.slice(idx + 2) };
  }

  function parseHeaders(headerText) {
    // Unfold continuation lines (those beginning with whitespace).
    var lines = headerText.split("\n");
    var headers = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^[ \t]/.test(line) && headers.length) {
        headers[headers.length - 1].value += " " + line.trim();
      } else {
        var c = line.indexOf(":");
        if (c > 0) headers.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
      }
    }
    return headers;
  }

  function get(headers, name) {
    name = name.toLowerCase();
    for (var i = headers.length - 1; i >= 0; i--) {
      if (headers[i].name.toLowerCase() === name) return headers[i].value;
    }
    return "";
  }

  function getAll(headers, name) {
    name = name.toLowerCase();
    return headers.filter(function (h) { return h.name.toLowerCase() === name; })
      .map(function (h) { return h.value; });
  }

  // ---- transfer-encoding decoders --------------------------------------

  function decodeQuotedPrintable(s) {
    return s.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, function (_, h) {
      return String.fromCharCode(parseInt(h, 16));
    });
  }

  function base64ToBytes(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, "");
    try {
      var bin = atob(s);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    } catch (e) {
      return new Uint8Array(0);
    }
  }

  function bytesToUtf8(bytes) {
    try { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
    catch (e) { return ""; }
  }

  // ---- MIME parsing (pragmatic, recursive) ------------------------------

  // Returns { headers, parts: [{contentType, filename, isAttachment, text, bytes}] }
  function parseMessage(raw) {
    var top = splitHeadersBody(raw);
    var headers = parseHeaders(top.headerText);
    var parts = [];
    parseEntity(headers, top.body, parts);
    return { headers: headers, parts: parts };
  }

  function contentTypeOf(headers) {
    var ct = get(headers, "content-type") || "text/plain";
    return ct;
  }

  function boundaryOf(ct) {
    var m = ct.match(/boundary\s*=\s*"?([^";]+)"?/i);
    return m ? m[1] : null;
  }

  function parseEntity(headers, body, out) {
    var ct = contentTypeOf(headers);
    var lower = ct.toLowerCase();

    if (lower.indexOf("multipart/") === 0) {
      var b = boundaryOf(ct);
      if (!b) { leaf(headers, body, out); return; }
      var marker = "--" + b;
      var chunks = body.split(marker);
      for (var i = 0; i < chunks.length; i++) {
        var chunk = chunks[i];
        if (chunk === "" || /^--\s*$/.test(chunk.trim())) continue;
        chunk = chunk.replace(/^\r?\n/, "");
        var sub = splitHeadersBody(chunk);
        var subHeaders = parseHeaders(sub.headerText);
        if (!subHeaders.length && !sub.body.trim()) continue;
        parseEntity(subHeaders, sub.body, out);
      }
      return;
    }
    leaf(headers, body, out);
  }

  function leaf(headers, body, out) {
    var ct = contentTypeOf(headers);
    var cte = (get(headers, "content-transfer-encoding") || "7bit").toLowerCase();
    var disp = get(headers, "content-disposition") || "";
    var filename = (disp.match(/filename\s*=\s*"?([^";]+)"?/i) || ct.match(/name\s*=\s*"?([^";]+)"?/i) || [])[1] || "";
    var isAttachment = /attachment/i.test(disp) || (!!filename && !/^text\//i.test(ct));

    var bytes = null, text = "";
    if (cte === "base64") {
      bytes = base64ToBytes(body);
      if (/^text\//i.test(ct) || /html|plain/i.test(ct)) text = bytesToUtf8(bytes);
    } else if (cte === "quoted-printable") {
      text = decodeQuotedPrintable(body);
    } else {
      text = body;
    }

    out.push({
      contentType: ct.split(";")[0].trim().toLowerCase(),
      filename: filename,
      isAttachment: isAttachment,
      text: text,
      bytes: bytes
    });
  }

  // ---- link + url extraction -------------------------------------------

  var URL_RE = /\bhttps?:\/\/[^\s"'<>)\]}]+/gi;

  function extractLinks(parts) {
    var links = []; // {href, text}
    var seen = {};
    function add(href, text) {
      href = (href || "").trim().replace(/[.,;]+$/, "");
      if (!/^https?:\/\//i.test(href)) return;
      var key = href + "||" + (text || "");
      if (seen[key]) return;
      seen[key] = 1;
      links.push({ href: href, text: (text || "").trim() });
    }
    parts.forEach(function (p) {
      if (p.contentType === "text/html" && p.text) {
        try {
          var doc = new DOMParser().parseFromString(p.text, "text/html");
          // NOTE: parsing a string does not load images/scripts; we never append this to the page.
          var anchors = doc.querySelectorAll("a[href]");
          anchors.forEach(function (a) { add(a.getAttribute("href"), a.textContent); });
        } catch (e) { /* fall through to regex */ }
      }
      if (p.text && !p.isAttachment) {
        var m; URL_RE.lastIndex = 0;
        while ((m = URL_RE.exec(p.text))) add(m[0], "");
      }
    });
    return links;
  }

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ""; }
  }

  // ---- signal building --------------------------------------------------

  var SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "is.gd", "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc"];
  var RISKY_EXT = ["exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "hta", "jar", "msi", "ps1", "lnk", "iso", "img", "docm", "xlsm", "pptm"];
  var URGENCY = ["urgent", "immediately", "within 24 hours", "verify your account",
    "account suspended", "suspended", "unusual activity", "confirm your", "update your payment",
    "gift card", "wire transfer", "final notice", "password expire", "reset your password",
    "failure to", "act now", "your account will"];

  function analyzeParsed(msg) {
    return new Promise(function (resolve) {
      var h = msg.headers;
      var signals = [];
      function sig(level, title, detail, evidence) {
        signals.push({ level: level, title: title, detail: detail, evidence: evidence || "" });
      }

      var from = parseAddress(get(h, "from"));
      var fromDom = domainOfEmail(from.address);
      var fromReg = registrable(fromDom);

      // Sender present?
      if (from.address) {
        sig("info", "Sender address", "This is the address the message claims to come from. Check it carefully against mail you know is genuine.", from.name ? (from.name + " <" + from.address + ">") : from.address);
      } else {
        sig("watch", "No clear sender", "We couldn't read a From address. Paste the full headers for a better check.", "");
      }

      // Display name that hides a different address
      if (from.name && /@/.test(from.name)) {
        var nameDom = domainOfEmail(from.name);
        if (nameDom && fromDom && registrable(nameDom) !== fromReg) {
          sig("watch", "Display name shows a different address",
            "The sender's name is written to look like one address, but the real address is on a different domain. A common trick.",
            from.name + "  (real: " + from.address + ")");
        }
      }

      // Reply-To mismatch
      var replyTo = parseAddress(get(h, "reply-to"));
      if (replyTo.address) {
        var rDom = registrable(domainOfEmail(replyTo.address));
        if (fromReg && rDom && rDom !== fromReg) {
          sig("alert", "Replies would go to a different domain",
            "If you reply, your message goes to a different domain than the sender's. Attackers use this to catch replies.",
            "From: " + fromDom + "   Reply-To: " + replyTo.address);
        } else if (rDom && rDom === fromReg) {
          sig("ok", "Reply-To matches the sender", "Replies go back to the same domain as the sender.", replyTo.address);
        }
      }

      // Return-Path / envelope sender (from headers or smtp.mailfrom)
      var authResults = getAll(h, "authentication-results").join(" ") + " " +
        getAll(h, "received-spf").join(" ") + " " + get(h, "return-path");
      var mailfrom = (authResults.match(/smtp\.mailfrom\s*=\s*([^\s;]+)/i) || [])[1] ||
        domainOfEmail((get(h, "return-path") || "").replace(/[<>]/g, ""));
      if (mailfrom && fromReg) {
        var mfReg = registrable(domainOfEmail(mailfrom.indexOf("@") >= 0 ? mailfrom : "x@" + mailfrom));
        if (mfReg && mfReg !== fromReg) {
          sig("watch", "Envelope sender differs from the From address",
            "The server-level sender (Return-Path) is on a different domain than the visible From. Sometimes legitimate (mailing lists), often not.",
            "From: " + fromReg + "   Envelope: " + mfReg);
        }
      }

      // Authentication results: SPF / DKIM / DMARC
      var authText = getAll(h, "authentication-results").join(" ") + " " + getAll(h, "received-spf").join(" ");
      var re = /\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|none|neutral|permerror|temperror)/gi;
      var seenAuth = {}, am;
      while ((am = re.exec(authText))) {
        var proto = am[1].toLowerCase(), res = am[2].toLowerCase();
        if (seenAuth[proto]) continue; seenAuth[proto] = 1;
        var label = proto.toUpperCase();
        if (res === "fail" || res === "softfail" || res === "permerror") {
          sig("alert", label + " check failed",
            label === "SPF" ? "The sending server isn't on the sender domain's approved list. The address may be spoofed." :
            label === "DKIM" ? "The message's digital signature didn't validate. It may have been forged or altered." :
            "The domain's anti-spoofing policy was not met. Treat the sender with suspicion.",
            label.toLowerCase() + "=" + res);
        } else if (res === "pass") {
          sig("ok", label + " passed", "This authentication check passed.", label.toLowerCase() + "=pass");
        }
      }
      if (!Object.keys(seenAuth).length) {
        sig("info", "No authentication results found",
          "This paste has no SPF/DKIM/DMARC results, so we can't tell whether the sender is authentic. Pasting the full raw headers helps.", "");
      }

      // Links
      var links = extractLinks(msg.parts);
      var offDomain = 0;
      links.forEach(function (l) {
        var host = hostOf(l.href);
        var reg = registrable(host);

        // link text that looks like a URL/domain pointing somewhere else
        var textHost = "";
        var tm = l.text.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
        if (tm) textHost = registrable(tm[0]);
        if (textHost && reg && textHost !== reg && /https?:\/\/|\.[a-z]{2,}/i.test(l.text)) {
          sig("alert", "A link points somewhere other than it claims",
            "The clickable text shows one address, but the link actually goes to a different domain.",
            l.text + "  →  " + host);
        }

        if (isIpHost(host)) {
          sig("alert", "A link uses a raw IP address", "Real companies rarely link to a bare IP address.", l.href);
        }
        if (/^xn--/i.test(host) || host.indexOf(".xn--") >= 0) {
          sig("watch", "A link uses a look-alike (punycode) domain",
            "This domain is encoded in a way that can disguise look-alike characters.", host);
        }
        if (SHORTENERS.indexOf(reg) >= 0) {
          sig("watch", "A link is hidden behind a shortener",
            "Shortened links hide where they really go. Be cautious, especially if the message asks you to sign in.", host);
        }
        if (fromReg && reg && reg !== fromReg) offDomain++;
      });
      if (links.length && fromReg && offDomain === links.length) {
        sig("info", "Links go to a different domain than the sender",
          "All links lead away from the sender's own domain. Common in newsletters, but worth noting.", offDomain + " of " + links.length + " link(s)");
      }

      // Urgency / pressure language
      var bodyText = msg.parts.filter(function (p) { return !p.isAttachment && p.text; })
        .map(function (p) { return p.contentType === "text/html" ? stripTags(p.text) : p.text; })
        .join("\n").toLowerCase();
      var hits = URGENCY.filter(function (w) { return bodyText.indexOf(w) >= 0; });
      if (hits.length) {
        sig("watch", "Pressure or urgency language",
          "The message uses wording designed to rush you. Slow down; urgency is a classic tactic.",
          hits.slice(0, 4).join(", "));
      }

      // Attachments (hash locally, flag risky types)
      var attachments = msg.parts.filter(function (p) { return p.isAttachment && p.filename; });
      var pending = [];
      attachments.forEach(function (p) {
        var ext = (p.filename.split(".").pop() || "").toLowerCase();
        var dbl = /\.(pdf|docx?|xlsx?|jpe?g|png|txt|zip)\.(exe|scr|js|vbs|hta|cmd|bat|lnk|iso)$/i.test(p.filename);
        if (dbl) {
          sig("alert", "Attachment has a disguised double extension",
            "The file looks like a document but is actually an executable. A strong danger sign.", p.filename);
        } else if (RISKY_EXT.indexOf(ext) >= 0) {
          sig("alert", "Risky attachment type", "This file type can run code on your computer. Do not open it unless you are certain.", p.filename + " (." + ext + ")");
        } else {
          sig("info", "Attachment present", "Unexpected attachments are worth treating with care.", p.filename);
        }
        if (p.bytes && p.bytes.length && window.crypto && crypto.subtle) {
          pending.push(crypto.subtle.digest("SHA-256", p.bytes).then(function (buf) {
            var hex = Array.prototype.map.call(new Uint8Array(buf), function (b) {
              return ("0" + b.toString(16)).slice(-2);
            }).join("");
            sig("info", "Attachment fingerprint (SHA-256)",
              "You can look this up yourself on a service like VirusTotal. We do not send it anywhere for you.",
              p.filename + "\n" + hex);
          }));
        }
      });

      Promise.all(pending).then(function () { resolve(signals); });
    });
  }

  function stripTags(html) {
    try {
      var doc = new DOMParser().parseFromString(html, "text/html");
      return doc.body ? doc.body.textContent || "" : "";
    } catch (e) { return html.replace(/<[^>]+>/g, " "); }
  }

  // ---- rendering --------------------------------------------------------

  var ORDER = { alert: 0, watch: 1, info: 2, ok: 3 };
  var LABEL = { alert: "Warning sign", watch: "Worth a closer look", info: "Note", ok: "Looks normal" };

  function render(signals) {
    signals.sort(function (a, b) { return ORDER[a.level] - ORDER[b.level]; });
    var alerts = signals.filter(function (s) { return s.level === "alert"; }).length;
    var watches = signals.filter(function (s) { return s.level === "watch"; }).length;

    var summary;
    if (alerts > 0) {
      summary = '<div class="summary summary-alert"><strong>' + alerts + ' warning sign' +
        (alerts === 1 ? "" : "s") + '</strong> and ' + watches + ' thing' + (watches === 1 ? "" : "s") +
        ' to look at more closely. Be careful with this message.</div>';
    } else if (watches > 0) {
      summary = '<div class="summary summary-watch"><strong>No strong warning signs,</strong> but ' +
        watches + ' thing' + (watches === 1 ? "" : "s") + ' worth a closer look. Stay cautious.</div>';
    } else {
      summary = '<div class="summary summary-ok">No obvious warning signs found in what you pasted. ' +
        'That is reassuring but not a guarantee; keep your guard up.</div>';
    }

    var cards = signals.map(function (s) {
      return '<div class="signal ' + s.level + '">' +
        '<div class="signal-head"><span class="sig-tag">' + LABEL[s.level] + '</span>' +
        '<span class="sig-title">' + esc(s.title) + '</span></div>' +
        '<p class="sig-detail">' + esc(s.detail) + '</p>' +
        (s.evidence ? '<pre class="sig-ev">' + esc(s.evidence) + '</pre>' : "") +
        '</div>';
    }).join("");

    var el = document.getElementById("results");
    el.innerHTML = summary +
      '<p class="reminder">These are educational signals, not a verdict. When unsure, don\'t click, ' +
      'and verify with the sender another way.</p>' + cards;
    el.hidden = false;
    el.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  function run(raw) {
    raw = (raw || "").trim();
    var el = document.getElementById("results");
    if (!raw) {
      el.innerHTML = '<div class="summary summary-watch">Paste an email above first.</div>';
      el.hidden = false;
      return;
    }
    var msg = parseMessage(raw);
    analyzeParsed(msg).then(render);
  }

  // ---- sample (synthetic, uses reserved example domains) ----------------

  var SAMPLE = [
    'From: "IT Help Desk" <help@secure-login.example.net>',
    'Reply-To: recovery@mail.example.org',
    'To: you@yourcompany.example',
    'Subject: Action required: your password will expire in 24 hours',
    'Date: Mon, 27 Oct 2026 09:00:00 +0000',
    'Authentication-Results: mx.yourcompany.example; spf=fail smtp.mailfrom=secure-login.example.net; dkim=none; dmarc=fail',
    'Content-Type: text/html; charset="utf-8"',
    '',
    '<p>Dear user, unusual activity was detected. You must verify your account',
    'immediately or it will be suspended.</p>',
    '<p><a href="http://login.example.net/reset">https://accounts.yourcompany.example/reset</a></p>'
  ].join("\n");

  // ---- wire up ----------------------------------------------------------

  function ready() {
    var input = document.getElementById("email-input");
    document.getElementById("analyze-btn").addEventListener("click", function () { run(input.value); });
    document.getElementById("sample-btn").addEventListener("click", function () {
      input.value = SAMPLE; run(SAMPLE);
    });
    document.getElementById("clear-btn").addEventListener("click", function () {
      input.value = ""; var el = document.getElementById("results"); el.hidden = true; el.innerHTML = "";
      input.focus();
    });
    document.getElementById("file-input").addEventListener("change", function (e) {
      var f = e.target.files && e.target.files[0];
      if (!f) return;
      var reader = new FileReader();
      reader.onload = function () { input.value = reader.result; run(reader.result); };
      reader.readAsText(f);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
