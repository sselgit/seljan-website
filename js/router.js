// Auto-detect router (SKRoute): looks at what was pasted and lists every tool that can handle it.
// Self-contained and offline: it only reads text and builds links. Values travel in the URL fragment
// (the part after #), which browsers never send to any server.
(function (root) {
  'use strict';

  var FILE_EXT = {};
  ('exe dll txt doc docx xls xlsx ppt pptx pdf js vbs ps1 bat cmd png jpg jpeg gif html htm css json xml log tmp dat bin sys msi lnk iso img py sh rtf csv ini cfg conf yml yaml md db bak old tar gz rar zip')
    .split(' ').forEach(function (e) { FILE_EXT[e] = true; });

  function refang(s) {
    return String(s == null ? '' : s).trim()
      .replace(/h\s*[xX]{2}\s*p(s?)/gi, 'http$1')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)/gi, '.')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*@\s*\]|\(\s*at\s*\)|\[\s*at\s*\]/gi, '@')
      .replace(/^[<"'`(]+/, '')
      .replace(/[>"'`),;]+$/, '')
      .trim();
  }

  var RE = {
    ipv4: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
    domain: /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,23}$/i,
    email: /^[^@\s<>]+@([a-z0-9-]+\.)+[a-z]{2,}$/i,
    url: /^(https?|ftp):\/\/\S+$/i,
    hash: /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i,
    cve: /^CVE-\d{4}-\d{4,7}$/i,
    attack: /^T\d{4}(\.\d{3})?$/,
    asn: /^AS\s?\d{1,10}$/i,
    jwt: /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/,
    macFull: /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^([0-9a-f]{4}\.){2}[0-9a-f]{4}$/i,
    macPartial: /^([0-9a-f]{2}[:-]){2,4}[0-9a-f]{2}$/i,
    mac12: /^[0-9a-f]{12}$/i
  };

  function isIPv6(v) {
    if (root.SK && root.SK.net) return root.SK.net.parseIPv6(v) !== null;
    return /^[0-9a-f:]+$/i.test(v) && (v.match(/:/g) || []).length >= 2 && (v.indexOf('::') >= 0 || (v.match(/:/g) || []).length === 7);
  }

  function isCidr(v) {
    var m = /^(.+)\/(\d{1,3})$/.exec(v);
    if (!m) return false;
    var n = +m[2];
    if (RE.ipv4.test(m[1])) return n <= 32;
    return m[1].indexOf(':') >= 0 && isIPv6(m[1]) && n <= 128;
  }

  function looksBase64(v) {
    var t = v.replace(/\s+/g, '');
    if (t.length < 16 || !/^[A-Za-z0-9+\/_-]+={0,2}$/.test(t)) return false;
    if (t.replace(/=+$/, '').length % 4 === 1) return false;
    // Ordinary words are valid Base64 letters too, so also require a digit or symbol real Base64 almost always has.
    return (t.length % 4 === 0 || t.indexOf('=') >= 0) && /[0-9+\/=_-]/.test(t);
  }
  function looksHex(v) {
    var t = v.replace(/0x|\\x|[\s:,\-]/gi, '');
    return t.length >= 10 && t.length % 2 === 0 && /^[0-9a-f]+$/i.test(t) && !RE.hash.test(t) && /(0x|\\x|\s)/i.test(v);
  }

  // Tool catalogue. net: true when the tool asks public DNS or registry sources from the visitor's browser.
  var TOOLS = {
    dns: { href: 'dns.html', label: 'DNS records', why: 'A, AAAA, MX, NS, TXT, SOA, CAA and more', net: true },
    dnsreport: { href: 'dnsreport.html', label: 'DNS report', why: 'Name servers, mail security (SPF, DMARC), DNSSEC, and findings', net: true },
    dnssec: { href: 'dnssec.html', label: 'DNSSEC test', why: 'Whether the chain of trust validates', net: true },
    propagation: { href: 'propagation.html', label: 'DNS propagation', why: 'Compare answers from five public resolvers', net: true },
    reverse: { href: 'reverse.html', label: 'Reverse DNS', why: 'PTR record and forward-confirmation', net: true },
    whois: { href: 'whois.html', label: 'WHOIS (RDAP)', why: 'Registration and ownership data', net: true },
    abuse: { href: 'abuse.html', label: 'Abuse contacts', why: 'Who to report it to', net: true },
    asn: { href: 'asn.html', label: 'ASN and routing', why: 'Which network announces it', net: true },
    freemail: { href: 'freemail.html', label: 'Free email check', why: 'Free, disposable or business mail', net: false },
    mac: { href: 'mac.html', label: 'MAC vendor', why: 'Who made the network card', net: false },
    network: { href: 'network.html', label: 'IP and CIDR tools', why: 'Public or private, subnet math', net: false },
    hash: { href: 'hash.html', label: 'Hash tools', why: 'Identify the hash type', net: false },
    time: { href: 'time.html', label: 'Timestamp converter', why: 'Every reading in UTC and your zone', net: false },
    decode: { href: 'decode.html', label: 'Decoder', why: 'Base64, hex, URL, escapes, layers', net: false },
    ioc: { href: 'ioc.html', label: 'Indicators', why: 'Defang, refang or extract', net: false },
    reference: { href: 'reference.html', label: 'Reference tables', why: 'Event IDs and more', net: false },
    pivot: { href: 'index.html', label: 'Reputation pivot', why: 'Blocklists, Shodan, OTX and more', net: true, plain: true },
    ports: { href: 'index.html#ports', label: 'Port reference', why: 'What this port is for', net: false, external: true }
  };

  function tool(id, value, kind, extra) {
    var t = TOOLS[id], o = { id: id, label: t.label, why: t.why, net: !!t.net };
    if (t.external) o.href = t.href;
    else o.href = t.href + '#q=' + encodeURIComponent(value) + '&k=' + kind + (t.net && !t.plain ? '&go=1' : '');
    if (extra) Object.keys(extra).forEach(function (k) { o[k] = extra[k]; });
    return o;
  }
  function ext(label, why, href) { return { id: 'ext', label: label, why: why, net: false, href: href, external: true }; }

  function hostOfUrl(u) { try { return new URL(u).hostname.replace(/\.$/, '').toLowerCase(); } catch (e) { return ''; } }

  // Returns matches, best first: [{ kind, label, value, confidence, tools: [...] }]
  function detect(raw) {
    var original = String(raw == null ? '' : raw);
    var v = refang(original);
    var out = [];
    if (!v) return out;
    function add(kind, label, value, conf, tools) { out.push({ kind: kind, label: label, value: value, confidence: conf, tools: tools }); }
    var single = !/\s/.test(v);

    if (single && isCidr(v)) add('cidr', 'IP range (CIDR)', v, 0.97, [tool('network', v, 'cidr')]);
    else if (single && RE.ipv4.test(v)) {
      add('ipv4', 'IPv4 address', v, 0.98, [tool('reverse', v, 'ip'), tool('whois', v, 'ip'), tool('abuse', v, 'ip'), tool('asn', v, 'ip'), tool('network', v, 'ip'), tool('pivot', v, 'ip')]);
    } else if (single && v.indexOf(':') >= 0 && isIPv6(v.replace(/^\[|\]$/g, ''))) {
      var v6 = v.replace(/^\[|\]$/g, '');
      add('ipv6', 'IPv6 address', v6, 0.97, [tool('reverse', v6, 'ip'), tool('whois', v6, 'ip'), tool('abuse', v6, 'ip'), tool('asn', v6, 'ip'), tool('network', v6, 'ip')]);
    }

    var isClock = /^\d{2}:\d{2}(:\d{2})?$/.test(v);
    if (single && !isClock && (RE.macFull.test(v) || RE.macPartial.test(v))) add('mac', RE.macFull.test(v) ? 'MAC address' : 'MAC address prefix', v, RE.macFull.test(v) ? 0.95 : 0.7, [tool('mac', v, 'mac')]);
    else if (single && RE.mac12.test(v) && !/^\d+$/.test(v)) add('mac', 'MAC address (no separators)', v, 0.55, [tool('mac', v, 'mac')]);

    if (single && RE.asn.test(v)) add('asn', 'Autonomous system number', v.replace(/\s+/g, '').toUpperCase(), 0.96, [tool('asn', v.replace(/\s+/g, '').toUpperCase(), 'asn'), tool('whois', v.replace(/\s+/g, '').toUpperCase(), 'asn')]);

    if (single && RE.url.test(v)) {
      var host = hostOfUrl(v), kids = [];
      if (host && RE.ipv4.test(host)) kids.push(tool('reverse', host, 'ip'), tool('whois', host, 'ip'), tool('asn', host, 'ip'), tool('abuse', host, 'ip'));
      else if (host) kids.push(tool('dns', host, 'domain'), tool('dnsreport', host, 'domain'), tool('whois', host, 'domain'), tool('abuse', host, 'domain'), tool('dnssec', host, 'domain'));
      if (/%[0-9a-f]{2}/i.test(v)) kids.push(tool('decode', v, 'text'));
      kids.push(tool('ioc', v, 'text'), tool('pivot', v, 'url'));
      add('url', 'URL (host: ' + (host || 'unknown') + ')', v, 0.96, kids);
    } else if (single && RE.email.test(v)) {
      var dom = v.split('@')[1].toLowerCase();
      add('email', 'Email address', v, 0.96, [tool('freemail', v, 'email'), tool('dnsreport', dom, 'domain'), tool('dns', dom, 'domain'), tool('whois', dom, 'domain'), tool('abuse', dom, 'domain'), tool('pivot', v, 'email')]);
    } else if (single && RE.hash.test(v)) {
      add('hash', ({ 32: 'MD5 or NTLM hash', 40: 'SHA-1 hash', 64: 'SHA-256 hash', 128: 'SHA-512 hash' })[v.length], v, 0.9, [tool('hash', v, 'hash')].concat(v.length <= 64 ? [tool('pivot', v, 'hash')] : []));
    } else if (single && RE.domain.test(v) && !RE.ipv4.test(v)) {
      var tld = v.slice(v.lastIndexOf('.') + 1).toLowerCase();
      var conf = FILE_EXT[tld] ? 0.3 : 0.93;
      var d = v.toLowerCase().replace(/\.$/, '');
      if (FILE_EXT[tld]) add('file', 'File name (not a domain)', v, conf, [tool('hash', v, 'text'), tool('ioc', v, 'text')]);
      else add('domain', 'Domain name', d, conf, [tool('dns', d, 'domain'), tool('dnsreport', d, 'domain'), tool('dnssec', d, 'domain'), tool('propagation', d, 'domain'), tool('whois', d, 'domain'), tool('abuse', d, 'domain'), tool('freemail', d, 'domain'), tool('pivot', d, 'domain')]);
    }

    if (single && RE.cve.test(v)) add('cve', 'CVE identifier', v.toUpperCase(), 0.95, [ext('NVD entry', 'NIST National Vulnerability Database', 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.toUpperCase())), ext('CISA KEV search', 'Known exploited vulnerabilities', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog')]);
    if (single && RE.attack.test(v)) add('attack', 'MITRE ATT&CK technique', v, 0.93, [ext('ATT&CK page', 'MITRE ATT&CK', 'https://attack.mitre.org/techniques/' + v.replace('.', '/') + '/')]);

    if (single && RE.jwt.test(v)) add('jwt', 'JSON Web Token', v, 0.95, [tool('decode', v, 'text')]);

    if (single && /^\d{9,19}$/.test(v)) add('timestamp', 'Numeric timestamp (maybe)', v, 0.8, [tool('time', v, 'time')]);
    else if (/^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/.test(v) || /^\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}/.test(v) || /^[A-Z][a-z]{2},?\s+\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4}\s+\d{2}:/.test(v) || /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$/.test(v)) {
      add('timestamp', 'Date and time', v, 0.85, [tool('time', v, 'time')]);
    }

    if (single && /^\d{1,6}$/.test(v)) {
      var n = +v, k = [];
      if (n >= 1 && n <= 65535) k.push(tool('ports', v, 'port'));
      if (n <= 4294967295) k.push(tool('asn', 'AS' + v, 'asn'));
      if (/^\d{3,5}$/.test(v)) k.push(tool('reference', v, 'text'));
      if (k.length) add('number', 'Number: port, ASN or event ID?', v, 0.45, k);
    }

    // Encodings
    var enc = [];
    if (/%[0-9a-f]{2}/i.test(v)) enc.push('percent-encoded text');
    if (/&#?\w+;/.test(v) && /&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(v)) enc.push('HTML entities');
    if (/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}/i.test(v)) enc.push('escape sequences');
    if (single && looksBase64(v) && !RE.hash.test(v) && !RE.jwt.test(v) && !RE.domain.test(v) && !/^\d+$/.test(v)) enc.push('Base64');
    if (looksHex(v)) enc.push('hex bytes');
    if (/fromCharCode|\[char\]\s*\d+/i.test(v)) enc.push('character codes');
    if (enc.length) add('encoded', 'Possibly ' + enc.join(' or '), v, 0.7, [tool('decode', v, 'text')]);

    // Free text with several indicators
    if (!single || out.length === 0) {
      var found = 0;
      if ((v.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).length) found++;
      if (/\bhttps?:\/\/\S+/i.test(v)) found++;
      if (/\b[a-z0-9-]+(\.[a-z0-9-]+)+\.[a-z]{2,}\b/i.test(v)) found++;
      if (/\b[a-f0-9]{32,64}\b/i.test(v)) found++;
      if (/\bCVE-\d{4}-\d{4,7}\b/i.test(v)) found++;
      if (found >= 1 && /\s/.test(v)) add('text', 'Text containing indicators', v, 0.65, [tool('ioc', v, 'text'), tool('decode', v, 'text')]);
    }

    out.sort(function (a, b) { return b.confidence - a.confidence; });
    return out;
  }

  // Build the "open in our tools" panel. Primary match first, then "also possible".
  // opts.skip: tool ids to leave out (the home page already shows its own reputation links).
  function render(container, matches, opts) {
    var skip = (opts && opts.skip) || [];
    while (container.firstChild) container.removeChild(container.firstChild);
    if (!matches.length) { container.hidden = true; return 0; }
    container.hidden = false;
    var count = 0;
    matches.slice(0, 3).forEach(function (m, i) {
      var head = document.createElement('p');
      head.className = i === 0 ? 'kit-routes-head' : 'kit-routes-head also';
      head.textContent = (i === 0 ? 'Looks like: ' : 'Also possible: ') + m.label;
      container.appendChild(head);
      var row = document.createElement('div');
      row.className = 'ioc-links';
      m.tools.forEach(function (t) {
        if (skip.indexOf(t.id) >= 0) return;
        var a = document.createElement('a');
        a.className = 'ioc-link';
        a.href = t.href;
        if (t.href.indexOf('http') === 0) { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
        a.title = t.why + (t.net ? ' (looks it up online from your browser)' : ' (runs offline)');
        a.textContent = t.label;
        var tag = document.createElement('span');
        tag.setAttribute('aria-hidden', 'true');
        tag.textContent = t.net ? ' ⇢' : '';
        a.appendChild(tag);
        row.appendChild(a);
        count++;
      });
      container.appendChild(row);
    });
    if (count) {
      var legend = document.createElement('p');
      legend.className = 'kit-note';
      legend.textContent = '⇢ looks it up online from your browser. The others run offline.';
      container.appendChild(legend);
    }
    return count;
  }

  root.SKRoute = { detect: detect, render: render, refang: refang, TOOLS: TOOLS };
})(typeof window !== 'undefined' ? window : this);
