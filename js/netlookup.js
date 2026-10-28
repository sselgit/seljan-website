// Lookup engine for the DNS, registry and network tools (SK.nl).
// Pure helpers (parsing, analysis) are unit tested. Network calls go straight from the visitor's browser to
// public sources, never through us: no cookies, no referrer, and private addresses and internal names are refused.
(function () {
  var SK = window.SK = window.SK || {};
  var NL = SK.nl = {};

  var TIMEOUT_MS = 9000;
  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }
  function enc(s) { return encodeURIComponent(s); }
  function fail(msg) { var e = new Error(msg); e.userMessage = msg; return e; }

  /* ================================================================ record types */

  NL.TYPE = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DNAME: 39, OPT: 41, DS: 43, RRSIG: 46,
    NSEC: 47, DNSKEY: 48, NSEC3: 50, NSEC3PARAM: 51, TLSA: 52, SVCB: 64, HTTPS: 65, CAA: 257, ANY: 255 };
  var TYPE_NAMES = {};
  Object.keys(NL.TYPE).forEach(function (k) { TYPE_NAMES[NL.TYPE[k]] = k; });
  NL.typeName = function (code) { return TYPE_NAMES[code] || ('TYPE' + code); };
  var RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];
  NL.rcodeName = function (c) { return RCODES[c] || ('RCODE' + c); };

  /* ================================================================ names and addresses */

  // Lower-case ASCII (punycode) host name without a trailing dot, or null when it is not a usable name.
  NL.cleanName = function (s) {
    var v = String(s == null ? '' : s).trim().replace(/\.+$/, '');
    if (!v || v.length > 300 || /[\/\\@:?#\s]/.test(v)) return null;
    var ascii;
    try { ascii = new URL('http://' + v).hostname; } catch (e) { return null; }
    ascii = ascii.replace(/\.$/, '');
    if (!/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(ascii)) return null;
    return ascii;
  };

  var RESERVED_SUFFIXES = ['local', 'localhost', 'internal', 'lan', 'home', 'corp', 'intranet', 'localdomain', 'test', 'invalid', 'example', 'home.arpa', 'arpa'];

  // Single-label names and private-use suffixes are internal; they are never sent to public resolvers.
  NL.isReservedName = function (name) {
    var h = lower(name).replace(/\.+$/, '');
    if (!h || h.indexOf('.') < 0) return true;
    return RESERVED_SUFFIXES.some(function (s) { return h === s || h.slice(-(s.length + 1)) === '.' + s; });
  };

  // { version, text, routable, label } for an IP address, or null.
  NL.parseIp = function (s) {
    var v = String(s || '').trim();
    var c = SK.net && SK.net.classify(v);
    if (!c) return null;
    return { version: v.indexOf(':') >= 0 ? 6 : 4, text: c.ip, routable: !!c.routable, label: c.label };
  };

  NL.reverseName = function (ip) {
    var v4 = SK.net.parseIPv4(ip);
    if (v4 !== null) return SK.net.ipv4ToStr(v4).split('.').reverse().join('.') + '.in-addr.arpa';
    var v6 = SK.net.parseIPv6(ip);
    if (v6 !== null) return SK.net.ipv6Expand(v6).replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
    return null;
  };

  /* ================================================================ DNS wire format */

  function encodeName(name) {
    var out = [];
    String(name).replace(/\.$/, '').split('.').forEach(function (label) {
      if (!label || label.length > 63) throw fail('That name has an empty or over-long label.');
      out.push(label.length);
      for (var i = 0; i < label.length; i++) out.push(label.charCodeAt(i) & 255);
    });
    out.push(0);
    return out;
  }

  // opts: { dnssec: send the DO flag, cd: checking disabled }
  NL.encodeQuery = function (name, type, opts) {
    opts = opts || {};
    var b = [];
    function u16(n) { b.push((n >> 8) & 255, n & 255); }
    u16(0);                                    // message id 0, as RFC 8484 recommends for HTTP
    u16(0x0100 | (opts.cd ? 0x0010 : 0));      // recursion desired (+ checking disabled)
    u16(1); u16(0); u16(0); u16(opts.dnssec ? 1 : 0);
    Array.prototype.push.apply(b, encodeName(name));
    u16(type); u16(1);
    if (opts.dnssec) { b.push(0); u16(41); u16(1232); b.push(0, 0, 0x80, 0); u16(0); }  // EDNS OPT with the DO flag
    return new Uint8Array(b);
  };

  NL.b64url = function (bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  function b64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function hexOf(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s.toUpperCase();
  }

  function readName(buf, off) {
    var labels = [], jumped = false, next = off, pos = off, guard = 0;
    for (;;) {
      if (pos >= buf.length || guard++ > 128) throw new Error('bad DNS name');
      var len = buf[pos];
      if (len === 0) { pos++; if (!jumped) next = pos; break; }
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= buf.length) throw new Error('bad DNS pointer');
        var ptr = ((len & 0x3f) << 8) | buf[pos + 1];
        if (!jumped) next = pos + 2;
        jumped = true; pos = ptr;
        continue;
      }
      if (len & 0xc0) throw new Error('bad DNS label');
      pos++;
      var label = '';
      for (var i = 0; i < len; i++) label += String.fromCharCode(buf[pos + i]);
      labels.push(label);
      pos += len;
    }
    return [labels.length ? labels.join('.') + '.' : '.', next];
  }

  function fmtTime(sec) {
    var d = new Date(sec * 1000);
    return d.getUTCFullYear() + SK.pad(d.getUTCMonth() + 1) + SK.pad(d.getUTCDate()) + SK.pad(d.getUTCHours()) + SK.pad(d.getUTCMinutes()) + SK.pad(d.getUTCSeconds());
  }

  function parseRdata(type, buf, dv, start, end) {
    var i, parts, n;
    switch (type) {
      case 1: return Array.prototype.slice.call(buf, start, start + 4).join('.');
      case 28: {
        var v = 0n;
        for (i = 0; i < 16; i++) v = (v << 8n) | BigInt(buf[start + i]);
        return SK.net.ipv6Compress(v);
      }
      case 2: case 5: case 12: case 39: return readName(buf, start)[0];
      case 15: return dv.getUint16(start) + ' ' + readName(buf, start + 2)[0];
      case 16: {
        parts = [];
        for (i = start; i < end;) { n = buf[i]; var s = ''; for (var k = 0; k < n; k++) s += String.fromCharCode(buf[i + 1 + k]); parts.push(s); i += 1 + n; }
        return '"' + parts.join('') + '"';
      }
      case 6: {
        var m = readName(buf, start), r = readName(buf, m[1]), p = r[1];
        return m[0] + ' ' + r[0] + ' ' + [0, 4, 8, 12, 16].map(function (o) { return dv.getUint32(p + o); }).join(' ');
      }
      case 33: return dv.getUint16(start) + ' ' + dv.getUint16(start + 2) + ' ' + dv.getUint16(start + 4) + ' ' + readName(buf, start + 6)[0];
      case 257: {
        var tl = buf[start + 1], tag = '', val = '';
        for (i = 0; i < tl; i++) tag += String.fromCharCode(buf[start + 2 + i]);
        for (i = start + 2 + tl; i < end; i++) val += String.fromCharCode(buf[i]);
        return buf[start] + ' ' + tag + ' "' + val + '"';
      }
      case 43: return dv.getUint16(start) + ' ' + buf[start + 2] + ' ' + buf[start + 3] + ' ' + hexOf(buf.subarray(start + 4, end));
      case 48: return dv.getUint16(start) + ' ' + buf[start + 2] + ' ' + buf[start + 3] + ' ' + b64(buf.subarray(start + 4, end));
      case 46: {
        var sg = readName(buf, start + 18);
        return NL.typeName(dv.getUint16(start)) + ' ' + buf[start + 2] + ' ' + buf[start + 3] + ' ' + dv.getUint32(start + 4) + ' ' +
          fmtTime(dv.getUint32(start + 8)) + ' ' + fmtTime(dv.getUint32(start + 12)) + ' ' + dv.getUint16(start + 16) + ' ' + sg[0] + ' ' + b64(buf.subarray(sg[1], end));
      }
      case 64: case 65: {
        var tgt = readName(buf, start + 2), out = dv.getUint16(start) + ' ' + tgt[0];
        for (i = tgt[1]; i + 4 <= end;) { var key = dv.getUint16(i), vl = dv.getUint16(i + 2); out += ' key' + key + '=' + hexOf(buf.subarray(i + 4, i + 4 + vl)); i += 4 + vl; }
        return out;
      }
      default: return '\\# ' + (end - start) + ' ' + hexOf(buf.subarray(start, end));
    }
  }

  // Decode a DNS message into { id, rcode, rcodeName, aa, tc, rd, ra, ad, cd, questions, answers, authority, additional }.
  NL.decodeMessage = function (bytes) {
    var buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (buf.length < 12) throw fail('The DNS answer was too short.');
    var dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    var flags = dv.getUint16(2), counts = [dv.getUint16(4), dv.getUint16(6), dv.getUint16(8), dv.getUint16(10)], off = 12, i, s;
    var msg = { id: dv.getUint16(0), rcode: flags & 15, rcodeName: NL.rcodeName(flags & 15), aa: !!(flags & 0x0400), tc: !!(flags & 0x0200),
      rd: !!(flags & 0x0100), ra: !!(flags & 0x0080), ad: !!(flags & 0x0020), cd: !!(flags & 0x0010), questions: [], answers: [], authority: [], additional: [] };
    for (i = 0; i < counts[0]; i++) {
      var q = readName(buf, off);
      msg.questions.push({ name: q[0], type: dv.getUint16(q[1]) });
      off = q[1] + 4;
    }
    ['answers', 'authority', 'additional'].forEach(function (sec, si) {
      for (s = 0; s < counts[si + 1]; s++) {
        var nm = readName(buf, off), p = nm[1];
        var type = dv.getUint16(p), ttl = dv.getUint32(p + 4), rdlen = dv.getUint16(p + 8), rs = p + 10;
        if (type !== 41) {
          var data;
          try { data = parseRdata(type, buf, dv, rs, rs + rdlen); } catch (e) { data = '\\# ' + rdlen + ' ' + hexOf(buf.subarray(rs, rs + rdlen)); }
          msg[sec].push({ name: nm[0], type: type, typeName: NL.typeName(type), ttl: ttl, data: data });
        }
        off = rs + rdlen;
      }
    });
    return msg;
  };

  /* ================================================================ resolvers and requests */

  NL.RESOLVERS = [
    { id: 'google', name: 'Google Public DNS', json: 'https://dns.google/resolve', wire: 'https://dns.google/dns-query' },
    { id: 'cloudflare', name: 'Cloudflare 1.1.1.1', json: 'https://cloudflare-dns.com/dns-query', wire: 'https://cloudflare-dns.com/dns-query' },
    { id: 'dnssb', name: 'DNS.SB', wire: 'https://doh.dns.sb/dns-query' },
    { id: 'controld', name: 'Control D (unfiltered)', wire: 'https://freedns.controld.com/p0' },
    { id: 'rethink', name: 'RethinkDNS (basic)', wire: 'https://basic.rethinkdns.com/dns-query' }
  ];
  function resolverById(id) {
    for (var i = 0; i < NL.RESOLVERS.length; i++) if (NL.RESOLVERS[i].id === id) return NL.RESOLVERS[i];
    return NL.RESOLVERS[0];
  }

  // Fetch with no cookies, no referrer and a timeout. Resolves { status, ok, text, json, bytes }.
  NL.request = function (url, opts) {
    opts = opts || {};
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, opts.timeout || TIMEOUT_MS);
    var init = { method: 'GET', mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', headers: opts.headers || {} };
    if (ctl) init.signal = ctl.signal;
    return fetch(url, init).then(function (res) {
      var read = opts.binary ? res.arrayBuffer() : res.text();
      return read.then(function (body) {
        clearTimeout(timer);
        var out = { status: res.status, ok: res.ok };
        if (opts.binary) out.bytes = new Uint8Array(body);
        else { out.text = body; try { out.json = JSON.parse(body); } catch (e) { out.json = null; } }
        return out;
      });
    }, function (err) { clearTimeout(timer); throw err; });
  };

  NL.friendlyError = function (err) {
    if (err && err.userMessage) return err.userMessage;
    if (err && err.name === 'AbortError') return 'Timed out.';
    return 'Blocked or unreachable from this browser.';
  };

  function fromJson(j) {
    function map(list) { return (list || []).map(function (a) { return { name: a.name, type: a.type, typeName: NL.typeName(a.type), ttl: a.TTL, data: a.data }; }); }
    return { rcode: j.Status, rcodeName: NL.rcodeName(j.Status), ad: !!j.AD, cd: !!j.CD, tc: !!j.TC, answers: map(j.Answer), authority: map(j.Authority), additional: [] };
  }

  // Query one resolver. opts: { resolver: id, dnssec: request DNSSEC data, cd: skip validation }.
  // Always resolves to the same shape: { rcode, rcodeName, ad, answers: [...], authority: [...], resolver }.
  NL.query = function (name, type, opts) {
    opts = opts || {};
    var r = resolverById(opts.resolver || 'google');
    var p;
    if (r.json && !opts.wire) {
      var url = r.json + '?name=' + enc(name) + '&type=' + type + (opts.dnssec ? '&do=1' : '') + (opts.cd ? '&cd=1' : '');
      p = NL.request(url, { headers: { Accept: 'application/dns-json' } }).then(function (res) {
        if (!res.json || typeof res.json.Status !== 'number') throw fail('Unexpected DNS response.');
        return fromJson(res.json);
      });
    } else {
      var q = NL.b64url(NL.encodeQuery(name, type, opts));
      p = NL.request(r.wire + '?dns=' + q, { headers: { Accept: 'application/dns-message' }, binary: true }).then(function (res) {
        if (!res.ok) throw fail('The resolver answered with HTTP ' + res.status + '.');
        return NL.decodeMessage(res.bytes);
      });
    }
    return p.then(function (m) { m.resolver = r; return m; });
  };

  NL.txtValue = function (data) { return String(data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''); };
  NL.dataOf = function (msg, type) {
    return (msg.answers || []).filter(function (a) { return a.type === type; }).map(function (a) { return a.data; });
  };

  /* ================================================================ analysis: email and zone records */

  NL.parseSpf = function (txtValues) {
    var records = txtValues.map(NL.txtValue).filter(function (t) { return /^v=spf1(\s|$)/i.test(t); });
    var out = { records: records, count: records.length, all: '', lookups: 0, mechanisms: [] };
    if (!records.length) return out;
    var tokens = records[0].trim().split(/\s+/).slice(1);
    out.mechanisms = tokens;
    tokens.forEach(function (t) {
      var m = /^([+\-~?]?)all$/i.exec(t);
      if (m) out.all = m[1] || '+';
      if (/^[+\-~?]?(include|a|mx|ptr|exists)([:\/]|$)/i.test(t) || /^redirect=/i.test(t)) out.lookups++;
    });
    return out;
  };

  NL.parseDmarc = function (txtValues) {
    var rec = txtValues.map(NL.txtValue).filter(function (t) { return /^v=DMARC1/i.test(t); })[0];
    if (!rec) return null;
    var tags = {};
    rec.split(';').forEach(function (part) {
      var kv = part.trim().split('=');
      if (kv.length >= 2) tags[lower(kv[0].trim())] = kv.slice(1).join('=').trim();
    });
    return { record: rec, tags: tags, policy: lower(tags.p || '') };
  };

  NL.parseSoa = function (data) {
    var p = String(data || '').trim().split(/\s+/);
    if (p.length < 7) return null;
    return { mname: p[0], rname: p[1], serial: +p[2], refresh: +p[3], retry: +p[4], expire: +p[5], minimum: +p[6] };
  };

  // d: gathered records for one zone. Returns findings [{ level: pass|info|warn|error, title, detail }].
  NL.analyzeReport = function (d) {
    var f = [];
    function add(level, title, detail) { f.push({ level: level, title: title, detail: detail || '' }); }

    if (d.rcode === 3) { add('error', 'This domain does not exist', 'The resolver answered NXDOMAIN. Check the spelling, or the name may be unregistered or expired.'); return f; }

    // Name servers
    var ns = (d.ns || []).map(lower);
    if (!ns.length) add('error', 'No name servers found', 'Nothing answered for NS records. If this is a subdomain it may simply be served by its parent zone.');
    else if (ns.length === 1) add('warn', 'Only one name server', 'Use at least two name servers, ideally on different networks, so a single failure does not take the domain offline.');
    else add('pass', ns.length + ' name servers', ns.join(', '));

    // SOA
    var soa = d.soa ? NL.parseSoa(d.soa) : null;
    if (soa) {
      var notes = [];
      if (soa.refresh < 1200 || soa.refresh > 86400) notes.push('refresh ' + soa.refresh + 's is outside the usual 1200 to 86400');
      if (soa.retry < 120 || soa.retry > 7200) notes.push('retry ' + soa.retry + 's is outside the usual 120 to 7200');
      if (soa.expire < 604800 || soa.expire > 2419200) notes.push('expire ' + soa.expire + 's is outside the usual 604800 to 2419200');
      if (soa.minimum > 86400) notes.push('negative-caching TTL ' + soa.minimum + 's is over a day');
      add(notes.length ? 'info' : 'pass', 'SOA record present', 'Primary ' + soa.mname + ', serial ' + soa.serial + (notes.length ? '. Timers worth a look: ' + notes.join('; ') + '.' : '.'));
    } else if (ns.length) add('info', 'No SOA record at this name', 'Normal for a name inside a larger zone. A zone apex should always have one.');

    // Addresses
    var hasA = (d.a || []).length, hasAaaa = (d.aaaa || []).length, hasCname = (d.cname || []).length;
    if (hasCname && (ns.length && soa)) add('error', 'CNAME at the zone apex', 'A CNAME cannot sit beside the SOA and NS records. Use an A or AAAA record, or the provider\'s ALIAS/ANAME feature.');
    if (hasA || hasAaaa || hasCname) add('pass', 'Resolves to an address', [(d.a || []).join(', '), (d.aaaa || []).join(', '), hasCname ? 'CNAME ' + d.cname.join(', ') : ''].filter(Boolean).join(' | '));
    else add('info', 'No A, AAAA or CNAME at this name', 'Fine for a domain used only for email or as a parent of subdomains.');
    if (hasA && !hasAaaa) add('info', 'No IPv6 (AAAA) record', 'Not an error. IPv6 reachability improves access for IPv6-only networks.');
    (d.a || []).forEach(function (ip) {
      var c = SK.net && SK.net.classifyIPv4(ip);
      if (c && !c.routable) add('warn', 'A record points to a non-public address', ip + ' is ' + c.label + '. Outside visitors cannot reach it, and it can hint at internal addressing.');
    });

    // Mail
    var mx = d.mx || [];
    var nullMx = mx.length === 1 && /^0\s+\.?$/.test(mx[0].trim());
    if (nullMx) add('info', 'Null MX', 'This domain declares that it does not receive email (RFC 7505).');
    else if (!mx.length) add('info', 'No MX records', 'Mail for this domain falls back to its A record, which is rarely intended. Add a null MX if it should not receive mail.');
    else add('pass', mx.length + ' mail server' + (mx.length > 1 ? 's' : ''), mx.join(', '));
    var mxTargets = d.mxTargets || {};
    Object.keys(mxTargets).forEach(function (host) {
      var t = mxTargets[host];
      if (t.cname && t.cname.length) add('error', 'MX points to a CNAME', host + ' is an alias. Mail servers must be named by A or AAAA records (RFC 2181).');
      else if (!(t.a || []).length && !(t.aaaa || []).length) add('error', 'MX target does not resolve', host + ' has no address, so mail to this domain may bounce.');
    });

    // SPF
    var spf = NL.parseSpf(d.txt || []);
    if (!mx.length || nullMx) {
      if (!spf.count) add('info', 'No SPF record', 'A domain that sends no mail should publish "v=spf1 -all" so others cannot spoof it.');
    }
    if (spf.count > 1) add('error', 'More than one SPF record', 'Receivers treat several SPF records as a permanent error. Merge them into one.');
    else if (spf.count === 1) {
      var q = { '-': 'fail (strict)', '~': 'soft fail', '?': 'neutral', '+': 'allow everything', '': 'no "all" mechanism' }[spf.all];
      var lvl = spf.all === '-' ? 'pass' : (spf.all === '+' ? 'error' : 'warn');
      add(lvl, 'SPF: ' + q, spf.records[0] + (spf.lookups > 10 ? ' (about ' + spf.lookups + ' lookups, over the limit of 10)' : ''));
      if (spf.lookups > 10) add('error', 'SPF may exceed 10 DNS lookups', 'Counted ' + spf.lookups + ' lookup mechanisms at the top level. Over 10, receivers return a permanent error.');
    } else if (mx.length && !nullMx) add('warn', 'No SPF record', 'Without SPF, receivers cannot tell which servers may send mail for this domain.');

    // DMARC
    var dmarc = NL.parseDmarc(d.dmarc || []);
    if (!dmarc) { if (mx.length && !nullMx) add('warn', 'No DMARC record', 'Without DMARC, anyone can send mail that appears to come from this domain and the domain owner gets no reports.'); }
    else if (dmarc.policy === 'reject') add('pass', 'DMARC: reject', dmarc.record);
    else if (dmarc.policy === 'quarantine') add('pass', 'DMARC: quarantine', dmarc.record);
    else add('warn', 'DMARC is monitor-only (p=' + (dmarc.policy || 'missing') + ')', 'Spoofed mail is still delivered. Move to quarantine or reject once reports look clean.');
    if (dmarc && !dmarc.tags.rua) add('info', 'DMARC has no reporting address (rua)', 'Add rua=mailto:... to receive aggregate reports.');

    // Mail transport hardening (informational)
    if (mx.length && !nullMx) {
      if ((d.mtasts || []).length) add('pass', 'MTA-STS published', 'Receivers can require TLS when sending to this domain.');
      else add('info', 'No MTA-STS policy', 'MTA-STS makes sending servers insist on TLS. Optional hardening.');
    }

    // CAA, DNSSEC
    if ((d.caa || []).length) add('pass', 'CAA restricts certificate issuers', d.caa.join(' | '));
    else add('info', 'No CAA record', 'A CAA record limits which certificate authorities may issue certificates for the domain.');
    var ds = d.dnssec || {};
    if (ds.verdict === 'valid') add('pass', 'DNSSEC is signed and validates', '');
    else if (ds.verdict === 'bogus') add('error', 'DNSSEC validation fails', 'Validating resolvers return errors for this domain. Fix or remove the DS record at the registrar.');
    else if (ds.verdict) add('info', 'DNSSEC: ' + NL.dnssecText(ds.verdict), '');

    // TTLs
    if (d.minTtl !== undefined && d.minTtl !== null && d.minTtl < 60 && (hasA || hasAaaa)) add('info', 'Very short TTL', 'Address records have a TTL of ' + d.minTtl + ' seconds. Fine for failover, but it increases query load.');
    return f;
  };

  /* ================================================================ DNSSEC */

  var DNSSEC_ALGS = { 3: 'DSA (obsolete)', 5: 'RSA/SHA-1 (deprecated)', 6: 'DSA-NSEC3-SHA1 (obsolete)', 7: 'RSASHA1-NSEC3-SHA1 (deprecated)', 8: 'RSA/SHA-256', 10: 'RSA/SHA-512',
    12: 'GOST R 34.10-2001 (obsolete)', 13: 'ECDSA P-256/SHA-256', 14: 'ECDSA P-384/SHA-384', 15: 'Ed25519', 16: 'Ed448' };
  var DS_DIGESTS = { 1: 'SHA-1 (deprecated)', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384' };
  NL.dnssecAlgName = function (n) { return DNSSEC_ALGS[n] || ('algorithm ' + n); };
  NL.dsDigestName = function (n) { return DS_DIGESTS[n] || ('digest type ' + n); };

  var VERDICT_TEXT = {
    valid: 'signed, and the chain of trust validates',
    unsigned: 'not signed (no DS at the parent, no DNSKEY)',
    bogus: 'signed, but validation FAILS',
    island: 'has DNSKEY records but no DS at the parent, so resolvers do not validate it',
    brokenDs: 'a DS record exists at the parent but the zone publishes no DNSKEY',
    unknown: 'could not be determined'
  };
  NL.dnssecText = function (v) { return VERDICT_TEXT[v] || v; };

  // inputs: { ds: [..], dnskey: [..], normal: query result with the validation default, cd: query result with CD set }
  NL.dnssecVerdict = function (x) {
    var hasDs = (x.ds || []).length > 0, hasKey = (x.dnskey || []).length > 0;
    if (!hasDs && !hasKey) return 'unsigned';
    if (hasDs && !hasKey) return 'brokenDs';
    if (!hasDs && hasKey) return 'island';
    if (x.normal && x.cd && x.normal.rcode === 2 && x.cd.rcode === 0) return 'bogus';
    if (x.normal && x.normal.rcode === 0 && x.normal.ad) return 'valid';
    return 'unknown';
  };

  // Split "key tag alg digesttype digest" and "flags proto alg key" strings.
  NL.parseDs = function (data) { var p = String(data).trim().split(/\s+/); return { keyTag: +p[0], alg: +p[1], digestType: +p[2], digest: p.slice(3).join('') }; };
  NL.parseDnskey = function (data) {
    var p = String(data).trim().split(/\s+/);
    var flags = +p[0];
    return { flags: flags, role: flags & 1 ? 'KSK (key signing key)' : 'ZSK (zone signing key)', protocol: +p[1], alg: +p[2], key: p.slice(3).join('') };
  };
  NL.parseRrsig = function (data) {
    var p = String(data).trim().split(/\s+/);
    // Resolvers write the validity times either as YYYYMMDDHHMMSS (DNS presentation format) or as Unix seconds.
    function ts(s) {
      var m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(s);
      if (m) return Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
      return /^\d{1,11}$/.test(s) ? Number(s) * 1000 : NaN;
    }
    return { covers: String(p[0]).toUpperCase(), alg: +p[1], labels: +p[2], origTtl: +p[3], expires: ts(p[4]), inception: ts(p[5]), keyTag: +p[6], signer: p[7] };
  };

  /* ================================================================ propagation */

  // results: [{ resolver: {id,name}, ok, rcode, answers: [data strings] | error }]
  NL.comparePropagation = function (results) {
    var groups = {}, answered = 0;
    results.forEach(function (r) {
      if (!r.ok) return;
      answered++;
      var key = r.rcode === 0 ? r.answers.slice().sort().join(' | ') : '(' + NL.rcodeName(r.rcode) + ')';
      (groups[key] = groups[key] || []).push(r.resolver.name);
    });
    var keys = Object.keys(groups);
    return { answered: answered, failed: results.length - answered, groups: keys.map(function (k) { return { answer: k, resolvers: groups[k] }; }), consistent: answered > 0 && keys.length === 1 };
  };

  /* ================================================================ registry data (RDAP) */

  // RDAP bootstrap redirector: it forwards to the right registry, and each registry must allow browser requests.
  // IPv6 colons must stay as they are in the path: rdap.org answers HTTP 400 when they are percent-encoded.
  NL.rdapUrl = function (kind, value) {
    return 'https://rdap.org/' + kind + '/' + (kind === 'ip' ? String(value).replace(/[^0-9A-Fa-f:.]/g, function (c) { return enc(c); }) : enc(value));
  };

  NL.rdap = function (kind, value) {
    return NL.request(NL.rdapUrl(kind, value), { headers: { Accept: 'application/rdap+json, application/json' }, timeout: 12000 }).then(function (res) {
      if (res.status === 404) throw fail('No registration found for ' + value + '.');
      if (res.status === 429) throw fail('Rate limited by the registry. Try again in a minute.');
      if (!res.json) throw fail('The registry answered in an unexpected format (HTTP ' + res.status + ').');
      if (!res.ok) throw fail('The registry answered with HTTP ' + res.status + '.');
      return res.json;
    });
  };

  function vcardValue(entity, prop) {
    var v = entity && entity.vcardArray && entity.vcardArray[1];
    if (!v) return '';
    var found = v.filter(function (x) { return x[0] === prop; })[0];
    return found ? String(found[3] == null ? '' : (Array.isArray(found[3]) ? found[3].filter(Boolean).join(', ') : found[3])) : '';
  }
  function allEntities(list, out) {
    (list || []).forEach(function (e) { out.push(e); allEntities(e.entities, out); });
    return out;
  }
  function eventDate(j, action) {
    var ev = (j.events || []).filter(function (e) { return e.eventAction === action; })[0];
    return ev && ev.eventDate ? String(ev.eventDate).slice(0, 10) : '';
  }

  NL.abuseContacts = function (j) {
    var out = [];
    allEntities(j.entities, []).forEach(function (e) {
      if ((e.roles || []).indexOf('abuse') >= 0) {
        var email = vcardValue(e, 'email'), tel = vcardValue(e, 'tel'), name = vcardValue(e, 'fn');
        if (email || tel) out.push({ name: name, email: email, phone: tel });
      }
    });
    return out;
  };

  // Domain: { name, status, registered, updated, expires, registrar, registrarId, nameservers, dnssec, abuse, entities }
  NL.summarizeDomain = function (j) {
    var ents = allEntities(j.entities, []);
    var registrar = ents.filter(function (e) { return (e.roles || []).indexOf('registrar') >= 0; })[0];
    var ids = registrar && registrar.publicIds ? registrar.publicIds.filter(function (p) { return /iana/i.test(p.type || ''); }) : [];
    var people = ents.filter(function (e) { return /registrant|administrative|technical|billing/.test((e.roles || []).join(' ')); }).map(function (e) {
      return { roles: (e.roles || []).join(', '), name: vcardValue(e, 'fn'), org: vcardValue(e, 'org'), email: vcardValue(e, 'email') };
    }).filter(function (p) { return p.name || p.org || p.email; });
    return {
      name: j.ldhName || j.unicodeName || '', status: j.status || [], registered: eventDate(j, 'registration'), updated: eventDate(j, 'last changed'),
      expires: eventDate(j, 'expiration'), registrar: registrar ? vcardValue(registrar, 'fn') : '', registrarId: ids[0] ? ids[0].identifier : '',
      nameservers: (j.nameservers || []).map(function (n) { return lower(n.ldhName); }),
      dnssec: j.secureDNS ? (j.secureDNS.delegationSigned ? 'signed' : 'unsigned') : '', abuse: NL.abuseContacts(j), contacts: people
    };
  };

  NL.summarizeIp = function (j) {
    var cidrs = (j.cidr0_cidrs || []).map(function (c) { return (c.v4prefix || c.v6prefix) + '/' + c.length; });
    var org = allEntities(j.entities, []).filter(function (e) { return vcardValue(e, 'fn') && (e.roles || []).some(function (r) { return /registrant|administrative|technical/.test(r); }); })[0];
    var desc = (j.remarks || []).map(function (r) { return (r.description || []).join(' '); }).filter(Boolean).join(' ').slice(0, 300);
    return { name: j.name || '', handle: j.handle || '', range: (j.startAddress || '') + (j.endAddress ? ' - ' + j.endAddress : ''), cidrs: cidrs, country: j.country || '',
      type: j.type || '', registered: eventDate(j, 'registration'), updated: eventDate(j, 'last changed'), organization: org ? vcardValue(org, 'fn') : '', description: desc, abuse: NL.abuseContacts(j) };
  };

  NL.summarizeAutnum = function (j) {
    var org = allEntities(j.entities, []).filter(function (e) { return vcardValue(e, 'fn'); })[0];
    return { name: j.name || '', handle: j.handle || '', range: j.startAutnum ? 'AS' + j.startAutnum + (j.endAutnum && j.endAutnum !== j.startAutnum ? ' - AS' + j.endAutnum : '') : '',
      country: j.country || '', type: j.type || '', registered: eventDate(j, 'registration'), updated: eventDate(j, 'last changed'), organization: org ? vcardValue(org, 'fn') : '', abuse: NL.abuseContacts(j) };
  };

  /* ================================================================ ASN (Team Cymru DNS service, RIPEstat) */

  // "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
  NL.parseCymruOrigin = function (txt) {
    var p = NL.txtValue(txt).split('|').map(function (s) { return s.trim(); });
    if (p.length < 5) return null;
    return { asns: p[0].split(/\s+/).filter(Boolean).map(Number), prefix: p[1], country: p[2], registry: p[3], allocated: p[4] };
  };
  // "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
  NL.parseCymruAsn = function (txt) {
    var p = NL.txtValue(txt).split('|').map(function (s) { return s.trim(); });
    if (p.length < 5) return null;
    return { asn: +p[0], country: p[1], registry: p[2], allocated: p[3], name: p.slice(4).join('|') };
  };

  NL.cymruOriginName = function (ip) {
    var v4 = SK.net.parseIPv4(ip);
    if (v4 !== null) return SK.net.ipv4ToStr(v4).split('.').reverse().join('.') + '.origin.asn.cymru.com';
    var v6 = SK.net.parseIPv6(ip);
    if (v6 !== null) return SK.net.ipv6Expand(v6).replace(/:/g, '').split('').reverse().join('.') + '.origin6.asn.cymru.com';
    return null;
  };

  // "AS15169", "as 15169" or "15169" -> 15169, or null.
  NL.parseAsn = function (s) {
    var m = /^\s*(?:AS\s*)?(\d{1,10})\s*$/i.exec(String(s || ''));
    if (!m) return null;
    var n = +m[1];
    return n >= 0 && n <= 4294967295 ? n : null;
  };

  NL.ripeStat = function (endpoint, resource, opts) {
    return NL.request('https://stat.ripe.net/data/' + endpoint + '/data.json?resource=' + enc(resource) + '&sourceapp=seljan-net', { headers: { Accept: 'application/json' }, timeout: (opts && opts.timeout) || 10000 }).then(function (res) {
      if (!res.json || !res.json.data) throw fail('RIPEstat answered in an unexpected format.');
      return res.json.data;
    });
  };

  /* ================================================================ MAC addresses */

  // Returns { hex: UPPERCASE hex digits, full: true for a complete 48-bit address } or null.
  NL.parseMac = function (s) {
    var t = lower(s).trim();
    if (!/^[0-9a-f]{2}([:\-]?[0-9a-f]{2})*$|^([0-9a-f]{4}\.){2,5}[0-9a-f]{4}$|^[0-9a-f]{6,12}$/.test(t)) return null;
    var hex = t.replace(/[:\-.]/g, '').toUpperCase();
    if (hex.length < 6 || hex.length > 12) return null;
    return { hex: hex, full: hex.length === 12 };
  };

  NL.macFlags = function (hex) {
    var b0 = parseInt(hex.slice(0, 2), 16);
    return { multicast: !!(b0 & 1), localAdmin: !!(b0 & 2), broadcast: hex === 'FFFFFFFFFFFF' };
  };

  NL.formatMac = function (hex12) {
    var pairs = hex12.match(/.{2}/g);
    return { colon: pairs.join(':'), hyphen: pairs.join('-'), dotted: hex12.match(/.{4}/g).join('.').toLowerCase(), plain: hex12 };
  };

  // db: parsed oui.json. Longest assignment wins: 36-bit, then 28-bit, then 24-bit.
  NL.lookupOui = function (db, hex) {
    var tries = [['S', 9, 'MA-S (36-bit block)'], ['M', 7, 'MA-M (28-bit block)'], ['L', 6, 'MA-L (24-bit block)']];
    for (var i = 0; i < tries.length; i++) {
      var t = tries[i], key = hex.slice(0, t[1]);
      if (hex.length >= t[1] && db[t[0]] && Object.prototype.hasOwnProperty.call(db[t[0]], key)) return { vendor: db.v[db[t[0]][key]], registry: t[2], prefix: key };
    }
    return null;
  };

  /* ================================================================ email providers */

  var FREE = ('gmail.com googlemail.com outlook.com hotmail.com live.com msn.com passport.com windowslive.com yahoo.com ymail.com rocketmail.com aol.com aim.com icloud.com me.com mac.com ' +
    'proton.me protonmail.com protonmail.ch pm.me tutanota.com tuta.com tutanota.de tutamail.com tuta.io keemail.me zoho.com zohomail.com zoho.eu mail.com email.com usa.com post.com ' +
    'gmx.com gmx.net gmx.de gmx.at gmx.ch web.de yandex.com yandex.ru ya.ru mail.ru inbox.ru list.ru bk.ru internet.ru rambler.ru qq.com 163.com 126.com yeah.net sina.com sina.cn sohu.com ' +
    'naver.com daum.net hanmail.net kakao.com seznam.cz email.cz centrum.cz wp.pl o2.pl onet.pl onet.eu interia.pl gazeta.pl libero.it virgilio.it tiscali.it alice.it orange.fr free.fr ' +
    'laposte.net sfr.fr wanadoo.fr neuf.fr t-online.de freenet.de rediffmail.com hushmail.com mailfence.com cock.li riseup.net disroot.org fastmail.com fastmail.fm duck.com ' +
    'lycos.com juno.com netzero.net earthlink.net bigpond.com optusnet.com.au shaw.ca rogers.com sympatico.ca telus.net bell.net').split(' ');
  var ISP = 'att.net sbcglobal.net bellsouth.net verizon.net comcast.net cox.net charter.net frontier.com windstream.net optonline.net roadrunner.com twc.com'.split(' ');
  var DISPOSABLE = ('mailinator.com guerrillamail.com guerrillamail.net guerrillamail.org sharklasers.com grr.la guerrillamailblock.com 10minutemail.com 10minutemail.net temp-mail.org tempmail.com ' +
    'tempmail.net yopmail.com yopmail.fr trashmail.com trashmail.net getnada.com nada.email maildrop.cc throwawaymail.com dispostable.com fakeinbox.com mailnesia.com mintemail.com ' +
    'spamgourmet.com mohmal.com emailondeck.com burnermail.io tempr.email moakt.com mytemp.email dropmail.me inboxkitten.com mailtemp.net tempinbox.com discard.email').split(' ');
  var FREE_PATTERNS = [/^yahoo\.[a-z.]{2,}$/, /^hotmail\.[a-z.]{2,}$/, /^live\.[a-z.]{2,}$/, /^outlook\.[a-z.]{2,}$/, /^gmx\.[a-z.]{2,}$/];
  var FREE_SET = {}, ISP_SET = {}, DISP_SET = {};
  FREE.forEach(function (d) { FREE_SET[d] = true; });
  ISP.forEach(function (d) { ISP_SET[d] = true; });
  DISPOSABLE.forEach(function (d) { DISP_SET[d] = true; });

  // Accepts a domain or an address. Returns { domain, category: free|disposable|isp|none }.
  NL.classifyEmailDomain = function (input) {
    var v = lower(input).trim();
    var at = v.lastIndexOf('@');
    var d = (at >= 0 ? v.slice(at + 1) : v).replace(/\.+$/, '');
    var cat = 'none';
    if (DISP_SET[d]) cat = 'disposable';
    else if (FREE_SET[d] || FREE_PATTERNS.some(function (re) { return re.test(d); })) cat = 'free';
    else if (ISP_SET[d]) cat = 'isp';
    return { domain: d, category: cat };
  };

  var MX_PROVIDERS = [
    [/(^|\.)(google|googlemail)\.com\.?$/, 'Google (Gmail or Google Workspace)'], [/\.protection\.outlook\.com\.?$/, 'Microsoft 365 / Exchange Online'], [/(^|\.)hotmail\.com\.?$|\.olc\.protection\.outlook\.com\.?$/, 'Microsoft (Outlook.com)'],
    [/(^|\.)pphosted\.com\.?$|(^|\.)ppe-hosted\.com\.?$/, 'Proofpoint'], [/(^|\.)mimecast\.com\.?$|(^|\.)mimecast-offshore\.com\.?$/, 'Mimecast'], [/(^|\.)zoho\.(com|eu|in|com\.au)\.?$/, 'Zoho Mail'],
    [/(^|\.)secureserver\.net\.?$/, 'GoDaddy mail'], [/(^|\.)messagingengine\.com\.?$/, 'Fastmail'], [/(^|\.)(protonmail\.ch|proton\.me)\.?$/, 'Proton Mail'], [/(^|\.)mailgun\.org\.?$/, 'Mailgun'],
    [/(^|\.)yahoodns\.net\.?$|(^|\.)yahoo\.com\.?$/, 'Yahoo Mail'], [/(^|\.)icloud\.com\.?$/, 'Apple iCloud Mail'], [/(^|\.)barracudanetworks\.com\.?$/, 'Barracuda'],
    [/(^|\.)mailchannels\.net\.?$/, 'MailChannels'], [/(^|\.)emailsrvr\.com\.?$/, 'Rackspace Email'], [/(^|\.)ovh\.net\.?$/, 'OVH mail'], [/(^|\.)qq\.com\.?$/, 'Tencent QQ Mail'], [/(^|\.)yandex\.(net|ru)\.?$/, 'Yandex Mail']
  ];
  NL.mxProvider = function (host) {
    var h = lower(host).replace(/^\d+\s+/, '').trim();
    for (var i = 0; i < MX_PROVIDERS.length; i++) if (MX_PROVIDERS[i][0].test(h)) return MX_PROVIDERS[i][1];
    return '';
  };

  /* ================================================================ orchestration (each takes injectable sources for tests) */

  // A query that never rejects: on failure it resolves { error }.
  function safeQuery(query, name, type, extra) {
    return Promise.resolve().then(function () { return query(name, type, extra); }).then(function (r) { return r; }, function (e) { return { error: e }; });
  }
  function dataList(res, type) { return res && !res.error ? NL.dataOf(res, type) : []; }
  function lowerList(list) { return list.map(lower); }

  // Full record set for the DNS report.
  NL.gatherReport = function (name, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, resolver = opts.resolver || 'google';
    function q(n, t, extra) { return safeQuery(query, n, t, Object.assign({ resolver: resolver }, extra || {})); }
    var T = NL.TYPE;
    return Promise.all([q(name, T.NS), q(name, T.SOA), q(name, T.A), q(name, T.AAAA), q(name, T.CNAME), q(name, T.MX), q(name, T.TXT), q(name, T.CAA),
      q('_dmarc.' + name, T.TXT), q('_mta-sts.' + name, T.TXT), NL.dnssecCheck(name, { query: query, resolver: resolver })]).then(function (r) {
      var all = r.slice(0, 10);
      if (all.every(function (x) { return x.error; })) throw fail('Could not reach the DNS resolver. ' + NL.friendlyError(all[0].error));
      var d = {
        name: name, resolver: resolver,
        rcode: all.some(function (x) { return !x.error && x.rcode === 3; }) ? 3 : 0,
        ns: lowerList(dataList(r[0], T.NS)), soa: dataList(r[1], T.SOA)[0] || '', a: dataList(r[2], T.A), aaaa: dataList(r[3], T.AAAA), cname: dataList(r[4], T.CNAME),
        mx: dataList(r[5], T.MX), txt: dataList(r[6], T.TXT), caa: dataList(r[7], T.CAA), dmarc: dataList(r[8], T.TXT), mtasts: dataList(r[9], T.TXT).filter(function (t) { return /v=STSv1/i.test(t); }),
        dnssec: r[10], errors: []
      };
      all.forEach(function (x, i) { if (x.error) d.errors.push(['NS', 'SOA', 'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'DMARC', 'MTA-STS'][i]); });
      var ttls = [];
      [r[2], r[3]].forEach(function (x) { if (x && !x.error) x.answers.forEach(function (a) { if (a.type === T.A || a.type === T.AAAA) ttls.push(a.ttl); }); });
      d.minTtl = ttls.length ? Math.min.apply(null, ttls) : null;
      var hosts = d.mx.map(function (m) { return lower(m.replace(/^\d+\s+/, '')); }).filter(function (h) { return h && h !== '.'; }).slice(0, 5);
      return Promise.all(hosts.map(function (h) {
        var bare = h.replace(/\.$/, '');
        return Promise.all([q(bare, T.A), q(bare, T.AAAA), q(bare, T.CNAME)]).then(function (x) { return [h, { a: dataList(x[0], T.A), aaaa: dataList(x[1], T.AAAA), cname: dataList(x[2], T.CNAME) }]; });
      })).then(function (pairs) {
        d.mxTargets = {};
        pairs.forEach(function (p) { d.mxTargets[p[0]] = p[1]; });
        return d;
      });
    });
  };

  // DS at the parent, DNSKEY in the zone, and whether a validating resolver accepts the answer.
  NL.dnssecCheck = function (name, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, resolver = opts.resolver || 'google';
    function q(t, extra) { return safeQuery(query, name, t, Object.assign({ resolver: resolver, dnssec: true }, extra || {})); }
    return Promise.all([q(NL.TYPE.DS), q(NL.TYPE.DNSKEY), q(NL.TYPE.DNSKEY, { cd: true })]).then(function (r) {
      var dsR = r[0], keyR = r[1], cdR = r[2];
      if (dsR.error && keyR.error) return { error: dsR.error, verdict: 'unknown', ds: [], dnskey: [], rrsigs: [] };
      var rrsigs = [];
      if (!keyR.error) keyR.answers.forEach(function (a) { if (a.type === NL.TYPE.RRSIG) { try { rrsigs.push(NL.parseRrsig(a.data)); } catch (e) { /* skip */ } } });
      var cdUse = cdR.error ? keyR : cdR;
      var out = { ds: dataList(dsR, NL.TYPE.DS), dnskey: dataList(keyR.error ? cdR : keyR, NL.TYPE.DNSKEY), rrsigs: rrsigs, normal: keyR.error ? null : keyR, cd: cdUse.error ? null : cdUse };
      if (!out.dnskey.length && !cdR.error) out.dnskey = dataList(cdR, NL.TYPE.DNSKEY);
      out.verdict = NL.dnssecVerdict(out);
      return out;
    });
  };

  function sameIp(a, b) {
    var x = SK.net.parseIPv6(a), y = SK.net.parseIPv6(b);
    if (x !== null && y !== null) return x === y;
    return a === b;
  }

  // PTR records for an IP, each checked by looking the name up again (forward-confirmed reverse DNS).
  NL.reverseLookup = function (ip, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, resolver = opts.resolver || 'google';
    var rev = NL.reverseName(ip), v6 = ip.indexOf(':') >= 0;
    if (!rev) return Promise.reject(fail('That is not a valid IP address.'));
    return query(rev, NL.TYPE.PTR, { resolver: resolver }).then(function (res) {
      var names = NL.dataOf(res, NL.TYPE.PTR).slice(0, 4);
      return Promise.all(names.map(function (n) {
        return safeQuery(query, n.replace(/\.$/, ''), v6 ? NL.TYPE.AAAA : NL.TYPE.A, { resolver: resolver }).then(function (fr) {
          var addrs = dataList(fr, v6 ? NL.TYPE.AAAA : NL.TYPE.A);
          return { name: n, addrs: addrs, confirmed: addrs.some(function (a) { return sameIp(a, ip); }), error: fr.error ? NL.friendlyError(fr.error) : '' };
        });
      })).then(function (ptr) { return { ip: ip, rcode: res.rcode, rcodeName: res.rcodeName, ptr: ptr }; });
    });
  };

  // Ask every public resolver the same question and compare. Always uses the wire format so all resolvers take one path.
  NL.propagation = function (name, type, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, resolvers = opts.resolvers || NL.RESOLVERS;
    return Promise.all(resolvers.map(function (r) {
      var t0 = Date.now();
      return safeQuery(query, name, type, { resolver: r.id, wire: true }).then(function (res) {
        if (res.error) return { resolver: r, ok: false, error: NL.friendlyError(res.error), ms: Date.now() - t0 };
        var ans = res.answers.filter(function (a) { return a.type === type || (type === NL.TYPE.A && a.type === NL.TYPE.CNAME); });
        return { resolver: r, ok: true, rcode: res.rcode, rcodeName: res.rcodeName, answers: ans.map(function (a) { return a.data; }), ttl: ans.length ? Math.min.apply(null, ans.map(function (a) { return a.ttl; })) : null, ms: Date.now() - t0 };
      });
    })).then(function (results) { return { results: results, summary: NL.comparePropagation(results) }; });
  };

  NL.daysBetween = function (fromMs, toMs) { return Math.floor((toMs - fromMs) / 86400000); };

  // WHOIS data through RDAP for a domain, IP or AS number.
  NL.whoisLookup = function (kind, value, opts) {
    opts = opts || {};
    var rdap = opts.rdap || NL.rdap, now = opts.now || Date.now();
    var path = kind === 'asn' ? 'autnum' : kind;
    var rv = kind === 'asn' ? String(NL.parseAsn(value)) : value;
    return rdap(path, rv).then(function (j) {
      var summary = kind === 'domain' ? NL.summarizeDomain(j) : (kind === 'ip' ? NL.summarizeIp(j) : NL.summarizeAutnum(j));
      if (kind === 'domain') {
        var reg = summary.registered ? Date.parse(summary.registered) : NaN, exp = summary.expires ? Date.parse(summary.expires) : NaN;
        summary.ageDays = isNaN(reg) ? null : NL.daysBetween(reg, now);
        summary.daysToExpiry = isNaN(exp) ? null : NL.daysBetween(now, exp);
      }
      return { kind: kind, value: value, summary: summary, raw: j };
    });
  };

  // Where to send an abuse report: the domain's registrar plus the network owner of each address it uses.
  NL.abuseLookup = function (target, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, rdap = opts.rdap || NL.rdap, ripe = opts.ripe || NL.ripeStat;
    function network(ip) {
      return Promise.all([
        Promise.resolve().then(function () { return ripe('abuse-contact-finder', ip, { timeout: 8000 }); }).then(function (d) { return { contacts: (d.abuse_contacts || []).slice(0, 5), rir: d.authoritative_rir || '' }; }, function (e) { return { error: NL.friendlyError(e) }; }),
        Promise.resolve().then(function () { return rdap('ip', ip); }).then(function (j) { return NL.summarizeIp(j); }, function (e) { return { error: NL.friendlyError(e) }; })
      ]).then(function (r) { return { ip: ip, ripe: r[0], rdap: r[1] }; });
    }
    if (target.kind === 'ip') return network(target.value).then(function (n) { return { target: target, registrar: null, networks: [n] }; });
    return Promise.all([
      Promise.resolve().then(function () { return rdap('domain', target.value); }).then(function (j) { return NL.summarizeDomain(j); }, function (e) { return { error: NL.friendlyError(e) }; }),
      safeQuery(query, target.value, NL.TYPE.A, { resolver: 'google' }), safeQuery(query, target.value, NL.TYPE.AAAA, { resolver: 'google' })
    ]).then(function (r) {
      var ips = dataList(r[1], NL.TYPE.A).concat(dataList(r[2], NL.TYPE.AAAA)).filter(function (ip) { var p = NL.parseIp(ip); return p && p.routable; }).slice(0, 3);
      return Promise.all(ips.map(network)).then(function (nets) { return { target: target, registrar: r[0], networks: nets, noAddress: !ips.length }; });
    });
  };

  // Routing and ownership for an AS number, or for the AS that announces an IP.
  NL.asnLookup = function (input, opts) {
    opts = opts || {};
    var query = opts.query || NL.query, rdap = opts.rdap || NL.rdap, ripe = opts.ripe || NL.ripeStat;
    var out = { input: input, ip: null, origin: null, asn: null, info: null, rdap: null, overview: null, errors: {} };
    function guard(label, fn) { return Promise.resolve().then(fn).then(function (v) { return v; }, function (e) { out.errors[label] = NL.friendlyError(e); return null; }); }
    var first;
    var asn = NL.parseAsn(input);
    if (asn !== null && !/[.:]/.test(String(input))) { out.asn = asn; first = Promise.resolve(); }
    else {
      var ip = NL.parseIp(input);
      if (!ip) return Promise.reject(fail('Enter an AS number such as AS15169, or a public IP address.'));
      out.ip = ip.text;
      first = guard('origin', function () {
        return query(NL.cymruOriginName(ip.text), NL.TYPE.TXT, { resolver: 'google' }).then(function (res) {
          var o = NL.parseCymruOrigin(NL.dataOf(res, NL.TYPE.TXT)[0]);
          if (!o) throw fail('No announced route found for that address.');
          out.origin = o; out.asn = o.asns[0];
        });
      });
    }
    return first.then(function () {
      if (out.asn === null) return out;
      var n = out.asn;
      return Promise.all([
        guard('info', function () { return query('AS' + n + '.asn.cymru.com', NL.TYPE.TXT, { resolver: 'google' }).then(function (res) { out.info = NL.parseCymruAsn(NL.dataOf(res, NL.TYPE.TXT)[0]); }); }),
        guard('rdap', function () { return rdap('autnum', String(n)).then(function (j) { out.rdap = NL.summarizeAutnum(j); }); }),
        guard('overview', function () { return ripe('as-overview', 'AS' + n, { timeout: 7000 }).then(function (d) { out.overview = { holder: d.holder || '', announced: !!d.announced }; }); })
      ]).then(function () { return out; });
    });
  };

  // The prefixes an AS announces. The answer can be large (hundreds of KB), so it is fetched on request.
  NL.asnPrefixes = function (asn, opts) {
    opts = opts || {};
    var ripe = opts.ripe || NL.ripeStat;
    return Promise.resolve().then(function () { return ripe('announced-prefixes', 'AS' + asn, { timeout: 30000 }); }).then(function (d) {
      var p = (d.prefixes || []).map(function (x) { return x.prefix; });
      return { count: p.length, sample: p.slice(0, 40) };
    });
  };
})();
