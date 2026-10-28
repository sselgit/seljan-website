// Snort and Suricata rule parser and a small match simulator (SK.ids).
//
// The simulator covers the options that matter for tuning: header (protocol, addresses, ports), flow, content with
// nocase / offset / depth / distance / within / startswith / endswith, pcre, dsize, isdataat, urilen, bsize, and the HTTP
// buffers. Anything else is parsed and kept, but not evaluated, and the result is marked approximate.
//
// Search windows follow Suricata's inspection code: a window is [start, end) inside a buffer where
//   absolute:  start = offset, end = offset + depth       (depth counts from offset)
//   relative:  start = previous match end + distance, end = previous match end + distance + within
(function () {
  var SK = window.SK = window.SK || {};
  var IDS = SK.ids = {};

  var STEP_BUDGET = 40000;

  function fail(msg) { var e = new Error(msg); e.userMessage = msg; return e; }

  /* ================================================================ bytes and strings */

  // Bytes to a string with one character per byte, so offsets in the string are offsets in the data.
  IDS.bin = function (bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 8192) out += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192));
    return out;
  };
  IDS.bytesOf = function (str) {
    var out = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 255;
    return out;
  };

  // Rule-syntax text for a byte string: printable ASCII as-is, everything else in |hex| blocks.
  IDS.escapeContent = function (str) {
    var out = '', hex = false;
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i), plain = c >= 32 && c < 127 && '"\\;:|'.indexOf(str.charAt(i)) < 0;
      if (plain) { if (hex) { out += '|'; hex = false; } out += str.charAt(i); }
      else {
        if (!hex) { out += '|'; hex = true; } else out += ' ';
        out += (c < 16 ? '0' : '') + c.toString(16).toUpperCase();
      }
    }
    if (hex) out += '|';
    return out;
  };

  // Inverse of escapeContent: the text between the quotes of a content option.
  IDS.unescapeContent = function (text) {
    var out = '', i = 0, hex = false;
    while (i < text.length) {
      var ch = text.charAt(i);
      if (hex) {
        if (ch === '|') { hex = false; i++; continue; }
        if (/\s/.test(ch)) { i++; continue; }
        var h = text.substr(i, 2);
        if (!/^[0-9a-fA-F]{2}$/.test(h)) throw fail('Bad hex in content: ' + text);
        out += String.fromCharCode(parseInt(h, 16)); i += 2; continue;
      }
      if (ch === '|') { hex = true; i++; continue; }
      if (ch === '\\' && i + 1 < text.length) { out += text.charAt(i + 1); i += 2; continue; }
      out += ch; i++;
    }
    return out;
  };

  /* ================================================================ rule parsing */

  // Option names that select a buffer, mapped to one canonical name.
  var BUFFER_NAMES = {
    'http.uri': 'http.uri', 'http.uri.raw': 'http.uri.raw', 'http.method': 'http.method', 'http.request_line': 'http.request_line', 'http.header': 'http.header',
    'http.header.raw': 'http.header.raw', 'http.cookie': 'http.cookie', 'http.user_agent': 'http.user_agent', 'http.host': 'http.host', 'http.referer': 'http.referer',
    'http.content_type': 'http.content_type', 'http.request_body': 'http.request_body', 'http.client_body': 'http.request_body', 'http.stat_code': 'http.stat_code',
    'http.stat_msg': 'http.stat_msg', 'http.response_line': 'http.response_line', 'http.server': 'http.server', 'http.location': 'http.location',
    'http.response_body': 'http.response_body', 'file.data': 'http.response_body', 'file_data': 'http.response_body', 'pkt_data': 'raw', 'raw_data': 'raw'
  };
  var UNDERSCORE_BUFFERS = {
    'http_uri': 'http.uri', 'http_raw_uri': 'http.uri.raw', 'http_method': 'http.method', 'http_header': 'http.header', 'http_raw_header': 'http.header.raw',
    'http_cookie': 'http.cookie', 'http_raw_cookie': 'http.cookie', 'http_client_body': 'http.request_body', 'http_stat_code': 'http.stat_code',
    'http_stat_msg': 'http.stat_msg', 'http_user_agent': 'http.user_agent', 'http_host': 'http.host', 'http_raw_host': 'http.host', 'http_referer': 'http.referer',
    'http_content_type': 'http.content_type', 'http_server': 'http.server', 'http_location': 'http.location', 'http_request_line': 'http.request_line',
    'http_response_line': 'http.response_line'
  };
  var BUFFER_LABEL = {
    raw: 'the raw payload', 'http.uri': 'the HTTP URI', 'http.uri.raw': 'the raw HTTP URI', 'http.method': 'the HTTP method', 'http.request_line': 'the HTTP request line',
    'http.header': 'the HTTP headers', 'http.header.raw': 'the raw HTTP headers', 'http.cookie': 'the Cookie header', 'http.user_agent': 'the User-Agent header',
    'http.host': 'the Host header', 'http.referer': 'the Referer header', 'http.content_type': 'the Content-Type header', 'http.request_body': 'the HTTP request body',
    'http.stat_code': 'the HTTP status code', 'http.stat_msg': 'the HTTP status message', 'http.response_line': 'the HTTP response line', 'http.server': 'the Server header',
    'http.location': 'the Location header', 'http.response_body': 'the HTTP response body'
  };
  IDS.bufferLabel = function (b) { return BUFFER_LABEL[b] || b; };
  IDS.BUFFER_NAMES = BUFFER_NAMES;
  IDS.UNDERSCORE_BUFFERS = UNDERSCORE_BUFFERS;

  var PCRE_BUFFER_FLAGS = { U: 'http.uri', I: 'http.uri.raw', P: 'http.request_body', H: 'http.header', D: 'http.header.raw', M: 'http.method', C: 'http.cookie', K: 'http.cookie', S: 'http.stat_code', Y: 'http.stat_msg', V: 'http.user_agent', W: 'http.host' };
  var UNSUPPORTED_KEYS = { byte_test: 1, byte_jump: 1, byte_extract: 1, byte_math: 1, stream_size: 1, tcp_state: 1, 'stream-event': 1, 'decode-event': 1, 'ssl_state': 1, 'tls.sni': 1, 'tls.cert_subject': 1,
    'dns.query': 1, 'dns_query': 1, 'ja3.hash': 1, 'ja3s.hash': 1, filemagic: 1, filemd5: 1, filesha256: 1, filename: 1, fileext: 1, lua: 1, luajit: 1, base64_decode: 1, base64_data: 1, 'http.accept': 1,
    'http.start': 1, 'http.protocol': 1, 'http.header_names': 1, 'http.connection': 1, 'http.accept_enc': 1, 'http.accept_lang': 1, 'http.content_len': 1, 'http.request_header': 1, 'http.response_header': 1,
    flags: 1, seq: 1, ack: 1, window: 1, ttl: 1, id: 1, ipopts: 1, fragbits: 1, tos: 1, itype: 1, icode: 1, icmp_id: 1, icmp_seq: 1, sameip: 1, geoip: 1, ip_proto: 1, 'tcp.flags': 1, 'tcp.seq': 1, 'tcp.ack': 1, 'tcp.window': 1,
    'ip.ttl': 1, 'ip.id': 1, 'ip.tos': 1, 'icmpv4.type': 1, 'icmpv4.code': 1, 'ssh.proto': 1, 'ssh.software': 1, 'smb.named_pipe': 1, 'rfb.secresult': 1, 'dce_iface': 1, 'dce_opnum': 1, 'dce_stub_data': 1,
    'flowint': 1, 'xbits': 1, 'iprep': 1, 'hostbits': 1, 'ftpbounce': 1, 'asn1': 1, 'cvs': 1, 'rpc': 1 };

  // Text of rules to individual rule strings (joins lines ending in a backslash, drops comments and blanks).
  IDS.splitRules = function (text) {
    var lines = String(text).replace(/\r\n?/g, '\n').split('\n'), out = [], cur = '';
    lines.forEach(function (l) {
      if (cur) { cur += l.replace(/^\s+/, ''); }
      else if (/^\s*(#|$)/.test(l)) return;
      else cur = l;
      if (/\\\s*$/.test(cur)) { cur = cur.replace(/\\\s*$/, ''); return; }
      out.push(cur.trim()); cur = '';
    });
    if (cur.trim()) out.push(cur.trim());
    return out;
  };

  function tokenizeHeader(h) {
    var tokens = [], cur = '', depth = 0;
    for (var i = 0; i < h.length; i++) {
      var ch = h.charAt(i);
      if (ch === '[') depth++;
      if (ch === ']') depth--;
      if (/\s/.test(ch) && depth <= 0) { if (cur) tokens.push(cur); cur = ''; } else cur += ch;
    }
    if (cur) tokens.push(cur);
    return tokens;
  }

  // Split an option string on ';', ignoring semicolons inside quotes or escaped.
  function splitOptions(s) {
    var out = [], cur = '', inq = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (ch === '\\') { cur += ch + (s.charAt(i + 1) || ''); i++; continue; }
      if (ch === '"') inq = !inq;
      if (ch === ';' && !inq) { if (cur.trim()) out.push(cur.trim()); cur = ''; } else cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out;
  }

  function toInt(v) {
    var s = String(v == null ? '' : v).trim();
    return /^-?\d+$/.test(s) ? parseInt(s, 10) : null;
  }

  function parseCompare(v) {
    var m = /^\s*(!?)\s*(?:(\d+)\s*<>\s*(\d+)|([<>]=?|=)?\s*(\d+))\s*$/.exec(String(v));
    if (!m) return null;
    if (m[2] !== undefined) return { op: '<>', a: +m[2], b: +m[3], not: false };
    return { op: m[4] || (m[1] ? '!=' : '='), a: +m[5], not: !!m[1] && !m[4] };
  }
  function compare(c, n) {
    var r;
    if (c.op === '<>') r = n > c.a && n < c.b;
    else if (c.op === '<') r = n < c.a; else if (c.op === '>') r = n > c.a;
    else if (c.op === '<=') r = n <= c.a; else if (c.op === '>=') r = n >= c.a; else r = n === c.a;
    return c.not ? !r : r;
  }

  // Rewrite the PCRE-only syntax JavaScript lacks: \A \z \Z \h \R, atomic groups, possessive quantifiers, (?P<name>).
  // Walks the pattern so escaped characters and character classes are left alone.
  function translatePcre(p) {
    var out = '', i = 0, inClass = false;
    while (i < p.length) {
      var ch = p.charAt(i);
      if (ch === '\\' && i + 1 < p.length) {
        var n = p.charAt(i + 1);
        if (!inClass && n === 'A') out += '^';
        else if (!inClass && (n === 'z' || n === 'Z')) out += '$';
        else if (n === 'h') out += inClass ? ' \\t' : '[ \\t]';
        else if (!inClass && n === 'R') out += '(?:\\r\\n|\\n|\\r)';
        else out += ch + n;
        i += 2; continue;
      }
      if (inClass) { if (ch === ']') inClass = false; out += ch; i++; continue; }
      if (ch === '[') { inClass = true; out += ch; i++; if (p.charAt(i) === '^') { out += '^'; i++; } if (p.charAt(i) === ']') { out += '\\]'; i++; } continue; }
      if (ch === '(' && p.substr(i, 3) === '(?>') { out += '(?:'; i += 3; continue; }
      if (ch === '(' && p.substr(i, 4) === '(?P<') { out += '(?<'; i += 4; continue; }
      if (ch === '+' && i > 0 && /[*+?}]/.test(p.charAt(i - 1)) && !/\\$/.test(out.slice(0, -1) + '') && isQuantifier(p, i - 1)) { i++; continue; }   // possessive: drop the extra +
      out += ch; i++;
    }
    return out;
  }
  // True when the character at index q is a quantifier (not escaped and not inside a class).
  function isQuantifier(p, q) {
    var bs = 0, j = q - 1;
    while (j >= 0 && p.charAt(j) === '\\') { bs++; j--; }
    return bs % 2 === 0;
  }

  // PCRE to a JavaScript regular expression over a one-character-per-byte string.
  IDS.compilePcre = function (src, flagText) {
    var out = { src: src, flags: flagText || '', re: null, error: '', anchored: false, relative: false, buffer: null, unsupported: false };
    var jsFlags = '', pattern = src, i;
    for (i = 0; i < out.flags.length; i++) {
      var f = out.flags.charAt(i);
      if (f === 'i') jsFlags += 'i'; else if (f === 's') jsFlags += 's'; else if (f === 'm') jsFlags += 'm';
      else if (f === 'A') out.anchored = true; else if (f === 'R') out.relative = true;
      else if (PCRE_BUFFER_FLAGS[f]) out.buffer = PCRE_BUFFER_FLAGS[f];
      else if (f === 'x') pattern = pattern.replace(/\\#/g, '\u0001').replace(/#.*$/gm, '').replace(/\s+/g, '').replace(/\u0001/g, '\\#');
    }
    var lead = /^\(\?([ismx]+)\)/.exec(pattern);
    if (lead) { pattern = pattern.slice(lead[0].length); lead[1].split('').forEach(function (c) { if ('ism'.indexOf(c) >= 0 && jsFlags.indexOf(c) < 0) jsFlags += c; }); }
    pattern = translatePcre(pattern);
    try { out.re = new RegExp(pattern, jsFlags + (out.anchored ? 'y' : 'g')); } catch (e) { out.error = 'This pattern uses PCRE features the simulator cannot translate (' + e.message + ').'; out.unsupported = true; }
    return out;
  };

  // engine: 'suricata' | 'snort3' | 'snort2'. Throws a friendly error for a rule that cannot be read.
  IDS.parseRule = function (text, engine) {
    engine = engine || 'suricata';
    var raw = String(text).trim();
    var open = -1, depth = 0, i;
    for (i = 0; i < raw.length; i++) { var ch = raw.charAt(i); if (ch === '[') depth++; else if (ch === ']') depth--; else if (ch === '(' && depth <= 0) { open = i; break; } }
    var close = raw.lastIndexOf(')');
    if (open < 0 || close < open) throw fail('That does not look like a rule: no option list in parentheses was found.');
    var head = tokenizeHeader(raw.slice(0, open));
    var rule = { raw: raw, engine: engine, action: head[0] || 'alert', proto: lower(head[1]), src: 'any', sport: 'any', dir: '->', dst: 'any', dport: 'any', opts: [], contents: [], pcres: [], unsupported: [], sid: null, gid: 1, rev: null, msg: '', classtype: '', priority: null, flow: null, usesHttp: false, appLayer: null };
    if (head.length >= 7) { rule.src = head[2]; rule.sport = head[3]; rule.dir = head[4]; rule.dst = head[5]; rule.dport = head[6]; }
    else if (head.length === 2) rule.shortHeader = true;     // Snort 3 service rule such as: alert http (...)
    else throw fail('The rule header should read: action protocol source port -> destination port.');
    if (rule.dir !== '->' && rule.dir !== '<>') throw fail('The rule direction must be -> or <>.');

    var last = null, curBuf = 'raw', afterContent = false, opts = splitOptions(raw.slice(open + 1, close));
    opts.forEach(function (o) {
      var m = /^([A-Za-z_][A-Za-z0-9_.\-]*)\s*(?::\s*([\s\S]*))?$/.exec(o);
      if (!m) return;
      var key = m[1], val = m[2] === undefined ? '' : m[2].trim();
      var wasAfterContent = afterContent;
      afterContent = key === 'content' || (afterContent && /^(nocase|rawbytes|fast_pattern|startswith|endswith|offset|depth|distance|within)$/.test(key));
      if (key === 'content') {
        var neg = false, v = val;
        if (v.charAt(0) === '!') { neg = true; v = v.slice(1).trim(); }
        if (v.charAt(0) !== '"') throw fail('A content option must be in quotes: ' + o);
        // Find the closing quote (skipping escaped ones). Snort 3 writes modifiers after it, separated by commas.
        var qEnd = -1;
        for (var qi = 1; qi < v.length; qi++) { if (v.charAt(qi) === '\\') { qi++; continue; } if (v.charAt(qi) === '"') { qEnd = qi; break; } }
        if (qEnd < 0) throw fail('A content option must be in quotes: ' + o);
        var inline = v.slice(qEnd + 1).trim();
        var c = { type: 'content', neg: neg, str: IDS.unescapeContent(v.slice(1, qEnd)), nocase: false, offset: null, depth: null, distance: null, within: null, fast: false, fastOnly: false, startswith: false, endswith: false, buffer: curBuf, idx: rule.contents.length, varMods: [] };
        if (inline) {
          if (inline.charAt(0) !== ',') throw fail('Unexpected text after a content string: ' + o);
          inline.slice(1).split(',').forEach(function (tok) {
            tok = tok.trim();
            var mm = /^([a-z_]+)(?:[\s:]+(.+))?$/i.exec(tok);
            if (!mm) return;
            var mn = mm[1].toLowerCase(), ma = mm[2] === undefined ? '' : mm[2].trim();
            if (mn === 'nocase') c.nocase = true;
            else if (mn === 'fast_pattern') { c.fast = true; c.fastOnly = /only/.test(ma); c.fastArgs = ma; }
            else if (mn === 'startswith') c.startswith = true;
            else if (mn === 'endswith') c.endswith = true;
            else if (mn === 'offset' || mn === 'depth' || mn === 'distance' || mn === 'within') { var nn = toInt(ma); if (nn === null) c.varMods.push(mn + ' ' + ma); else c[mn] = nn; }
          });
          c.inlineStyle = true;
        }
        rule.contents.push(c); rule.opts.push(c); last = c;
      } else if (key === 'nocase') { if (last) last.nocase = true; }
      else if (key === 'rawbytes') { /* ignored */ }
      else if (key === 'fast_pattern') { if (last) { last.fast = true; last.fastOnly = /only/.test(val); last.fastArgs = val; } }
      else if (key === 'startswith') { if (last) last.startswith = true; }
      else if (key === 'endswith') { if (last) last.endswith = true; }
      else if (key === 'offset' || key === 'depth' || key === 'distance' || key === 'within') {
        if (!last) return;
        var n = toInt(val);
        if (n === null) last.varMods.push(key + ':' + val); else last[key] = n;
      }
      else if (UNDERSCORE_BUFFERS[key] && engine !== 'snort3' && wasAfterContent && last) {
        // Snort 2 and Suricata legacy style: a content modifier that applies to the content just before it.
        last.buffer = UNDERSCORE_BUFFERS[key]; last.legacy = key; rule.usesHttp = true;
        afterContent = true;
      }
      else if (BUFFER_NAMES[key] || UNDERSCORE_BUFFERS[key]) {
        // A sticky buffer: the contents that follow look in this buffer.
        var canon = BUFFER_NAMES[key] || UNDERSCORE_BUFFERS[key];
        curBuf = canon; rule.opts.push({ type: 'sticky', name: canon, original: key });
        if (/^http/.test(canon)) rule.usesHttp = true;
      }
      else if (key === 'pcre') {
        var pneg = false, pv = val;
        if (pv.charAt(0) === '!') { pneg = true; pv = pv.slice(1).trim(); }
        if (pv.charAt(0) !== '"' || pv.charAt(pv.length - 1) !== '"') throw fail('A pcre option must be in quotes: ' + o);
        pv = pv.slice(1, -1);
        var mm = /^\/([\s\S]*)\/([A-Za-z]*)$/.exec(pv);
        if (!mm) throw fail('A pcre option must look like "/pattern/flags": ' + o);
        var p = IDS.compilePcre(mm[1], mm[2]);
        p.type = 'pcre'; p.neg = pneg; p.buffer = p.buffer || curBuf; p.idx = rule.pcres.length;
        if (/^http/.test(p.buffer)) rule.usesHttp = true;
        rule.pcres.push(p); rule.opts.push(p);
      }
      else if (key === 'flow') {
        var fl = { toServer: false, toClient: false, established: null, text: val };
        val.split(',').map(function (s) { return s.trim().toLowerCase(); }).forEach(function (s) {
          if (s === 'to_server' || s === 'from_client') fl.toServer = true;
          else if (s === 'to_client' || s === 'from_server') fl.toClient = true;
          else if (s === 'established') fl.established = true;
          else if (s === 'not_established') fl.established = false;
        });
        rule.flow = fl; rule.opts.push({ type: 'flow', value: val });
      }
      else if (key === 'dsize') { var d = parseCompare(val); rule.opts.push({ type: 'dsize', value: val, cmp: d }); if (!d) rule.unsupported.push('dsize'); }
      else if (key === 'bsize') { var b = parseCompare(val); rule.opts.push({ type: 'bsize', value: val, cmp: b, buffer: curBuf }); if (!b) rule.unsupported.push('bsize'); }
      else if (key === 'urilen') {
        var ul = parseCompare(val.replace(/,.*$/, '')); rule.opts.push({ type: 'urilen', value: val, cmp: ul }); rule.usesHttp = true; if (!ul) rule.unsupported.push('urilen');
      }
      else if (key === 'isdataat') {
        var im = /^(!?)\s*(\d+)\s*(?:,\s*(relative))?/i.exec(val);
        rule.opts.push({ type: 'isdataat', value: val, not: im ? !!im[1] : false, n: im ? +im[2] : 0, relative: !!(im && im[3]), buffer: curBuf, ok: !!im });
        if (!im) rule.unsupported.push('isdataat');
      }
      else if (key === 'app-layer-protocol') { rule.appLayer = val.replace(/^!/, '').trim().toLowerCase(); rule.opts.push({ type: 'raw', key: key, value: val }); if (rule.appLayer === 'http' || rule.appLayer === 'http1') rule.usesHttp = true; }
      else if (key === 'sid') { rule.sid = toInt(val); rule.opts.push({ type: 'raw', key: key, value: val }); }
      else if (key === 'gid') { rule.gid = toInt(val) || 1; rule.opts.push({ type: 'raw', key: key, value: val }); }
      else if (key === 'rev') { rule.rev = toInt(val); rule.opts.push({ type: 'raw', key: key, value: val }); }
      else if (key === 'priority') { rule.priority = toInt(val); rule.opts.push({ type: 'raw', key: key, value: val }); }
      else if (key === 'msg') { rule.msg = val.replace(/^"|"$/g, ''); rule.opts.push({ type: 'raw', key: key, value: val }); }
      else if (key === 'classtype') { rule.classtype = val; rule.opts.push({ type: 'raw', key: key, value: val }); }
      else {
        if (UNSUPPORTED_KEYS[key] && rule.unsupported.indexOf(key) < 0) rule.unsupported.push(key);
        if ((key === 'threshold' || key === 'detection_filter' || key === 'event_filter' || key === 'ratelimit') ) rule.thresholdOpt = { key: key, value: val };
        if (key === 'flowbits' && /^isset|^isnotset/i.test(val) && rule.unsupported.indexOf('flowbits') < 0) rule.unsupported.push('flowbits');
        rule.opts.push({ type: 'raw', key: key, value: val });
      }
    });
    if (!rule.contents.length && !rule.pcres.length) rule.noContent = true;
    return rule;
  };

  // Rules from a block of text. Returns [{ ok, rule, error, raw }].
  IDS.parseRules = function (text, engine) {
    return IDS.splitRules(text).map(function (r) {
      try { return { ok: true, rule: IDS.parseRule(r, engine), raw: r }; }
      catch (e) { return { ok: false, error: e.userMessage || e.message, raw: r }; }
    });
  };

  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }

  /* ================================================================ HTTP */

  function decodeChunked(s, start) {
    var out = '', pos = start, guard = 0;
    while (pos < s.length && guard++ < 10000) {
      var eol = s.indexOf('\r\n', pos);
      if (eol < 0) break;
      var size = parseInt(s.slice(pos, eol).split(';')[0], 16);
      if (isNaN(size)) break;
      pos = eol + 2;
      if (size === 0) { pos = s.indexOf('\r\n\r\n', pos - 2) >= 0 ? s.indexOf('\r\n\r\n', pos - 2) + 4 : s.length; break; }
      out += s.substr(pos, size); pos += size + 2;
    }
    return { body: out, end: Math.min(pos, s.length) };
  }

  function pctDecode(s) { return s.replace(/%([0-9a-fA-F]{2})/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); }); }

  // Parse HTTP/1.x in one direction. s is the stream as a one-character-per-byte string.
  IDS.parseHttp = function (dir, s) {
    var txs = [], pos = 0, isReq = dir === 'toServer';
    var first = s.slice(0, 16);
    var looks = isReq ? /^[A-Z]{3,10} \S+/.test(s.slice(0, 40)) && /^[A-Z]{3,10} \S+ HTTP\/1\.[01]\r?\n/.test(s.slice(0, 2000)) : /^HTTP\/1\.[01] \d{3}/.test(first);
    if (!looks) return { isHttp: false, txs: [] };
    var guard = 0;
    while (pos < s.length && guard++ < 500) {
      var hEnd = s.indexOf('\r\n\r\n', pos), sep = 4;
      if (hEnd < 0) { hEnd = s.indexOf('\n\n', pos); sep = 2; }
      var block = hEnd < 0 ? s.slice(pos) : s.slice(pos, hEnd + sep);
      var lineEnd = block.search(/\r?\n/);
      var line = lineEnd < 0 ? block : block.slice(0, lineEnd);
      if (isReq ? !/^[A-Z]{3,10} \S+/.test(line) : !/^HTTP\/1\.[01] \d{3}/.test(line)) break;
      var headerStart = lineEnd < 0 ? block.length : lineEnd + (block.charAt(lineEnd) === '\r' ? 2 : 1);
      var headerText = block.slice(headerStart);
      var headers = [];
      headerText.split(/\r?\n/).forEach(function (h) { var i = h.indexOf(':'); if (i > 0) headers.push([h.slice(0, i).trim(), h.slice(i + 1).trim()]); });
      function hv(name) { var out = headers.filter(function (h) { return lower(h[0]) === name; }).map(function (h) { return h[1]; }); return out.length ? out.join(', ') : null; }
      var tx = { kind: isReq ? 'request' : 'response', start: pos, requestLine: line, headers: headers, headerText: headerText, host: hv('host'), userAgent: hv('user-agent'), cookie: hv('cookie'), referer: hv('referer'), contentType: hv('content-type'),
        server: hv('server'), location: hv('location'), body: '', bodyStart: hEnd < 0 ? s.length : hEnd + sep };
      if (isReq) {
        var rm = /^([A-Z]{3,10}) (\S+)(?: (HTTP\/[\d.]+))?/.exec(line);
        tx.method = rm[1]; tx.uri = rm[2]; tx.version = rm[3] || '';
      } else {
        var sm = /^(HTTP\/[\d.]+) (\d{3})\s*(.*)$/.exec(line);
        tx.version = sm[1]; tx.statCode = sm[2]; tx.statMsg = sm[3] || '';
      }
      var bodyStart = tx.bodyStart, end = bodyStart;
      var cl = hv('content-length'), te = lower(hv('transfer-encoding') || '');
      if (hEnd >= 0) {
        if (te.indexOf('chunked') >= 0) { var ch = decodeChunked(s, bodyStart); tx.body = ch.body; end = ch.end; }
        else if (cl !== null && /^\d+$/.test(cl)) { tx.body = s.substr(bodyStart, +cl); end = Math.min(s.length, bodyStart + +cl); }
        else if (!isReq && !/^(1\d\d|204|304)$/.test(tx.statCode || '')) { tx.body = s.slice(bodyStart); end = s.length; }
      } else end = s.length;
      tx.end = end;
      txs.push(tx);
      if (end <= pos) break;
      pos = end;
    }
    return { isHttp: txs.length > 0, txs: txs };
  };

  // The buffers a rule can address inside one HTTP transaction.
  function httpBuffers(tx) {
    var m = {};
    if (tx.kind === 'request') {
      var q = tx.uri || '';
      m['http.uri'] = pctDecode(q); m['http.uri.raw'] = q; m['http.method'] = tx.method || ''; m['http.request_line'] = tx.requestLine;
      m['http.request_body'] = tx.body; m['http.user_agent'] = tx.userAgent || ''; m['http.host'] = tx.host || ''; m['http.cookie'] = tx.cookie || '';
      m['http.referer'] = tx.referer || ''; m['http.content_type'] = tx.contentType || '';
    } else {
      m['http.stat_code'] = tx.statCode || ''; m['http.stat_msg'] = tx.statMsg || ''; m['http.response_line'] = tx.requestLine; m['http.response_body'] = tx.body;
      m['http.server'] = tx.server || ''; m['http.location'] = tx.location || ''; m['http.content_type'] = tx.contentType || '';
    }
    m['http.header'] = tx.headerText; m['http.header.raw'] = tx.headerText;
    return m;
  }

  /* ================================================================ header (addresses and ports) */

  function ipMatchesCidr(ip, spec) {
    if (spec.indexOf('/') < 0) return ip === spec || (SK.net && ip.indexOf(':') >= 0 && spec.indexOf(':') >= 0 && SK.net.parseIPv6(ip) === SK.net.parseIPv6(spec));
    if (!SK.net) return false;
    if (spec.indexOf(':') >= 0) {
      var m = /^(.+)\/(\d+)$/.exec(spec), a = SK.net.parseIPv6(ip), b = m && SK.net.parseIPv6(m[1]);
      if (a === null || b === null || b === undefined) return false;
      var shift = BigInt(128 - +m[2]);
      return (a >> shift) === (b >> shift);
    }
    return ip.indexOf(':') < 0 && SK.net.inCIDR4(ip, spec) === true;
  }

  function parseList(spec) {
    spec = String(spec).trim();
    if (spec.charAt(0) === '[' && spec.charAt(spec.length - 1) === ']') spec = spec.slice(1, -1);
    var out = [], cur = '', depth = 0;
    for (var i = 0; i < spec.length; i++) {
      var ch = spec.charAt(i);
      if (ch === '[') depth++; if (ch === ']') depth--;
      if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; } else cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out;
  }

  // vars: { HOME_NET: '10.0.0.0/8,192.168.0.0/16', ... }. An unset variable matches anything.
  function matchAddr(spec, ip, vars) {
    spec = String(spec).trim();
    if (!spec || spec === 'any') return true;
    var neg = false;
    if (spec.charAt(0) === '!') { neg = true; spec = spec.slice(1).trim(); }
    var items = parseList(spec), hit = false, unknown = false;
    items.forEach(function (it) {
      var itNeg = false;
      if (it.charAt(0) === '!') { itNeg = true; it = it.slice(1); }
      var r;
      if (it.charAt(0) === '$') {
        var v = vars && vars[it.slice(1)];
        if (!v) { unknown = true; r = true; } else r = matchAddr(v, ip, vars);
      } else if (it === 'any') r = true;
      else r = ipMatchesCidr(ip, it);
      if (itNeg ? !r : r) hit = true;
    });
    if (!items.length) hit = true;
    return neg ? !hit : (hit || unknown);
  }

  function matchPort(spec, port, vars) {
    spec = String(spec).trim();
    if (!spec || spec === 'any') return true;
    var neg = false;
    if (spec.charAt(0) === '!') { neg = true; spec = spec.slice(1).trim(); }
    var items = parseList(spec), hit = false;
    items.forEach(function (it) {
      var itNeg = false, r = false;
      if (it.charAt(0) === '!') { itNeg = true; it = it.slice(1); }
      if (it.charAt(0) === '$') { var v = vars && vars[it.slice(1)]; r = v ? matchPort(v, port, vars) : true; }
      else if (it === 'any') r = true;
      else {
        var m = /^(\d*)(:?)(\d*)$/.exec(it);
        if (m) {
          if (!m[2]) r = port === +m[1];
          else r = port >= (m[1] === '' ? 0 : +m[1]) && port <= (m[3] === '' ? 65535 : +m[3]);
        }
      }
      if (itNeg ? !r : r) hit = true;
    });
    return neg ? !hit : hit;
  }
  IDS.matchAddr = matchAddr;
  IDS.matchPort = matchPort;

  /* ================================================================ matching */

  function Buf(str) { this.str = str; this._lower = null; }
  Buf.prototype.lower = function () { if (this._lower === null) this._lower = this.str.toLowerCase(); return this._lower; };

  // Search window for a content, following Suricata's inspection code.
  function window_(c, buf, prev) {
    var len = buf.str.length, start, end;
    var relative = c.distance !== null || c.within !== null;
    var cLen = c.str.length;
    if (c.startswith) { start = 0; end = Math.min(len, cLen); return { start: 0, end: end }; }
    if (!relative) {
      start = c.offset !== null ? c.offset : 0;
      end = c.depth !== null ? start + c.depth : len;
    } else {
      var dist = c.distance !== null ? c.distance : 0;
      start = prev + dist; if (start < 0) start = 0;
      end = c.within !== null ? prev + dist + c.within : len;
      if (c.offset !== null && c.offset > start) start = c.offset;
      if (c.depth !== null && prev + c.depth < end) end = prev + c.depth;
    }
    if (end > len) end = len;
    return { start: start, end: end };
  }

  // All occurrences of a content inside its window (start offsets), up to a limit.
  function occurrences(c, buf, win, limit) {
    var out = [], hay = c.nocase ? buf.lower() : buf.str, needle = c.nocase ? c.str.toLowerCase() : c.str;
    if (!needle.length) return [win.start];
    var from = win.start;
    while (out.length < limit) {
      var i = hay.indexOf(needle, from);
      if (i < 0 || i + needle.length > win.end) break;
      out.push(i);
      from = i + 1;
    }
    return out;
  }

  function sessionSides(session, dir) {
    return dir === 'toServer' ? { src: session.client, dst: session.server } : { src: session.server, dst: session.client };
  }

  function protoOk(rule, session, unit) {
    var p = rule.proto;
    if (!p || p === 'ip') return true;
    if (p === 'tcp') return session.proto === 'tcp';
    if (p === 'udp') return session.proto === 'udp';
    if (p === 'icmp' || p === 'icmpv4' || p === 'icmpv6') return session.proto === 'icmp';
    if (p === 'http' || p === 'http1') return session.proto === 'tcp';
    return session.proto === 'tcp' || session.proto === 'udp';
  }

  function headerOk(rule, session, dir, vars) {
    var s = sessionSides(session, dir), r = null;
    if (matchAddr(rule.src, s.src.ip, vars) && matchPort(rule.sport, s.src.port, vars) && matchAddr(rule.dst, s.dst.ip, vars) && matchPort(rule.dport, s.dst.port, vars)) r = true;
    else if (rule.dir === '<>' && matchAddr(rule.src, s.dst.ip, vars) && matchPort(rule.sport, s.dst.port, vars) && matchAddr(rule.dst, s.src.ip, vars) && matchPort(rule.dport, s.src.port, vars)) r = true;
    return !!r;
  }

  // The things a rule is checked against: one per direction of a TCP session, or one per datagram.
  IDS.unitsOf = function (session) {
    var units = [];
    if (session.proto === 'tcp') {
      ['toServer', 'toClient'].forEach(function (dir) {
        var d = session.dirs[dir];
        if (!d || !d.data.length) return;
        if (!d._str) { d._str = IDS.bin(d.data); d._http = IDS.parseHttp(dir, d._str); }
        units.push({ session: session, dir: dir, kind: 'stream', str: d._str, segs: d.segs, http: d._http, sizes: d.segs.map(function (s) { return s.len; }) });
      });
    } else {
      session.datagrams.forEach(function (g, i) {
        if (!g._str) g._str = IDS.bin(g.data);
        units.push({ session: session, dir: g.dir, kind: 'dgram', str: g._str, segs: [{ start: 0, len: g.data.length, ts: g.ts, pkt: g.pkt }], http: { isHttp: false, txs: [] }, sizes: [g.data.length], index: i, icmp: g.icmp });
      });
    }
    return units;
  };

  function bufferOf(map, name, unit) {
    if (name === 'raw') return map.raw || (map.raw = new Buf(unit.str));
    var s = map.http && map.http[name];
    if (s === undefined) return null;
    var key = '_b_' + name;
    return map[key] || (map[key] = new Buf(s));
  }

  // Walk the options in order; contents and pcres can match more than once, so later failures retry earlier choices.
  function evalOptions(rule, unit, httpMap, ctx) {
    var budget = { n: STEP_BUDGET }, deepest = { i: -1, reason: '' }, approx = {};
    var map = { http: httpMap };
    var result = null;

    function fillCursor(cur, name) { return cur[name] === undefined ? 0 : cur[name]; }

    function step(i, cur, matches, bufName) {
      if (budget.n-- <= 0) { deepest.reason = 'The rule was too complex to evaluate fully.'; return null; }
      if (i > deepest.i) { deepest.i = i; deepest.reason = ''; }
      if (i >= rule.opts.length) return matches;
      var o = rule.opts[i];
      function note(reason) { if (i >= deepest.i) deepest.reason = reason; }
      switch (o.type) {
        case 'sticky': return step(i + 1, cur, matches, o.name);
        case 'content': {
          var buf = bufferOf(map, o.buffer, unit);
          if (!buf) { note('The rule looks in ' + IDS.bufferLabel(o.buffer) + ', which this traffic does not have.'); return null; }
          var prev = fillCursor(cur, o.buffer), win = window_(o, buf, prev);
          if (o.neg) {
            var found = win.start <= win.end ? occurrences(o, buf, win, 1) : [];
            if (found.length) { note('The negated content ' + describeContent(o) + ' was present, so the rule does not fire.'); return null; }
            return step(i + 1, cur, matches, bufName);
          }
          if (win.start > win.end) { note('The search window for ' + describeContent(o) + ' is empty.'); return null; }
          var occ = occurrences(o, buf, win, 24);
          if (o.endswith) occ = occ.filter(function (p) { return p + o.str.length === buf.str.length; });
          if (!occ.length) { note('Content ' + describeContent(o) + ' was not found in ' + IDS.bufferLabel(o.buffer) + (o.offset !== null || o.depth !== null || o.distance !== null || o.within !== null ? ' within its offset/depth/distance/within window (bytes ' + win.start + ' to ' + win.end + ')' : '') + '.'); return null; }
          for (var k = 0; k < occ.length; k++) {
            var nc = {}; for (var key in cur) nc[key] = cur[key];
            nc[o.buffer] = occ[k] + o.str.length;
            var r = step(i + 1, nc, matches.concat([{ opt: i, kind: 'content', idx: o.idx, buffer: o.buffer, start: occ[k], end: occ[k] + o.str.length, bufLen: buf.str.length, prevEnd: prev }]), bufName);
            if (r) return r;
          }
          return null;
        }
        case 'pcre': {
          if (o.unsupported) { approx.pcre = true; return step(i + 1, cur, matches, bufName); }
          var pb = bufferOf(map, o.buffer, unit);
          if (!pb) { note('The pcre looks in ' + IDS.bufferLabel(o.buffer) + ', which this traffic does not have.'); return null; }
          // With the R flag the pattern runs on the data after the previous match, so ^ anchors there.
          var pstart = o.relative ? fillCursor(cur, o.buffer) : 0;
          o.re.lastIndex = 0;
          var m = o.re.exec(pstart ? pb.str.slice(pstart) : pb.str);
          if (m && pstart) m.index += pstart;
          if (o.neg) { if (m) { note('The negated pcre matched, so the rule does not fire.'); return null; } return step(i + 1, cur, matches, bufName); }
          if (!m) { note('The pcre /' + o.src.slice(0, 60) + '/ did not match in ' + IDS.bufferLabel(o.buffer) + '.'); return null; }
          var nc2 = {}; for (var k2 in cur) nc2[k2] = cur[k2];
          nc2[o.buffer] = m.index + m[0].length;
          return step(i + 1, nc2, matches.concat([{ opt: i, kind: 'pcre', idx: o.idx, buffer: o.buffer, start: m.index, end: m.index + m[0].length, bufLen: pb.str.length }]), bufName);
        }
        case 'isdataat': {
          if (!o.ok) { approx.isdataat = true; return step(i + 1, cur, matches, bufName); }
          var ib = bufferOf(map, o.buffer, unit) || bufferOf(map, bufName, unit);
          if (!ib) return step(i + 1, cur, matches, bufName);
          var len = ib.str.length, ok = o.relative ? fillCursor(cur, o.buffer) + o.n <= len : o.n < len;
          if (o.not) ok = !ok;
          if (!ok) { note('isdataat:' + o.value + ' is not satisfied: the buffer has ' + len + ' bytes.'); return null; }
          return step(i + 1, cur, matches, bufName);
        }
        case 'dsize': {
          if (!o.cmp) return step(i + 1, cur, matches, bufName);
          var okd = unit.sizes.some(function (n) { return compare(o.cmp, n); });
          if (!okd) { note('dsize:' + o.value + ' is not satisfied: packet payloads here are ' + unit.sizes.slice(0, 6).join(', ') + ' bytes.'); return null; }
          approx.dsize = true;
          return step(i + 1, cur, matches, bufName);
        }
        case 'bsize': {
          var bb = bufferOf(map, o.buffer, unit);
          if (bb && o.cmp && !compare(o.cmp, bb.str.length)) { note('bsize:' + o.value + ' is not satisfied: the buffer has ' + bb.str.length + ' bytes.'); return null; }
          return step(i + 1, cur, matches, bufName);
        }
        case 'urilen': {
          var ub = bufferOf(map, 'http.uri.raw', unit);
          if (ub && o.cmp && !compare(o.cmp, ub.str.length)) { note('urilen:' + o.value + ' is not satisfied: the URI has ' + ub.str.length + ' bytes.'); return null; }
          return step(i + 1, cur, matches, bufName);
        }
        case 'raw': {
          if (UNSUPPORTED_KEYS[o.key] || (o.key === 'flowbits' && /isset|isnotset/i.test(o.value))) approx[o.key] = true;
          return step(i + 1, cur, matches, bufName);
        }
        default: return step(i + 1, cur, matches, bufName);
      }
    }
    var matches = step(0, {}, [], 'raw');
    return { ok: !!matches, matches: matches || [], approx: Object.keys(approx), reason: deepest.reason, deepest: deepest.i };
  }

  function describeContent(c) { return '"' + IDS.escapeContent(c.str).slice(0, 40) + '"'; }
  IDS.describeContent = describeContent;

  // Evaluate a rule against one unit. Returns { alerts: [{ unit, matches, approx, tx }], reason }.
  function evalUnit(rule, unit, ctx) {
    var session = unit.session, vars = ctx && ctx.vars;
    if (!protoOk(rule, session, unit)) return { alerts: [], reason: 'The rule is for ' + rule.proto + ' but this is ' + session.proto + ' traffic.' };
    if (!headerOk(rule, session, unit.dir, vars)) return { alerts: [], reason: 'The addresses or ports in the rule header do not match this traffic.' };
    var fl = rule.flow;
    if (fl) {
      if (fl.toServer && !fl.toClient && unit.dir !== 'toServer') return { alerts: [], reason: 'The rule says flow:' + fl.text + ' but this data goes to the client.' };
      if (fl.toClient && !fl.toServer && unit.dir !== 'toClient') return { alerts: [], reason: 'The rule says flow:' + fl.text + ' but this data goes to the server.' };
      if (fl.established === true && session.proto === 'tcp' && !session.established) return { alerts: [], reason: 'The rule needs an established connection, but no handshake was seen.' };
      if (fl.established === false && session.established) return { alerts: [], reason: 'The rule is for connections that are not established.' };
    }
    var alerts = [], lastReason = '', approxAll = {};
    if (rule.usesHttp) {
      if (!unit.http.isHttp) return { alerts: [], reason: 'The rule needs HTTP, but this stream does not contain HTTP/1.x.' };
      unit.http.txs.forEach(function (tx) {
        if (alerts.length >= 20) return;
        var r = evalOptions(rule, unit, httpBuffers(tx), ctx);
        if (r.ok) alerts.push({ unit: unit, matches: r.matches, approx: r.approx, tx: tx }); else lastReason = r.reason || lastReason;
      });
    } else {
      var r = evalOptions(rule, unit, null, ctx);
      if (r.ok) alerts.push({ unit: unit, matches: r.matches, approx: r.approx, tx: null }); else lastReason = r.reason;
    }
    return { alerts: alerts, reason: lastReason };
  }

  // Run a rule over sessions. Returns { alerts, sessionsAlerted, approx: [..], reasons: { text: count } }.
  IDS.run = function (rule, sessions, ctx) {
    var alerts = [], reasons = {}, approx = {}, hitSessions = {};
    sessions.forEach(function (s) {
      var any = false, best = '';
      IDS.unitsOf(s).forEach(function (u) {
        var r = evalUnit(rule, u, ctx);
        r.alerts.forEach(function (a) { a.session = s; alerts.push(a); any = true; a.approx.forEach(function (k) { approx[k] = true; }); });
        if (!r.alerts.length && r.reason && r.reason.length > best.length) best = r.reason;
      });
      if (any) hitSessions[s.id] = true; else if (best) reasons[best] = (reasons[best] || 0) + 1;
    });
    return { alerts: alerts, sessionsAlerted: Object.keys(hitSessions).length, approx: Object.keys(approx), reasons: reasons };
  };

  IDS.parseCompare = parseCompare;
  IDS.compare = compare;
  IDS.unsupported = UNSUPPORTED_KEYS;
  IDS.httpBuffers = httpBuffers;
})();
