// Snort and Suricata tuning advice (SK.idsTune): rule rendering for each engine, alert parsing, evidence from a capture,
// and recommendations (offset, depth, distance, within, buffers, flow, ports, context strings, thresholds and more).
// Every recommendation is checked by running the changed rule over the same captures.
(function () {
  var SK = window.SK = window.SK || {};
  var IDS = SK.ids, T = SK.idsTune = {};

  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }

  /* ================================================================ rendering */

  var STICKY = {
    suricata: { 'http.uri': 'http.uri', 'http.uri.raw': 'http.uri.raw', 'http.method': 'http.method', 'http.request_line': 'http.request_line', 'http.header': 'http.header', 'http.header.raw': 'http.header.raw',
      'http.cookie': 'http.cookie', 'http.user_agent': 'http.user_agent', 'http.host': 'http.host', 'http.referer': 'http.referer', 'http.content_type': 'http.content_type',
      'http.request_body': 'http.request_body', 'http.stat_code': 'http.stat_code', 'http.stat_msg': 'http.stat_msg', 'http.response_line': 'http.response_line', 'http.server': 'http.server',
      'http.location': 'http.location', 'http.response_body': 'file.data', raw: 'pkt_data' },
    snort3: { 'http.uri': 'http_uri', 'http.uri.raw': 'http_raw_uri', 'http.method': 'http_method', 'http.header': 'http_header', 'http.header.raw': 'http_raw_header', 'http.cookie': 'http_cookie',
      'http.request_body': 'http_client_body', 'http.stat_code': 'http_stat_code', 'http.stat_msg': 'http_stat_msg', 'http.response_body': 'file_data', raw: 'pkt_data' },
    snort2: { 'http.uri': 'http_uri', 'http.uri.raw': 'http_raw_uri', 'http.method': 'http_method', 'http.header': 'http_header', 'http.header.raw': 'http_raw_header', 'http.cookie': 'http_cookie',
      'http.request_body': 'http_client_body', 'http.stat_code': 'http_stat_code', 'http.stat_msg': 'http_stat_msg', 'http.response_body': 'file_data', raw: null }
  };
  var HEADER_FALLBACK = { 'http.user_agent': 1, 'http.host': 1, 'http.referer': 1, 'http.content_type': 1, 'http.server': 1, 'http.location': 1, 'http.request_line': 1, 'http.response_line': 1 };

  function stickyName(buffer, engine, warnings) {
    var map = STICKY[engine] || STICKY.suricata;
    if (map[buffer] !== undefined) return map[buffer];
    if (HEADER_FALLBACK[buffer] && map['http.header']) {
      if (warnings && warnings.indexOf(buffer) < 0) warnings.push(buffer);
      return map['http.header'];
    }
    return map.raw;
  }

  function contentText(c) { return (c.neg ? '!' : '') + '"' + IDS.escapeContent(c.str) + '"'; }

  // Rule text for an engine. Returns { text, warnings }.
  T.renderRule = function (rule, engine) {
    engine = engine || rule.engine || 'suricata';
    var warnings = [], parts = [], curBuf = 'raw';
    var head = rule.shortHeader ? [rule.action, rule.proto].join(' ') : [rule.action, rule.proto, rule.src, rule.sport, rule.dir, rule.dst, rule.dport].join(' ');

    function needSticky(buffer) {
      if (engine === 'snort2' || buffer === curBuf) return;
      var name = stickyName(buffer, engine, warnings);
      if (name) { parts.push(name + ';'); curBuf = buffer; }
    }
    rule.opts.forEach(function (o) {
      switch (o.type) {
        case 'sticky': break;                                       // regenerated from the options that need them
        case 'content': {
          needSticky(o.buffer);
          var base = 'content:' + contentText(o), mods = [], extra = [];
          var startsDepth = o.startswith && engine !== 'suricata';
          if (o.nocase) mods.push(['nocase']);
          if (o.startswith && engine === 'suricata') mods.push(['startswith']);
          if (o.endswith) { if (engine === 'suricata') mods.push(['endswith']); else extra.push('isdataat:!1,relative;'); }
          if (startsDepth) { mods.push(['offset', 0]); mods.push(['depth', o.str.length]); }
          else {
            if (o.offset !== null) mods.push(['offset', o.offset]);
            if (o.depth !== null) mods.push(['depth', o.depth]);
          }
          if (o.distance !== null) mods.push(['distance', o.distance]);
          if (o.within !== null) mods.push(['within', o.within]);
          o.varMods.forEach(function (v) { var m = /^(\w+)[:\s]+(.+)$/.exec(v); if (m) mods.push([m[1], m[2]]); });
          if (o.fast) mods.push(['fast_pattern']);
          if (engine === 'snort3') {
            parts.push(base + mods.map(function (m) { return ',' + m[0] + (m.length > 1 ? ' ' + m[1] : ''); }).join('') + ';');
          } else {
            parts.push(base + ';');
            mods.forEach(function (m) { parts.push(m.length > 1 ? m[0] + ':' + m[1] + ';' : m[0] + ';'); });
          }
          if (engine === 'snort2' && o.buffer !== 'raw') {
            var legacy = stickyName(o.buffer, 'snort2', warnings);
            if (legacy) parts.push(legacy + ';');
          }
          extra.forEach(function (e) { parts.push(e); });
          break;
        }
        case 'pcre': {
          needSticky(o.buffer);
          parts.push('pcre:' + (o.neg ? '!' : '') + '"/' + o.src + '/' + o.flags + '";');
          break;
        }
        case 'isdataat': case 'bsize': needSticky(o.buffer || 'raw'); parts.push(o.type + ':' + o.value + ';'); break;
        case 'flow': parts.push('flow:' + o.value + ';'); break;
        case 'dsize': parts.push('dsize:' + o.value + ';'); break;
        case 'urilen': parts.push('urilen:' + o.value + ';'); break;
        case 'raw': parts.push(o.value === '' ? o.key + ';' : o.key + ':' + o.value + ';'); break;
        default: break;
      }
    });
    return { text: head + ' (' + parts.join(' ') + ')', warnings: warnings };
  };

  T.cloneRule = function (rule) {
    var copy = Object.assign({}, rule);
    copy.opts = []; copy.contents = [];
    rule.opts.forEach(function (o) {
      if (o.type === 'content') { var c = Object.assign({}, o, { varMods: o.varMods.slice() }); copy.opts.push(c); copy.contents.push(c); }
      else if (o.type === 'pcre') copy.opts.push(o);          // compiled patterns are never edited, so they are shared
      else copy.opts.push(Object.assign({}, o));
    });
    copy.flow = rule.flow ? Object.assign({}, rule.flow) : null;
    copy.unsupported = rule.unsupported.slice();
    return copy;
  };

  /* ================================================================ alerts */

  // hasPorts: the alert is for TCP or UDP. Logs print IPv6 as address:port without brackets, which is ambiguous;
  // for TCP and UDP the last group is taken as the port when what is left is still a valid address.
  function splitHostPort(s, hasPorts) {
    s = String(s || '').trim();
    if (!s) return { ip: '', port: null };
    var m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
    if (m) return { ip: m[1], port: m[2] ? +m[2] : null };
    if (SK.net && SK.net.parseIPv6(s) !== null) {
      var cut = s.lastIndexOf(':');
      if (hasPorts && cut > 0 && /^\d{1,5}$/.test(s.slice(cut + 1)) && +s.slice(cut + 1) <= 65535 && SK.net.parseIPv6(s.slice(0, cut)) !== null) return { ip: s.slice(0, cut), port: +s.slice(cut + 1) };
      return { ip: s, port: null };
    }
    var i = s.lastIndexOf(':');
    if (i > 0 && /^\d+$/.test(s.slice(i + 1)) && s.indexOf(':') === i) return { ip: s.slice(0, i), port: +s.slice(i + 1) };
    if (i > 0 && /^\d+$/.test(s.slice(i + 1)) && SK.net && SK.net.parseIPv6(s.slice(0, i)) !== null) return { ip: s.slice(0, i), port: +s.slice(i + 1) };
    return { ip: s, port: null };
  }

  // Reads a Suricata EVE JSON alert, a Suricata or Snort fast-log line, or returns { kind: 'unknown' }.
  T.parseAlert = function (text) {
    var t = String(text || '').trim();
    if (!t) return null;
    if (t.charAt(0) === '{') {
      var j = null;
      try { j = JSON.parse(t); } catch (e) { try { j = JSON.parse(t.split('\n')[0]); } catch (e2) { j = null; } }
      if (j) {
        var a = j.alert || {}, ts = j.timestamp ? Date.parse(String(j.timestamp).replace(/([+-]\d\d)(\d\d)$/, '$1:$2')) : NaN;
        return { kind: 'eve', sid: a.signature_id || null, gid: a.gid || 1, rev: a.rev || null, msg: a.signature || '', classification: a.category || '', priority: a.severity || null,
          proto: lower(j.proto), src: { ip: j.src_ip || '', port: j.src_port === undefined ? null : j.src_port }, dst: { ip: j.dest_ip || '', port: j.dest_port === undefined ? null : j.dest_port },
          tsMs: isNaN(ts) ? null : ts, tsText: j.timestamp || '', http: j.http || null, payloadB64: j.payload || null };
      }
    }
    var line = t.split('\n').filter(function (l) { return /\[\*\*\]/.test(l); })[0];
    if (line) {
      var m = /^\s*(\S+)?\s*\[\*\*\]\s*\[(\d+):(\d+):(\d+)\]\s*(.*?)\s*\[\*\*\](?:\s*\[Classification:\s*(.*?)\])?(?:\s*\[Priority:\s*(\d+)\])?\s*\{(\w+)\}\s*(\S+)\s*->\s*(\S+)/.exec(line);
      if (m) {
        var hasPorts = /^(tcp|udp|sctp)$/i.test(m[8]), s = splitHostPort(m[9], hasPorts), d = splitHostPort(m[10], hasPorts);
        return { kind: 'fast', sid: +m[3], gid: +m[2], rev: +m[4], msg: m[5], classification: m[6] || '', priority: m[7] ? +m[7] : null, proto: lower(m[8]), src: s, dst: d, tsMs: null, tsText: m[1] || '' };
      }
    }
    return { kind: 'unknown' };
  };

  // Which sessions in a capture the alert describes (same endpoints in either direction).
  T.findAlertSessions = function (sessions, alert) {
    if (!alert || alert.kind === 'unknown' || !alert.src.ip) return [];
    var out = sessions.filter(function (s) {
      if (alert.proto && alert.proto !== s.proto && !(alert.proto === 'tcp' && s.proto === 'tcp')) return false;
      function eq(a, b) { return a.ip === b.ip && (a.port === null || b.port === null || a.port === b.port || s.proto === 'icmp'); }
      return (eq(alert.src, s.client) && eq(alert.dst, s.server)) || (eq(alert.src, s.server) && eq(alert.dst, s.client));
    });
    if (alert.tsMs && out.length > 1) out.sort(function (a, b) { return Math.abs(a.start - alert.tsMs) - Math.abs(b.start - alert.tsMs); });
    return out;
  };

  /* ================================================================ evidence from alerts */

  function segAt(segs, off) {
    for (var i = 0; i < segs.length; i++) if (off >= segs[i].start && off < segs[i].start + segs[i].len) return segs[i];
    return segs.length ? segs[segs.length - 1] : null;
  }
  function txAt(unit, off) {
    var txs = unit.http && unit.http.txs || [];
    for (var i = 0; i < txs.length; i++) if (off >= txs[i].start && off < Math.max(txs[i].end, txs[i].start + 1)) return txs[i];
    return null;
  }
  function bufStr(alert, name) {
    if (name === 'raw') return alert.unit.str;
    return alert.tx ? (IDS.httpBuffers(alert.tx)[name] || '') : '';
  }
  // Time of an alert in ms: the packet that carried the end of its first match.
  T.alertTime = function (alert) {
    var off = alert.tx ? alert.tx.start : (alert.matches.length ? alert.matches[0].end - 1 : 0);
    var seg = segAt(alert.unit.segs, Math.max(0, off));
    return seg && seg.ts ? seg.ts : alert.session.start;
  };
  T.alertSource = function (alert) { return alert.unit.dir === 'toServer' ? alert.session.client.ip : alert.session.server.ip; };
  T.alertDest = function (alert) { return alert.unit.dir === 'toServer' ? alert.session.server.ip : alert.session.client.ip; };

  function printable(s, max) {
    var out = String(s).replace(/[^\x20-\x7e]/g, '·');
    return max && out.length > max ? out.slice(0, max) + '…' : out;
  }
  T.printable = printable;

  // A readable summary of one alert: where each part of the rule matched, with surrounding bytes.
  T.evidence = function (alert, rule) {
    var u = alert.unit, s = alert.session;
    var firstLine = alert.tx ? alert.tx.requestLine : '';
    var matches = alert.matches.map(function (m) {
      var str = bufStr(alert, m.buffer), CTX = 28;
      var lbl = m.kind === 'content' ? IDS.describeContent(rule.contents[m.idx]) : 'pcre /' + (rule.pcres[m.idx] ? rule.pcres[m.idx].src.slice(0, 40) : '') + '/';
      return { kind: m.kind, idx: m.idx, label: lbl, buffer: m.buffer, bufferLabel: IDS.bufferLabel(m.buffer), start: m.start, end: m.end, bufLen: m.bufLen, prevEnd: m.prevEnd,
        before: printable(str.slice(Math.max(0, m.start - CTX), m.start)), matched: printable(str.slice(m.start, m.end), 80), after: printable(str.slice(m.end, m.end + CTX)) };
    });
    return { session: s.id, dir: u.dir, client: s.client, server: s.server, proto: s.proto, time: T.alertTime(alert), line: printable(firstLine, 120), matches: matches, approx: alert.approx };
  };

  /* ================================================================ analysis helpers */

  function matchesFor(alerts, idx, kind) {
    var out = [];
    alerts.forEach(function (a) { a.matches.forEach(function (m) { if (m.kind === (kind || 'content') && m.idx === idx) out.push({ m: m, a: a }); }); });
    return out;
  }

  function stats(list) {
    if (!list.length) return null;
    return { min: Math.min.apply(null, list), max: Math.max.apply(null, list), n: list.length };
  }
  T.stats = stats;

  var BUFFER_PREFERENCE = ['http.uri', 'http.request_body', 'http.header', 'http.cookie', 'http.user_agent', 'http.host', 'http.method', 'http.referer', 'http.content_type',
    'http.stat_code', 'http.response_body', 'http.server', 'http.location', 'http.stat_msg'];

  // Which HTTP buffers contain the content in the traffic where it matched.
  function bufferCandidates(alerts, c) {
    var sets = [];
    alerts.forEach(function (a) {
      a.matches.forEach(function (m) {
        if (m.kind !== 'content' || m.idx !== c.idx || m.buffer !== 'raw') return;
        var tx = txAt(a.unit, m.start);
        if (!tx) { sets.push(null); return; }
        var bufs = IDS.httpBuffers(tx), found = [];
        Object.keys(bufs).forEach(function (name) {
          if (name === 'http.header.raw' || name === 'http.uri.raw' || name === 'http.request_line' || name === 'http.response_line') return;
          var hay = c.nocase ? bufs[name].toLowerCase() : bufs[name], needle = c.nocase ? c.str.toLowerCase() : c.str;
          if (hay.indexOf(needle) >= 0) found.push(name);
        });
        sets.push(found);
      });
    });
    if (!sets.length || sets.some(function (s) { return s === null; })) return [];
    var inter = sets[0].filter(function (n) { return sets.every(function (s) { return s.indexOf(n) >= 0; }); });
    function rank(n) { var i = BUFFER_PREFERENCE.indexOf(n); return i < 0 ? 99 : i; }
    inter.sort(function (a, b) { return rank(a) - rank(b); });
    return inter;
  }

  function flowText(dir, established) { return (dir === 'toServer' ? 'to_server' : 'to_client') + (established ? ',established' : ''); }

  function setFlow(rule, dir, established) {
    var text = flowText(dir, established);
    var existing = rule.opts.filter(function (o) { return o.type === 'flow'; })[0];
    if (existing) existing.value = text;
    else {
      var at = rule.opts.findIndex(function (o) { return o.type === 'content' || o.type === 'pcre' || o.type === 'sticky'; });
      rule.opts.splice(at < 0 ? rule.opts.length : at, 0, { type: 'flow', value: text });
    }
    rule.flow = { toServer: dir === 'toServer', toClient: dir === 'toClient', established: established ? true : null, text: text };
  }

  var REQUEST_BUFFERS = /^http\.(uri|uri\.raw|method|request_line|request_body|user_agent|host|cookie|referer)$/;
  var RESPONSE_BUFFERS = /^http\.(stat_code|stat_msg|response_line|response_body|server|location)$/;

  /* ================================================================ the analysis */

  function sessionIds(alerts) { var s = {}; alerts.forEach(function (a) { s[a.session.id] = true; }); return s; }
  function size(o) { return Object.keys(o).length; }

  // inp: { rule, engine, fp: capture, tp: capture|null, alert: parsed alert|null, vars }
  T.analyze = function (inp) {
    var rule = inp.rule, engine = inp.engine || rule.engine, ctx = { vars: inp.vars || {} };
    var fpSess = inp.fp.sessions, tpSess = inp.tp ? inp.tp.sessions : null;
    var out = { engine: engine, hasTp: !!tpSess, recs: [], others: [], notes: [], steps: [], combined: null };

    var fpRun = IDS.run(rule, fpSess, ctx), tpRun = tpSess ? IDS.run(rule, tpSess, ctx) : null;
    out.fp = { alerts: fpRun.alerts.length, sessions: fpRun.sessionsAlerted, total: fpSess.length, reasons: fpRun.reasons, approx: fpRun.approx };
    out.tp = tpRun ? { alerts: tpRun.alerts.length, sessions: tpRun.sessionsAlerted, total: tpSess.length, reasons: tpRun.reasons, approx: tpRun.approx } : null;
    out.alertSessions = inp.alert ? T.findAlertSessions(fpSess, inp.alert).map(function (s) { return s.id; }) : [];
    out.evidence = { fp: fpRun.alerts.slice(0, 12).map(function (a) { return T.evidence(a, rule); }), tp: tpRun ? tpRun.alerts.slice(0, 12).map(function (a) { return T.evidence(a, rule); }) : [] };
    out.unsupported = rule.unsupported.slice();
    if (!fpRun.alerts.length) { out.noFpHit = true; return out; }
    if (tpRun && !tpRun.alerts.length) { out.noTpHit = true; }

    // Evaluating a changed rule only needs the sessions that alerted at first, because every change here narrows the rule.
    var fpIds = sessionIds(fpRun.alerts), tpIds = tpRun ? sessionIds(tpRun.alerts) : {};
    var fpHitSess = fpSess.filter(function (s) { return fpIds[s.id]; });
    var tpHitSess = tpRun ? tpSess.filter(function (s) { return tpIds[s.id]; }) : [];
    function evalRule(r) {
      var f = IDS.run(r, fpHitSess, ctx), t = tpRun ? IDS.run(r, tpHitSess, ctx) : null;
      return { fp: f.alerts.length, fpSessions: f.sessionsAlerted, tp: t ? t.alerts.length : null, tpSessions: t ? t.sessionsAlerted : null, fpRun: f, tpRun: t };
    }
    var base = { fp: fpRun.alerts.length, fpSessions: fpRun.sessionsAlerted, tp: tpRun ? tpRun.alerts.length : null, tpSessions: tpRun ? tpRun.sessionsAlerted : null };
    var hasTp = !!tpRun && tpRun.alerts.length > 0;

    function effect(r) {
      var e = evalRule(r);
      return { fpBefore: base.fp, fpAfter: e.fp, tpBefore: base.tp, tpAfter: e.tp, tpSessionsBefore: base.tpSessions, tpSessionsAfter: e.tpSessions,
        keepsTp: hasTp ? e.tpSessions === base.tpSessions : null, removesFp: base.fp - e.fp };
    }

    /* ---------- candidate changes against a given rule and its current alerts ---------- */
    function candidates(cur, curFp, curTp, withTp) {
      var recs = [], ref = withTp ? curTp : curFp;       // without a true-positive capture, only the false-positive evidence exists

      // 1. Direction and connection state
      var dirs = {};
      ref.forEach(function (a) { dirs[a.unit.dir] = true; });
      var dirKeys = Object.keys(dirs);
      var hasReq = cur.opts.some(function (o) { return o.buffer && REQUEST_BUFFERS.test(o.buffer); }), hasRes = cur.opts.some(function (o) { return o.buffer && RESPONSE_BUFFERS.test(o.buffer); });
      var inferDir = hasReq && !hasRes ? 'toServer' : (hasRes && !hasReq ? 'toClient' : (dirKeys.length === 1 && withTp ? dirKeys[0] : null));
      var f = cur.flow;
      if (cur.proto === 'tcp' || cur.proto === 'http') {
        var wantEst = ref.length && ref.every(function (a) { return a.session.established; });
        var haveDir = f && (f.toServer !== f.toClient);
        if (inferDir && (!haveDir || (wantEst && !(f && f.established)))) {
          var dir = haveDir ? (f.toServer ? 'toServer' : 'toClient') : inferDir;
          recs.push({ id: 'flow', kind: 'flow', title: 'Say which direction and connection state this rule is for', change: 'flow:' + flowText(dir, wantEst) + ';',
            why: [hasReq || hasRes ? 'The rule looks at ' + (dir === 'toServer' ? 'request' : 'response') + ' data, so it should only run on traffic going ' + (dir === 'toServer' ? 'to the server' : 'to the client') + '.' : 'All the matching traffic in the true-positive capture goes ' + (dir === 'toServer' ? 'to the server' : 'to the client') + '.',
              'This also lets the engine skip unrelated packets, which makes the rule cheaper to run.'],
            risk: 'low', semantic: !withTp, apply: function (r) { setFlow(r, dir, wantEst); } });
        }
      }

      // 2. Move contents into the HTTP buffer they belong to
      cur.contents.forEach(function (c) {
        if (c.neg || c.buffer !== 'raw') return;
        var cand = bufferCandidates(ref, c);
        if (!cand.length) return;
        var pick = cand[0];
        recs.push({ id: 'buffer' + c.idx, kind: 'buffer', contentIdx: c.idx, title: 'Search ' + IDS.bufferLabel(pick) + ' instead of the whole stream for ' + IDS.describeContent(c),
          change: 'Use the ' + pick + ' buffer for this content (offset, depth, distance and within then count from the start of that buffer).',
          why: ['In ' + (withTp ? 'the true-positive capture' : 'the matching traffic') + ' this text sits in ' + IDS.bufferLabel(pick) + (cand.length > 1 ? ' (it also appears in ' + cand.slice(1, 3).map(IDS.bufferLabel).join(' and ') + ')' : '') + '.',
            'Matching a whole TCP stream finds the same text in other places, such as page bodies, cookies and other headers. A buffer keeps the match where the attack puts it.',
            'Positions inside a buffer are also stable, unlike positions in a stream where header order changes.'],
          risk: 'low', semantic: !withTp, apply: function (r) { r.contents[c.idx].buffer = pick; r.usesHttp = true; } });
      });

      // 3. Server port
      if ((cur.proto === 'tcp' || cur.proto === 'udp') && withTp && /^(any|\$\w+)$/.test(cur.dport) && ref.every(function (a) { return a.unit.dir === 'toServer'; })) {
        var ports = {}; ref.forEach(function (a) { ports[a.session.server.port] = true; });
        var pl = Object.keys(ports).map(Number).sort(function (a, b) { return a - b; });
        if (pl.length && pl.length <= 4) {
          var ptxt = pl.length === 1 ? String(pl[0]) : '[' + pl.join(',') + ']';
          recs.push({ id: 'port', kind: 'port', title: 'Limit the destination port to ' + ptxt, change: 'Destination port in the rule header: ' + ptxt,
            why: ['The true-positive traffic only goes to port ' + pl.join(', ') + '.', 'Attackers can use other ports, and services run on non-standard ports. For HTTP, an "alert http" rule matches by protocol detection on any port instead.'],
            risk: 'medium', apply: function (r) { r.dport = ptxt; } });
        }
      }

      // 4. Anchor each content: offset and depth for the first, distance and within for the rest
      var prevPositive = null;
      cur.contents.forEach(function (c) {
        if (c.neg) return;
        var occ = matchesFor(ref, c.idx);
        if (!occ.length) { prevPositive = c; return; }
        var samePrev = prevPositive && prevPositive.buffer === c.buffer;
        var isFirst = !samePrev;
        if (isFirst) {
          var starts = occ.map(function (x) { return x.m.start; }), ends = occ.map(function (x) { return x.m.end; });
          var lo = Math.min.apply(null, starts), hi = Math.max.apply(null, ends), span = hi - lo;
          var pad = Math.max(8, Math.round(span * 0.25));
          var oStart = Math.max(0, lo - pad), oEnd = hi + pad, depth = oEnd - oStart;
          var already = c.offset !== null || c.depth !== null || c.startswith;
          var atStart = lo === 0;
          if (!already || (c.depth !== null && c.depth > depth + 16)) {
            var useStarts = atStart && c.str.length >= 3;
            recs.push({ id: 'anchor' + c.idx, kind: 'anchor', contentIdx: c.idx,
              title: useStarts ? 'Require ' + IDS.describeContent(c) + ' at the very start of ' + IDS.bufferLabel(c.buffer) : 'Anchor ' + IDS.describeContent(c) + ' to bytes ' + oStart + ' to ' + oEnd + ' of ' + IDS.bufferLabel(c.buffer),
              change: useStarts ? (engine === 'suricata' ? 'startswith;' : 'offset:0; depth:' + c.str.length + ';') : 'offset:' + oStart + '; depth:' + depth + ';',
              why: [(withTp ? 'In the true-positive capture' : 'In the matching traffic') + ' it was found at bytes ' + lo + ' to ' + hi + (occ.length > 1 ? ' (across ' + occ.length + ' alerts)' : '') + ' of the buffer.',
                useStarts ? 'It always begins the buffer, so startswith/depth removes every later occurrence.' : 'offset ' + oStart + ' starts the search; depth ' + depth + ' counts from there, so the content must end by byte ' + oEnd + '. That is the observed range plus ' + pad + ' bytes of margin each side.',
                'depth counts from offset (not from the start of the buffer) in both Snort and Suricata.'],
              risk: 'medium', apply: function (r) {
                var x = r.contents[c.idx];
                x.offset = null; x.depth = null; x.startswith = false;
                if (useStarts) { if (engine === 'suricata') x.startswith = true; else { x.offset = 0; x.depth = c.str.length; } }
                else { x.offset = oStart; x.depth = depth; }
              } });
          }
        } else {
          var gaps = [];
          occ.forEach(function (x) { if (x.m.prevEnd !== undefined) gaps.push(x.m.start - x.m.prevEnd); });
          var gs = stats(gaps);
          if (gs && c.distance === null && c.within === null) {
            var gpad = Math.max(4, Math.round((gs.max - gs.min) * 0.25));
            var dist = gs.min - gpad, within = gs.max + c.str.length - dist + gpad;
            if (dist < 0 && gs.min >= 0) dist = 0;
            if (dist >= 0) within = gs.max + c.str.length - dist + gpad;
            recs.push({ id: 'chain' + c.idx, kind: 'anchor', contentIdx: c.idx,
              title: 'Tie ' + IDS.describeContent(c) + ' to the content before it (distance ' + dist + ', within ' + within + ')', change: 'distance:' + dist + '; within:' + within + ';',
              why: ['It was found ' + (gs.min === gs.max ? gs.min : gs.min + ' to ' + gs.max) + ' bytes after the end of the previous content.',
                'The search window is [previous match end + distance, previous match end + distance + within), so distance ' + dist + ' and within ' + within + ' cover bytes ' + dist + ' to ' + (dist + within) + ' after it, a margin of ' + gpad + ' around what was observed.',
                'Relative positions survive changes earlier in the data, which absolute offsets do not.'],
              risk: 'medium', apply: function (r) { r.contents[c.idx].distance = dist; r.contents[c.idx].within = within; } });
          }
        }
        prevPositive = c;
      });

      // 5. nocase that is not needed
      cur.contents.forEach(function (c) {
        if (!c.nocase || c.neg || !withTp) return;
        var tpOcc = matchesFor(curTp, c.idx), fpOcc = matchesFor(curFp, c.idx);
        if (!tpOcc.length || !fpOcc.length) return;
        var exact = tpOcc.every(function (x) { return bufStr(x.a, x.m.buffer).slice(x.m.start, x.m.end) === c.str; });
        var fpOther = fpOcc.some(function (x) { return bufStr(x.a, x.m.buffer).slice(x.m.start, x.m.end) !== c.str; });
        if (exact && fpOther) {
          recs.push({ id: 'nocase' + c.idx, kind: 'nocase', contentIdx: c.idx, title: 'Make ' + IDS.describeContent(c) + ' case sensitive', change: 'Remove nocase from this content.',
            why: ['Every true-positive match has exactly this capitalization, but the false positives matched with different capitalization.'],
            risk: 'high', warn: 'If the protocol ignores case (HTTP methods and header names, SQL keywords, many commands), an attacker can change the capitalization and slip past the rule.',
            apply: function (r) { r.contents[c.idx].nocase = false; } });
        }
      });

      // 6. Extra context strings found only around true positives
      if (withTp && curTp.length) {
        var pos = cur.contents.filter(function (c) { return !c.neg; });
        var anchor = pos[pos.length - 1];
        var trailing = anchor && cur.opts.slice(cur.opts.indexOf(anchor) + 1).some(function (o) { return o.type === 'pcre' || (o.type === 'content' && !o.neg); });
        if (anchor && !trailing) {
          var W = 48;
          function windows(list) {
            return matchesFor(list, anchor.idx).slice(0, 40).map(function (x) {
              var str = bufStr(x.a, x.m.buffer), s0 = Math.max(0, x.m.start - W), e0 = Math.min(str.length, x.m.end + W);
              return { str: str.slice(s0, e0), ms: x.m.start - s0, me: x.m.end - s0, len: x.m.end - x.m.start };
            });
          }
          var tw = windows(curTp), fw = windows(curFp);
          if (tw.length && fw.length) {
            var found = [], seen = {};
            var ref0 = tw[0];
            ['after', 'before'].forEach(function (side) {
              for (var L = 24; L >= 4; L--) {
                var lo2 = side === 'after' ? ref0.me : 0, hi2 = side === 'after' ? ref0.str.length : ref0.ms;
                for (var st = lo2; st + L <= hi2; st++) {
                  var sub = ref0.str.slice(st, st + L);
                  if (seen[side + sub]) continue;
                  if (!/[\x21-\x7e]/.test(sub)) continue;
                  var inAllTp = tw.every(function (w) { var i = side === 'after' ? w.str.indexOf(sub, w.me) : w.str.lastIndexOf(sub, w.ms - L); return i >= 0 && (side === 'after' ? i >= w.me : i + L <= w.ms); });
                  if (!inAllTp) continue;
                  var inFp = fw.some(function (w) { return w.str.indexOf(sub) >= 0; });
                  if (inFp) continue;
                  seen[side + sub] = true;
                  found.push({ side: side, sub: sub, L: L, gapFromRef: side === 'after' ? st - ref0.me : ref0.ms - (st + L) });
                  if (found.filter(function (f) { return f.side === side; }).length >= 3) { st = hi2; L = 3; }
                }
              }
            });
            found.sort(function (a, b) { return b.L - a.L || a.gapFromRef - b.gapFromRef; });
            found.slice(0, 4).forEach(function (cand, k) {
              var gaps = tw.map(function (w) {
                if (cand.side === 'after') return w.str.indexOf(cand.sub, w.me) - w.me;
                var i = w.str.lastIndexOf(cand.sub, w.ms - cand.L); return -(w.me - i);
              });
              var gs2 = stats(gaps), padc = Math.max(4, Math.round((gs2.max - gs2.min) * 0.25));
              var distance = gs2.min - padc, within2 = gs2.max + cand.L - distance + padc;
              if (cand.side === 'after' && distance < 0) { distance = 0; within2 = gs2.max + cand.L + padc; }
              recs.push({ id: 'context' + k, kind: 'context', title: 'Also require ' + IDS.describeContent({ str: cand.sub }) + ' ' + (cand.side === 'after' ? 'after' : 'before') + ' the match',
                change: 'Add: content:"' + IDS.escapeContent(cand.sub) + '"; distance:' + distance + '; within:' + within2 + ';',
                why: ['This text appears ' + (cand.side === 'after' ? 'after' : 'before') + ' ' + IDS.describeContent(anchor) + ' in every true-positive match (' + tw.length + ' sample' + (tw.length === 1 ? '' : 's') + ') and in none of the ' + fw.length + ' false-positive matches.',
                  'It is relative to the end of ' + IDS.describeContent(anchor) + ': distance ' + distance + ' and within ' + within2 + ' search ' + (distance < 0 ? 'starting ' + (-distance) + ' bytes back' : 'starting ' + distance + ' bytes on') + ' for ' + within2 + ' bytes.'],
                risk: 'medium', warn: tw.length < 2 ? 'Only one true-positive sample was available, so this string might be a coincidence of that sample rather than part of the attack. Check it against the exploit or malware documentation.' : 'This string comes from your traffic. Check that it is part of the attack and not an artifact of the sample, and that it holds no secrets before you share the rule.',
                apply: function (r) {
                  var a2 = r.contents[anchor.idx];
                  var nc = { type: 'content', neg: false, str: cand.sub, nocase: false, offset: null, depth: null, distance: distance, within: within2, fast: false, fastOnly: false, startswith: false, endswith: false, buffer: a2.buffer, idx: r.contents.length, varMods: [], added: true };
                  var at = r.opts.indexOf(a2);
                  r.opts.splice(at + 1, 0, nc); r.contents.push(nc);
                } });
            });
          }
        }
      }

      // 7. Packet size (datagram protocols and single-packet TCP messages)
      if (withTp && !cur.usesHttp && !cur.opts.some(function (o) { return o.type === 'dsize'; })) {
        function psize(list) { return list.map(function (a) { var seg = segAt(a.unit.segs, a.matches.length ? a.matches[0].start : 0); return a.unit.kind === 'dgram' ? a.unit.str.length : (a.unit.segs.length === 1 && seg ? seg.len : null); }); }
        var ts = psize(curTp), fs = psize(curFp);
        if (ts.length && ts.every(function (n) { return n !== null; }) && fs.every(function (n) { return n !== null; })) {
          var tsx = stats(ts), fsx = stats(fs);
          var outside = fs.every(function (n) { return n < tsx.min || n > tsx.max; });
          if (outside) {
            var lo3 = tsx.min - 1 - (tsx.min === tsx.max ? 0 : Math.round((tsx.max - tsx.min) * 0.1)), hi3 = tsx.max + 1 + (tsx.min === tsx.max ? 0 : Math.round((tsx.max - tsx.min) * 0.1));
            var dtext = tsx.min === tsx.max ? tsx.min : Math.max(0, lo3) + '<>' + hi3;
            recs.push({ id: 'dsize', kind: 'dsize', title: 'Restrict the payload size (dsize)', change: 'dsize:' + dtext + ';',
              why: ['True-positive payloads are ' + (tsx.min === tsx.max ? tsx.min : tsx.min + ' to ' + tsx.max) + ' bytes; the false positives are ' + (fsx.min === fsx.max ? fsx.min : fsx.min + ' to ' + fsx.max) + ' bytes.', 'dsize counts the payload of one packet. A range like 10<>20 means more than 10 and fewer than 20.'],
              risk: 'high', warn: 'Packet sizes vary with TCP segmentation, MTU and tunneling, so dsize is only dependable for UDP and for fixed-size protocol messages.',
              apply: function (r) { var at = r.opts.findIndex(function (o) { return o.type === 'content' || o.type === 'pcre'; }); r.opts.splice(at < 0 ? r.opts.length : at, 0, { type: 'dsize', value: String(dtext), cmp: IDS.parseCompare(String(dtext)) }); } });
          }
        }
      }

      // 8. isdataat after the last content
      if (withTp && curTp.length) {
        var lastPos = cur.contents.filter(function (c) { return !c.neg; }).pop();
        if (lastPos && !cur.opts.some(function (o) { return o.type === 'isdataat'; })) {
          function remaining(list) { return matchesFor(list, lastPos.idx).map(function (x) { return x.m.bufLen - x.m.end; }); }
          var rt = remaining(curTp), rf = remaining(curFp);
          if (rt.length && rf.length) {
            var rts = stats(rt), rfs = stats(rf);
            if (rts.min > rfs.max) {
              var n = rfs.max + 1;
              recs.push({ id: 'isdataat', kind: 'isdataat', title: 'Require at least ' + n + ' more bytes after ' + IDS.describeContent(lastPos), change: 'isdataat:' + n + ',relative;',
                why: ['After the last content there are at least ' + rts.min + ' bytes in every true-positive match but at most ' + rfs.max + ' in the false positives.'],
                risk: 'medium', apply: function (r) { var last = r.contents[lastPos.idx]; var at = r.opts.indexOf(last); r.opts.splice(at + 1, 0, { type: 'isdataat', value: n + ',relative', not: false, n: n, relative: true, buffer: last.buffer, ok: true }); } });
            }
          }
        }
      }
      return recs;
    }

    /* ---------- individual recommendations against the original rule ---------- */
    var recs = candidates(rule, fpRun.alerts, tpRun ? tpRun.alerts : [], hasTp);
    recs.forEach(function (rec) {
      var r2 = T.cloneRule(rule);
      try { rec.apply(r2); } catch (e) { rec.error = e.message; return; }
      var rendered = T.renderRule(r2, engine);
      rec.rule = r2; rec.ruleText = rendered.text; rec.warnings = rendered.warnings;
      rec.effect = effect(r2);
    });
    recs = recs.filter(function (r) { return !r.error; });

    // Negated context strings: only offered when nothing else removes the false positives.
    /* (kept out of the main list on purpose: see notes) */

    /* ---------- threshold, rate and suppress ---------- */
    var perSrc = {};
    fpRun.alerts.forEach(function (a) { var k = T.alertSource(a); (perSrc[k] = perSrc[k] || []).push(T.alertTime(a)); });
    var srcKeys = Object.keys(perSrc);
    var tpPerSrc = {};
    if (tpRun) tpRun.alerts.forEach(function (a) { var k = T.alertSource(a); (tpPerSrc[k] = tpPerSrc[k] || []).push(T.alertTime(a)); });
    function maxInWindow(times, sec) {
      var t = times.slice().sort(function (a, b) { return a - b; }), best = 0, j = 0;
      for (var i = 0; i < t.length; i++) { while (t[i] - t[j] > sec * 1000) j++; best = Math.max(best, i - j + 1); }
      return best;
    }
    function limitSim(per, sec) { var kept = 0; Object.keys(per).forEach(function (k) { var t = per[k].slice().sort(function (a, b) { return a - b; }), start = -Infinity; t.forEach(function (x) { if (x - start >= sec * 1000) { kept++; start = x; } }); }); return kept; }
    out.alertStats = { sources: srcKeys.length, perSource: srcKeys.map(function (k) { return { ip: k, count: perSrc[k].length, burst60: maxInWindow(perSrc[k], 60) }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, 10),
      span: fpRun.alerts.length ? (Math.max.apply(null, fpRun.alerts.map(T.alertTime)) - Math.min.apply(null, fpRun.alerts.map(T.alertTime))) / 1000 : 0 };
    var others = [];
    if (fpRun.alerts.length >= 3) {
      var limAfter = limitSim(perSrc, 300), tpLimAfter = tpRun ? limitSim(tpPerSrc, 300) : null;
      others.push({ id: 'limit', kind: 'threshold', title: 'Cap the number of alerts instead of hiding them (rate limit)',
        change: engine === 'snort3' ? 'event_filter in your Snort 3 configuration: gid 1, sid ' + (rule.sid || 'N') + ', type limit, track by_src, count 1, seconds 300' : 'threshold:type limit, track by_src, count 1, seconds 300;',
        why: ['The capture has ' + fpRun.alerts.length + ' false-positive alerts from ' + srcKeys.length + ' source' + (srcKeys.length === 1 ? '' : 's') + '. At most one alert per source every 5 minutes would leave ' + limAfter + '.',
          'A limit keeps the first alert from each source, so the rule still detects the activity. It only reduces repeats.'],
        effect: { fpBefore: fpRun.alerts.length, fpAfter: limAfter, tpBefore: tpRun ? tpRun.alerts.length : null, tpAfter: tpLimAfter, keepsTp: tpRun ? true : null },
        risk: 'low', note: true });
      var fpBurst = Math.max.apply(null, srcKeys.map(function (k) { return maxInWindow(perSrc[k], 60); }));
      var tpBurst = tpRun && Object.keys(tpPerSrc).length ? Math.min.apply(null, Object.keys(tpPerSrc).map(function (k) { return maxInWindow(tpPerSrc[k], 60); })) : null;
      if (tpBurst !== null && tpBurst > fpBurst) {
        var cnt = fpBurst + 1;
        others.push({ id: 'detfilter', kind: 'threshold', title: 'Alert only after ' + cnt + ' hits from one source in 60 seconds (detection filter)',
          change: 'detection_filter:track by_src, count ' + cnt + ', seconds 60;',
          why: ['The busiest false-positive source produced ' + fpBurst + ' alert' + (fpBurst === 1 ? '' : 's') + ' in 60 seconds; the quietest true-positive source produced ' + tpBurst + '.', 'The first ' + (cnt - 1) + ' hits are not reported, so a real attack is reported a little later.'],
          effect: { fpBefore: fpRun.alerts.length, fpAfter: 0, tpBefore: tpRun.alerts.length, tpAfter: tpRun.alerts.length, keepsTp: true }, risk: 'medium', note: true,
          warn: 'A slow attack that stays below the count is never reported. Use this only for noisy, high-volume detections.' });
      }
    }
    if (srcKeys.length && srcKeys.length <= 3) {
      var tpSources = Object.keys(tpPerSrc), conflict = srcKeys.filter(function (k) { return tpSources.indexOf(k) >= 0; });
      others.push({ id: 'suppress', kind: 'suppress', title: 'Suppress this rule for ' + (srcKeys.length === 1 ? 'one source address' : srcKeys.length + ' source addresses'),
        change: engine === 'snort3' ? "suppress = { " + srcKeys.map(function (k) { return "{ gid = 1, sid = " + (rule.sid || 'N') + ", track = 'by_src', ip = '" + k + "' }"; }).join(', ') + ' }  (in snort.lua)'
          : srcKeys.map(function (k) { return 'suppress gen_id 1, sig_id ' + (rule.sid || 'N') + ', track by_src, ip ' + k; }).join('\n') + '   (in threshold.config)',
        why: ['All ' + fpRun.alerts.length + ' false-positive alerts come from ' + srcKeys.join(', ') + '.', 'A suppression leaves the rule untouched for everyone else.'],
        effect: { fpBefore: fpRun.alerts.length, fpAfter: 0, tpBefore: tpRun ? tpRun.alerts.length : null, tpAfter: tpRun ? tpRun.alerts.length - tpRun.alerts.filter(function (a) { return srcKeys.indexOf(T.alertSource(a)) >= 0; }).length : null, keepsTp: tpRun ? conflict.length === 0 : null },
        risk: 'high', note: true, warn: 'This blinds the rule for those hosts. If one of them is ever compromised, this rule will not report it. Prefer a narrower rule change, and give the suppression an owner and an end date.' });
    }
    // Performance only: a fast pattern on the longest content.
    var positives = rule.contents.filter(function (c) { return !c.neg; });
    if (positives.length > 1 && !positives.some(function (c) { return c.fast; })) {
      var longest = positives.slice().sort(function (a, b) { return b.str.length - a.str.length; })[0];
      if (longest.str.length >= 4) {
        var r3 = T.cloneRule(rule); r3.contents[longest.idx].fast = true;
        others.push({ id: 'fast', kind: 'performance', title: 'Use ' + IDS.describeContent(longest) + ' as the fast pattern', change: 'Add fast_pattern to this content.',
          why: ['The engine searches the fast pattern first and only checks the rest if it is found. The longest, rarest string is the best choice.', 'This does not change what the rule detects.'], risk: 'low',
          rule: r3, ruleText: T.renderRule(r3, engine).text, effect: { fpBefore: base.fp, fpAfter: base.fp, tpBefore: base.tp, tpAfter: base.tp, keepsTp: hasTp ? true : null }, performance: true });
      }
    }

    // Negated context (last resort): strings common to the false positives and absent around true positives.
    if (hasTp) {
      var anyFixes = recs.some(function (r) { return r.effect.fpAfter === 0 && r.effect.keepsTp; });
      if (!anyFixes) {
        var lastP = rule.contents.filter(function (c) { return !c.neg; }).pop();
        var trailing2 = lastP && rule.opts.slice(rule.opts.indexOf(lastP) + 1).some(function (o) { return o.type === 'pcre' || (o.type === 'content' && !o.neg); });
        if (lastP && !trailing2) {
          var W2 = 48;
          var wins = function (list) { return matchesFor(list, lastP.idx).slice(0, 40).map(function (x) { var str = bufStr(x.a, x.m.buffer), s0 = Math.max(0, x.m.start - W2), e0 = Math.min(str.length, x.m.end + W2); return { str: str.slice(s0, e0), ms: x.m.start - s0, me: x.m.end - s0 }; }); };
          var fw2 = wins(fpRun.alerts), tw2 = wins(tpRun.alerts);
          if (fw2.length >= 2 && tw2.length) {
            var f0 = fw2[0], hit = null;
            for (var L2 = 20; L2 >= 5 && !hit; L2--) for (var st2 = f0.me; st2 + L2 <= f0.str.length && !hit; st2++) {
              var sub2 = f0.str.slice(st2, st2 + L2);
              if (!/[\x21-\x7e]/.test(sub2)) continue;
              if (fw2.every(function (w) { return w.str.indexOf(sub2, w.me) >= 0; }) && !tw2.some(function (w) { return w.str.indexOf(sub2) >= 0; })) hit = { sub: sub2, gap: st2 - f0.me };
            }
            if (hit) {
              var gp = fw2.map(function (w) { return w.str.indexOf(hit.sub, w.me) - w.me; }), g3 = stats(gp), pad3 = Math.max(4, Math.round((g3.max - g3.min) * 0.25));
              var dist3 = Math.max(0, g3.min - pad3), within3 = g3.max + hit.sub.length - dist3 + pad3;
              var r4 = T.cloneRule(rule), a4 = r4.contents[lastP.idx];
              var nc4 = { type: 'content', neg: true, str: hit.sub, nocase: false, offset: null, depth: null, distance: dist3, within: within3, fast: false, fastOnly: false, startswith: false, endswith: false, buffer: a4.buffer, idx: r4.contents.length, varMods: [], added: true };
              r4.opts.splice(r4.opts.indexOf(a4) + 1, 0, nc4); r4.contents.push(nc4);
              others.push({ id: 'negctx', kind: 'negated', title: 'Exclude when ' + IDS.describeContent({ str: hit.sub }) + ' follows the match', change: 'Add: content:!"' + IDS.escapeContent(hit.sub) + '"; distance:' + dist3 + '; within:' + within3 + ';',
                why: ['Every false-positive match is followed by this text and no true-positive match is.', 'Nothing else in the data separated them, so this is the remaining option.'],
                risk: 'high', warn: 'A negated content is easy to evade: an attacker who adds this text after the attack slips past the rule. Prefer a positive requirement if you can find one, or a threshold.',
                rule: r4, ruleText: T.renderRule(r4, engine).text, effect: effect(r4) });
            }
          }
        }
      }
    }

    /* ---------- combined recommendation: apply the best changes one at a time, re-measuring each time ---------- */
    if (hasTp) {
      var cur = T.cloneRule(rule), curFp = fpRun.alerts, curTpAl = tpRun.alerts, curEffect = { fp: base.fp };
      var order = ['flow', 'buffer', 'anchor', 'nocase', 'context', 'dsize', 'isdataat', 'port'];
      var guard = 0, changed = true;
      while (changed && guard++ < 8 && curEffect.fp > 0) {
        changed = false;
        var cands = candidates(cur, curFp, curTpAl, true).filter(function (c) { return c.kind !== 'nocase' && c.kind !== 'dsize' && c.kind !== 'port'; });
        cands.sort(function (a, b) { return order.indexOf(a.kind) - order.indexOf(b.kind); });
        for (var ci = 0; ci < cands.length; ci++) {
          var cand = cands[ci], trial = T.cloneRule(cur);
          try { cand.apply(trial); } catch (e) { continue; }
          var ev = IDS.run(trial, fpHitSess, ctx), evTp = IDS.run(trial, tpHitSess, ctx);
          var keeps = evTp.sessionsAlerted === base.tpSessions;
          var better = ev.alerts.length < curEffect.fp;
          var semantic = (cand.kind === 'flow' || cand.kind === 'buffer') && ev.alerts.length <= curEffect.fp;
          if (keeps && (better || semantic) && out.steps.every(function (s) { return s.id !== cand.id; })) {
            out.steps.push({ id: cand.id, kind: cand.kind, title: cand.title, change: cand.change, fpAfter: ev.alerts.length, tpAfter: evTp.alerts.length, why: cand.why, warn: cand.warn || '' });
            cur = trial; curFp = ev.alerts; curTpAl = evTp.alerts; curEffect = { fp: ev.alerts.length }; changed = true; break;
          }
        }
      }
      if (out.steps.length) {
        var rendered2 = T.renderRule(cur, engine);
        out.combined = { rule: cur, ruleText: rendered2.text, warnings: rendered2.warnings, effect: effect(cur) };
      }
    }

    // Rank: verified fixes first, then partial, then everything else.
    function score(r) {
      var e = r.effect; if (!e) return 9;
      if (e.keepsTp === false) return 8;
      if (e.fpAfter === 0 && e.removesFp > 0) return 0;
      if (e.removesFp > 0) return 1;
      return r.semantic || r.kind === 'flow' || r.kind === 'buffer' ? 3 : 5;
    }
    recs.sort(function (a, b) { return score(a) - score(b) || (a.risk === 'low' ? 0 : 1) - (b.risk === 'low' ? 0 : 1); });
    out.recs = recs;
    out.others = others;
    out.fpAlerts = fpRun.alerts;
    out.tpAlerts = tpRun ? tpRun.alerts : [];
    // Apply the chosen changes (by id) to a copy of the rule and measure the result against both captures.
    out.compose = function (ids) {
      var r = T.cloneRule(rule), applied = [];
      recs.concat(others.filter(function (o) { return o.apply; })).forEach(function (rec) {
        if (ids.indexOf(rec.id) < 0 || !rec.apply) return;
        try { rec.apply(r); applied.push(rec.id); } catch (e) { /* skipped */ }
      });
      var rendered = T.renderRule(r, engine);
      return { rule: r, applied: applied, ruleText: rendered.text, warnings: rendered.warnings, effect: effect(r) };
    };

    // Notes on the evidence.
    if (!hasTp) out.notes.push('No true-positive capture was provided, so nothing here can be checked against real attack traffic. Positions and strings below describe what matched in the false-positive capture. Add a capture of the real activity to get verified numbers for offset, depth, distance and within.');
    if (out.noTpHit) out.notes.push('The rule did not fire on the true-positive capture in this simulation, so there is nothing to compare against. See the reasons below.');
    if (fpRun.approx.length) out.notes.push('This rule uses options the simulator cannot evaluate (' + fpRun.approx.join(', ') + '). It treats them as satisfied, so it may report more hits than your engine.');
    if (rule.unsupported.length) out.notes.push('Options that are kept as written but not simulated: ' + rule.unsupported.join(', ') + '.');
    if (inp.fp.stats && inp.fp.stats.gaps) out.notes.push('The false-positive capture has missing TCP segments (' + inp.fp.stats.gaps + '), which can hide matches or shift positions.');
    return out;
  };

  T.positionTable = function (rule, alerts) {
    return rule.contents.filter(function (c) { return !c.neg; }).map(function (c) {
      var occ = matchesFor(alerts, c.idx);
      return { idx: c.idx, label: IDS.describeContent(c), buffer: c.buffer, count: occ.length, starts: stats(occ.map(function (x) { return x.m.start; })), ends: stats(occ.map(function (x) { return x.m.end; })),
        gaps: stats(occ.filter(function (x) { return x.m.prevEnd > 0; }).map(function (x) { return x.m.start - x.m.prevEnd; })) };
    });
  };

  // Commands that check a rule against a capture with each engine.
  T.verifyCommands = function (engine) {
    if (engine === 'suricata') return ['suricata -r capture.pcap -S tuned.rules -l ./out -k none', 'Then read ./out/fast.log or ./out/eve.json. -S loads only your rule file; -k none ignores checksum errors in captures.'];
    if (engine === 'snort3') return ['snort -c snort.lua -r capture.pcap -R tuned.rules -A alert_fast -q', 'Run it once for the false-positive capture (expect no alert) and once for the true-positive capture (expect the alert).'];
    return ['snort -c /etc/snort/snort.conf -r capture.pcap -A console -q', 'Put the tuned rule in a rules file that snort.conf includes. Run it on both captures.'];
  };
})();
