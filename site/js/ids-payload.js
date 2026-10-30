// Payload viewer and content exclusions for the Snort/Suricata tuner (SK.idsPayload).
// Shows what a rule looked at in each false positive, spots text that is the same in every one (a table name after a SQL match,
// for example), and turns a selection into an exclusion that is re-run over the captures and then attacked with variants of the traffic.
(function () {
  var SK = window.SK = window.SK || {};
  var IDS = SK.ids, Y = SK.idsPayload = {};

  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }
  function reLit(s) { return String(s).replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&'); }

  /* ================================================================ what the rule looked at */

  function bufStr(alert, name) {
    if (name === 'raw') return alert.unit.str;
    return alert.tx ? (IDS.httpBuffers(alert.tx)[name] || '') : '';
  }

  // The buffer and positions an alert is about: the buffer of the last positive match, which is also where a relative option continues from.
  Y.focus = function (a) {
    if (!a.matches || !a.matches.length) return null;
    var last = a.matches[a.matches.length - 1], B = last.buffer;
    var inB = a.matches.filter(function (m) { return m.buffer === B; });
    return { buffer: B, str: bufStr(a, B), lastEnd: last.end, firstStart: inB[0].start, ranges: inB.map(function (m) { return { s: m.start, e: m.end }; }) };
  };

  // One entry per distinct payload (identical ones are counted), so 400 alerts of the same request show once.
  Y.views = function (alerts, limit) {
    var seen = {}, out = [], total = 0;
    alerts.forEach(function (a) {
      var f = Y.focus(a); if (!f) return;
      total++;
      var key = f.buffer + '\u0000' + f.lastEnd + '\u0000' + f.str;
      if (seen[key]) { seen[key].count++; return; }
      var v = { alert: a, buffer: f.buffer, text: f.str, lastEnd: f.lastEnd, ranges: f.ranges, count: 1, session: a.session, dir: a.unit.dir, line: a.tx ? a.tx.requestLine : '' };
      seen[key] = v; out.push(v);
    });
    return { items: out.slice(0, limit || 10), distinct: out.length, total: total };
  };

  // Text safe to show: one character per byte, so a position in the display is a position in the buffer.
  Y.display = function (s) { return String(s).replace(/[^\x20-\x7e\n]/g, '·'); };

  /* ================================================================ what must never be excluded */

  var SQL_WORDS = { select: 1, from: 1, where: 1, and: 1, or: 1, union: 1, order: 1, by: 1, group: 1, limit: 1, as: 1, on: 1, 'in': 1, not: 1, 'null': 1, is: 1, like: 1, join: 1,
    insert: 1, into: 1, update: 1, set: 1, 'delete': 1, drop: 1, values: 1, having: 1, exec: 1, execute: 1, table: 1, all: 1, distinct: 1, 'case': 1, when: 1, then: 1, 'else': 1, end: 1,
    'true': 1, 'false': 1, sleep: 1, benchmark: 1, waitfor: 1, 'delay': 1, concat: 1, 'char': 1, cast: 1, convert: 1, count: 1 };

  var ATTACK_TESTS = [
    [/['"`;()\\<>|&$%{}\[\]=]/, 'It has a quote, bracket, semicolon, equals sign or similar character. Attacks are built from those, so excluding them would hide attacks.'],
    [/--|\/\*|\*\/|#/, 'It has a comment marker. Attacks use these to cut off the rest of a query.'],
    [/\b(union|select|insert|update|delete|drop|alter|exec|execute|xp_\w*|sleep|pg_sleep|benchmark|waitfor|load_file|outfile|information_schema|sysobjects|having|truncate)\b/i, 'It is a SQL command word. Excluding it would let that command through.'],
    [/\b(or|and)\b\s*\d+\s*=|1\s*=\s*1/i, 'It looks like a SQL always-true test.'],
    [/\.\.[\/\\]|etc\/passwd|cmd\.exe|powershell|\/bin\/(?:ba)?sh|base64|eval|wget|curl|jndi|<script|onerror|document\.cookie/i, 'It looks like exploit text (path traversal, a shell, a script or a download command).']
  ];
  var SENSITIVE = /\b(users?|admin\w*|passwords?|passwd|pwd|pass|logins?|accounts?|customers?|credentials?|secrets?|tokens?|sessions?|mysql|master|sys\w*|shadow|credit\w*|cards?|ssn|payments?|employees?|auth\w*)\b/i;

  // Decide whether a piece of text may be offered for exclusion. { locked, reason, warns }.
  Y.check = function (x) {
    x = String(x == null ? '' : x);
    if (x.length < 3) return { locked: true, reason: 'Too short. Text of one or two characters appears everywhere, so excluding it would blind the rule.', warns: [] };
    if (x.length > 120) return { locked: true, reason: 'Too long to be a safe exclusion. Select a shorter piece.', warns: [] };
    if (/[\x00-\x08\x0b-\x1f\x7f-\xff]/.test(x)) return { locked: true, reason: 'It has control or non-text bytes.', warns: [] };
    for (var i = 0; i < ATTACK_TESTS.length; i++) if (ATTACK_TESTS[i][0].test(x)) return { locked: true, reason: ATTACK_TESTS[i][1], warns: [] };
    var warns = [];
    if (SENSITIVE.test(x)) warns.push('"' + x + '" is the kind of name an attacker goes after (accounts, passwords, admin). Only exclude it if this really is harmless data in your application.');
    if (/^\d+$/.test(x)) warns.push('A bare number is easy for an attacker to repeat.');
    if (SQL_WORDS[lower(x)]) warns.push('"' + x + '" is a SQL word, so it is part of how queries are written.');
    return { locked: false, reason: '', warns: warns };
  };

  /* ================================================================ text that is the same in every false positive */

  // Words right after the last match, scored by how many alerts they appear in. The scan stops at anything an attack would need
  // (a quote, a comment marker, a command word) so only plain words are suggested.
  Y.opportunities = function (alerts) {
    var groups = {}, n = 0;
    alerts.forEach(function (a) {
      var f = Y.focus(a); if (!f) return;
      n++;
      var after = f.str.slice(f.lastEnd, f.lastEnd + 120);
      var cut = after.search(/[&;'"`()#<>|\\=]|--|\/\*/);
      var span = cut >= 0 ? after.slice(0, cut) : after;
      var re = /[A-Za-z_][A-Za-z0-9_.\-]*/g, m, mine = {};
      while ((m = re.exec(span))) {
        var w = m[0];
        if (SQL_WORDS[lower(w)]) { if (ATTACK_TESTS[2][0].test(w)) break; continue; }
        if (mine[w]) continue;
        mine[w] = true;
        var g = groups[w] || (groups[w] = { x: w, alerts: 0, gaps: [] });
        g.alerts++; g.gaps.push(m.index);
      }
    });
    var list = Object.keys(groups).map(function (k) { var g = groups[k]; g.total = n; g.gapMin = Math.min.apply(null, g.gaps); g.gapMax = Math.max.apply(null, g.gaps); return g; })
      .filter(function (g) { return !Y.check(g.x).locked; });
    list.sort(function (a, b) { return b.alerts - a.alerts || a.gapMin - b.gapMin || a.x.length - b.x.length; });
    return list.slice(0, 6);
  };

  /* ================================================================ building the traffic variants */

  function toBytes(str) { var u = new Uint8Array(str.length); for (var i = 0; i < str.length; i++) u[i] = str.charCodeAt(i) & 255; return u; }

  // A copy of a session whose client-to-server stream is replaced.
  function variantSession(sess, str) {
    var c = Object.assign({}, sess), d = sess.dirs.toServer, seg0 = (d.segs && d.segs[0]) || { ts: sess.start, pkt: 0 };
    c.dirs = { toServer: { data: toBytes(str), segs: [{ start: 0, len: str.length, ts: seg0.ts, pkt: seg0.pkt }], gaps: 0 }, toClient: sess.dirs.toClient };
    return c;
  }

  // Position in the raw stream for a position in a decoded buffer. null when it cannot be worked out.
  function rawAt(a, buffer, idx) {
    var S = a.unit.str, tx = a.tx;
    if (buffer === 'raw') return idx;
    if (!tx) return null;
    if (buffer === 'http.request_body') return tx.bodyStart + idx;
    if (buffer === 'http.uri.raw' || buffer === 'http.uri') {
      var start = S.indexOf(tx.uri, tx.start);
      if (start < 0) return null;
      if (buffer === 'http.uri.raw') return start + idx;
      var d = 0, r = 0, u = tx.uri;
      while (d < idx && r < u.length) { if (u.charAt(r) === '%' && /^%[0-9a-fA-F]{2}/.test(u.substr(r, 3))) r += 3; else r++; d++; }
      return d === idx ? start + r : null;
    }
    return null;
  }
  function rawEnd(a, buffer) {
    var tx = a.tx, S = a.unit.str;
    if (buffer === 'raw') return S.length;
    if (!tx) return null;
    if (buffer === 'http.request_body') return tx.bodyStart + tx.body.length;
    if (buffer === 'http.uri' || buffer === 'http.uri.raw') { var st = S.indexOf(tx.uri, tx.start); return st < 0 ? null : st + tx.uri.length; }
    return null;
  }
  function insertText(a, buffer, at, text) {
    var S = a.unit.str, tx = a.tx;
    var ins = buffer === 'http.uri' || buffer === 'http.uri.raw' ? text.replace(/ /g, '%20') : text;
    var out = S.slice(0, at) + ins + S.slice(at);
    if (tx && buffer === 'http.request_body') {
      // The insert is inside the body, so the header block is untouched and can be rewritten with the new length.
      var head = out.slice(tx.start, tx.bodyStart).replace(/(Content-Length:\s*)(\d+)/i, function (m, h, n) { return h + (+n + ins.length); });
      out = out.slice(0, tx.start) + head + out.slice(tx.bodyStart);
    }
    return out;
  }

  Y.defaultAttack = function (rule) {
    var hay = lower((rule.msg || '') + ' ' + rule.contents.map(function (c) { return c.str; }).join(' ') + ' ' + rule.pcres.map(function (p) { return p.src; }).join(' '));
    return /sql|select|union|insert|from/.test(hay) ? ' UNION SELECT password FROM users--' : '';
  };

  /* ================================================================ the exclusions */

  function hashOf(s) { var h = 0; for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return (h >>> 0).toString(36); }
  var FLAG_FOR_BUFFER = { 'http.uri': 'U', 'http.uri.raw': 'I', 'http.request_body': 'P', 'http.header': 'H', 'http.header.raw': 'D', 'http.method': 'M', 'http.cookie': 'C' };

  function gapPattern(gaps) {
    if (!gaps.every(function (g) { return /^[\w\s,.*]*$/.test(g); })) return null;
    var uniq = {}; gaps.forEach(function (g) { uniq[g] = 1; });
    var keys = Object.keys(uniq);
    if (keys.length === 1) return keys[0] === '' ? '' : reLit(keys[0]);
    if (gaps.every(function (g) { return /^\s+$/.test(g); })) return '\\s+';
    var ls = gaps.map(function (g) { return g.length; });
    return '[\\w\\s,.*]{' + Math.min.apply(null, ls) + ',' + Math.max.apply(null, ls) + '}';
  }

  function sessionIdSet(alerts) { var s = {}; alerts.forEach(function (a) { s[a.session.id] = true; }); return s; }

  // inp: { rule, engine, fp, tp }, an: the result of SK.idsTune.analyze for the same inputs.
  Y.create = function (inp, an) {
    var rule = inp.rule, engine = inp.engine, ctx = { vars: inp.vars || {} };
    var fpAlerts = an.fpAlerts || [], tpAlerts = an.tpAlerts || [], hasTp = !!inp.tp && tpAlerts.length > 0;
    var fpIds = sessionIdSet(fpAlerts), tpIds = sessionIdSet(tpAlerts);
    var fpHit = inp.fp.sessions.filter(function (s) { return fpIds[s.id]; });
    var tpHit = inp.tp ? inp.tp.sessions.filter(function (s) { return tpIds[s.id]; }) : [];
    var base = { fp: fpAlerts.length, tp: inp.tp ? tpAlerts.length : null, tpSessions: Object.keys(tpIds).length };
    var T = SK.idsTune, self = {};

    function measure(r) {
      var f = IDS.run(r, fpHit, ctx), t = inp.tp ? IDS.run(r, tpHit, ctx) : null;
      return { fpBefore: base.fp, fpAfter: f.alerts.length, tpBefore: base.tp, tpAfter: t ? t.alerts.length : null,
        keepsTp: hasTp ? t.sessionsAlerted === base.tpSessions : null, removesFp: base.fp - f.alerts.length };
    }
    function fires(r, sess) { return IDS.run(r, [sess], ctx).alerts.length > 0; }

    // Where the text sits in every false positive, relative to the end of the last match.
    function locate(x, nocase) {
      var rows = [];
      fpAlerts.forEach(function (a) {
        var f = Y.focus(a); if (!f) return;
        var hay = nocase ? lower(f.str) : f.str, nd = nocase ? lower(x) : x;
        var i = hay.indexOf(nd, f.lastEnd);
        rows.push({ a: a, f: f, i: i, gap: i >= 0 ? f.str.slice(f.lastEnd, i) : null, tail: i >= 0 ? f.str.charAt(i + x.length) : null });
      });
      return rows;
    }

    function insertAfterLast(r, opt) {
      var at = -1;
      r.opts.forEach(function (o, i) { if ((o.type === 'content' || o.type === 'pcre') && !o.neg) at = i; });
      r.opts.splice(at + 1, 0, opt);
      if (opt.type === 'content') r.contents.push(opt); else r.pcres.push(opt);
    }

    // Attack the tuned rule with changed traffic. A test only counts when the original rule still fires on it.
    self.challenge = function (rec, attackText) {
      var tests = [], B = rec.buffer, x = rec.x, rows = rec.rows;
      var suffix = attackText === undefined || attackText === null ? Y.defaultAttack(rule) : attackText;
      function add(name, a, str) {
        var sess = variantSession(a.session, str), valid = fires(rule, sess), caught = fires(rec.rule, sess);
        tests.push({ name: name, valid: valid, caught: caught, bypassed: valid && !caught });
      }
      var row = rows.filter(function (r) { return r.i >= 0 && r.f.buffer === B; })[0];
      if (row && suffix) {
        var at = rawAt(row.a, B, row.i + x.length);
        if (at !== null) add('An attacker keeps the harmless text and adds "' + suffix.trim() + '" after it', row.a, insertText(row.a, B, at, suffix));
      }
      if (hasTp) {
        var a2 = tpAlerts.filter(function (a) { var f = Y.focus(a); return f && f.buffer === B; })[0];
        if (a2) {
          var f2 = Y.focus(a2), gap = row ? row.gap : ' ';
          var at2 = rawAt(a2, B, f2.lastEnd);
          if (at2 !== null) add('The real attack, with "' + x + '" slipped in next to the match', a2, insertText(a2, B, at2, gap + x));
          var at3 = rawEnd(a2, B);
          if (at3 !== null) add('The real attack, with "' + x + '" added at the end', a2, insertText(a2, B, at3, ' ' + x));
        }
      }
      return tests;
    };

    function finish(rec, notes, attackText) {
      var r2 = T.cloneRule(rule);
      rec.apply(r2);
      var rendered = T.renderRule(r2, engine);
      rec.rule = r2; rec.ruleText = rendered.text; rec.warnings = rendered.warnings; rec.effect = measure(r2);
      rec.tests = self.challenge(rec, attackText);
      rec.bypassed = rec.tests.some(function (t) { return t.bypassed; });
      if (rec.bypassed) { rec.risk = 'high'; rec.warn = 'An attacker can get past this exclusion by adding the text "' + rec.x + '". See the attack tests below.'; }
      rec.needsAck = rec.bypassed || rec.risk === 'high' || !!(rec.checkWarns && rec.checkWarns.length);
      rec.ackText = rec.bypassed ? 'I understand an attacker can get past this exclusion by adding "' + rec.x + '".' : 'I understand this exclusion can be copied by an attacker, and I accept that for this rule.';
      if (rec.checkWarns && rec.checkWarns.length) rec.why = rec.why.concat(rec.checkWarns);
      return rec;
    }

    // Exclusions for one piece of text. { locked, reason, recs, notes }.
    self.candidates = function (x, attackText) {
      var chk = Y.check(x);
      if (chk.locked) return { locked: true, reason: chk.reason, recs: [], notes: [] };
      var lastPos = rule.opts.filter(function (o) { return (o.type === 'content' || o.type === 'pcre') && !o.neg; }).pop();
      if (!lastPos) return { locked: false, recs: [], notes: ['This rule has no positive content or pcre to measure from.'] };
      var B = lastPos.buffer, notes = [], recs = [];
      var rowsCs = locate(x, false), rowsCi = locate(x, true);
      var hit = function (rows) { return rows.filter(function (r) { return r.i >= 0; }).length; };
      var nocase = hit(rowsCi) > hit(rowsCs), rows = nocase ? rowsCi : rowsCs, found = rows.filter(function (r) { return r.i >= 0 && r.f.buffer === B; });
      if (!found.length) return { locked: false, recs: [], notes: ['"' + x + '" was not found after the match in any false positive, so there is nothing to exclude.'] };
      if (found.length < rows.length) notes.push('"' + x + '" follows the match in ' + found.length + ' of ' + rows.length + ' false-positive alerts. The others would still alert.');
      var id = hashOf(x);
      var coverage = found.length + ' of ' + rows.length + ' false-positive alerts';
      var bufLabel = IDS.bufferLabel(B);
      var common = { x: x, rows: rows, buffer: B, checkWarns: chk.warns, kind: 'content-exclusion' };

      // 1. Anchored: the match, then exactly this text, then the end of the value.
      var gaps = found.map(function (r) { return r.gap; }), gp = gapPattern(gaps);
      var tailsOk = found.every(function (r) { return r.tail === '' || r.tail === '&'; });
      if (gp !== null && tailsOk) {
        var flags = 'AR' + (nocase ? 'i' : '') + (engine === 'snort2' && FLAG_FOR_BUFFER[B] ? FLAG_FOR_BUFFER[B] : '');
        var src = gp + reLit(x) + '(?:&|$)';
        recs.push(finish(Object.assign({}, common, {
          id: 'pay-a-' + id, mode: 'anchored', risk: 'medium',
          title: 'Skip when the match is followed by exactly "' + x + '" and the value ends',
          change: 'Add after the last match: pcre:!"/' + src + '/' + flags + '"; (in ' + bufLabel + ')',
          why: ['"' + x + '" follows the match in ' + coverage + '. The new line says: if what comes right after the match is "' + x + '" and then the value ends (or the next field starts), do not alert.',
            'Anything else after "' + x + '", such as a second query or a comment, makes the rule alert again. This is the narrowest way to say it.'],
          apply: function (r) {
            var p = IDS.compilePcre(src, flags);
            if (!p.re) throw new Error(p.error || 'pattern could not be compiled');
            p.type = 'pcre'; p.neg = true; p.buffer = B; p.idx = r.pcres.length;
            insertAfterLast(r, p);
          } }), notes, attackText));
      } else {
        notes.push(gp === null ? 'The text between the match and "' + x + '" has characters attacks use, so the narrow form is not offered.' : 'The text after "' + x + '" is not always the end of the value (' + (found.map(function (r) { return r.tail; }).filter(function (t, i, a) { return a.indexOf(t) === i; }).map(function (t) { return t === '' ? 'end' : '"' + t + '"'; }).join(', ')) + '), so the narrow form is not offered.');
      }

      // 2. A window after the match: the text appears within a few bytes. Easy to copy.
      var gl = found.map(function (r) { return r.gap.length; }), gmin = Math.min.apply(null, gl), gmax = Math.max.apply(null, gl);
      var pad = Math.max(4, Math.round((gmax - gmin) * 0.25)), dist = Math.max(0, gmin - pad), within = gmax + x.length - dist + pad;
      function negContent(distance, withinN) {
        return function (r) {
          var nc = { type: 'content', neg: true, str: x, nocase: nocase, offset: null, depth: null, distance: distance, within: withinN, fast: false, fastOnly: false, startswith: false, endswith: false, buffer: B, idx: r.contents.length, varMods: [], added: true };
          insertAfterLast(r, nc);
        };
      }
      recs.push(finish(Object.assign({}, common, {
        id: 'pay-w-' + id, mode: 'window', risk: 'high',
        title: 'Skip when "' + x + '" appears soon after the match',
        change: 'Add after the last match: content:!"' + IDS.escapeContent(x) + '"; ' + (nocase ? 'nocase; ' : '') + 'distance:' + dist + '; within:' + within + ';',
        why: ['"' + x + '" follows the match in ' + coverage + ', ' + gmin + (gmin === gmax ? '' : ' to ' + gmax) + ' bytes after it.', 'Simple to read and to deploy, but any request that has "' + x + '" in that window is skipped, whatever else it contains.'],
        apply: negContent(dist, within) }), notes, attackText));

      // 3. Anywhere in the value: the loosest form, offered so the cost is visible.
      recs.push(finish(Object.assign({}, common, {
        id: 'pay-x-' + id, mode: 'anywhere', risk: 'high',
        title: 'Skip when "' + x + '" appears anywhere in ' + bufLabel,
        change: 'Add after the last match: content:!"' + IDS.escapeContent(x) + '"; ' + (nocase ? 'nocase; ' : '') + '(searches all of ' + bufLabel + ')',
        why: ['The broadest form. Any request with "' + x + '" anywhere in ' + bufLabel + ' is skipped.'],
        apply: negContent(null, null) }), notes, attackText));

      return { locked: false, recs: recs, notes: notes };
    };

    self.opportunities = function () { return Y.opportunities(fpAlerts); };
    self.views = function (limit) { return Y.views(fpAlerts, limit); };
    self.defaultAttack = function () { return Y.defaultAttack(rule); };
    self.tpViews = function (limit) { return Y.views(tpAlerts, limit); };
    return self;
  };
})();
