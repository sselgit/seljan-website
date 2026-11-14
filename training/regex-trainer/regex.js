/* Regex Trainer. Runs entirely in the browser. No network, no storage. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }

  var st = { ex: [], pending: null, hintN: 0, revealed: false };
  var PRESETS = {
    web: '192.168.1.15 - - [14/Nov/2026:10:22:31 +0000] "GET /login HTTP/1.1" 200 512\n10.0.0.7 - - [14/Nov/2026:10:22:35 +0000] "POST /api/token HTTP/1.1" 401 87\n203.0.113.9 - - [14/Nov/2026:10:23:02 +0000] "GET /admin HTTP/1.1" 403 199\n192.168.1.15 - - [14/Nov/2026:10:23:40 +0000] "GET /home HTTP/1.1" 200 2048',
    contacts: 'Alice <alice@example.com>, Bob <bob.smith@corp.example.org>\nCall Carol on 555-123-4567 or Dave on (555) 987-6543.\nBackup contact: ERIN@EXAMPLE.NET (urgent only).',
    win: 'EventID=4625 Account=CORP\\jdoe SourceIP=198.51.100.23 LogonType=3\nEventID=4624 Account=CORP\\asmith SourceIP=10.1.2.3 LogonType=2\nEventID=4625 Account=CORP\\guest SourceIP=203.0.113.77 LogonType=10\nEventID=4672 Account=CORP\\admin SourceIP=- LogonType=2'
  };

  /* ---------- basic helpers ---------- */
  function esc(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\n/g, '\\n').replace(/\t/g, '\\t').replace(/\r/g, '\\r');
  }
  function tokens(s) {
    var out = [], re = /\d+|[A-Za-z]+|\s+|[\s\S]/g, m;
    while ((m = re.exec(s))) {
      var v = m[0];
      out.push({ k: /^\d/.test(v) ? 'd' : /^[A-Za-z]/.test(v) ? 'a' : /^\s/.test(v) ? 's' : 'p', v: v });
    }
    return out;
  }
  function sig(t) { return t.map(function (x) { return x.k === 'p' ? 'p' + x.v : x.k; }).join(','); }
  function isWord(c) { return !!c && /\w/.test(c); }
  function getFlags() {
    var f = '';
    document.querySelectorAll('#flags input').forEach(function (i) { if (i.checked) f += i.dataset.f; });
    return f;
  }
  function allMatches(re, text) {
    var out = [];
    if (!re) return out;
    var g = new RegExp(re.source, re.flags.indexOf('g') >= 0 ? re.flags : re.flags + 'g');
    var m, n = 0;
    while ((m = g.exec(text)) && n < 5000) {
      out.push({ s: m.index, e: m.index + m[0].length, t: m[0] });
      if (m[0] === '') g.lastIndex++;
      n++;
    }
    return out;
  }
  function risky(src) { return /\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/.test(src); }

  /* ---------- known patterns ---------- */
  var KNOWN = [
    { n: 'an IPv4 address', re: '(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)', b: true },
    { n: 'an email address', re: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', b: false },
    { n: 'an ISO date (YYYY-MM-DD)', re: '\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])', b: true },
    { n: 'a time (HH:MM:SS)', re: '(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d', b: true },
    { n: 'a MAC address', re: '(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', b: true },
    { n: 'an MD5 hash', re: '[a-fA-F0-9]{32}', b: true },
    { n: 'a SHA-1 hash', re: '[a-fA-F0-9]{40}', b: true },
    { n: 'a SHA-256 hash', re: '[a-fA-F0-9]{64}', b: true },
    { n: 'a UUID', re: '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', b: true },
    { n: 'a URL', re: 'https?://[^\\s"\'<>]+', b: false },
    { n: 'a CVE ID', re: 'CVE-\\d{4}-\\d{4,}', b: true, i: true },
    { n: 'a US phone number', re: '(?:\\(\\d{3}\\)\\s?|\\d{3}[-.\\s])\\d{3}[-.]\\d{4}', b: false },
    { n: 'a domain name', re: '(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}', b: true }
  ];
  function identify(strs) {
    for (var i = 0; i < KNOWN.length; i++) {
      var k = KNOWN[i], full = new RegExp('^(?:' + k.re + ')$', k.i ? 'i' : '');
      if (strs.every(function (s) { return full.test(s); })) return k;
    }
    return null;
  }

  /* ---------- inference ---------- */
  function buildGroup(g, level, skel) {
    var src = '', needI = false, n = g[0].length;
    for (var i = 0; i < n; i++) {
      var k = g[0][i].k;
      var vals = g.map(function (t) { return t[i].v; });
      if (k === 'p') { src += esc(vals[0]); continue; }
      var lens = vals.map(function (v) { return v.length; });
      var mn = Math.min.apply(null, lens), mx = Math.max.apply(null, lens);
      var q = function (cls) {
        if (skel) return cls + '{__}';
        if (level === 3) return cls + '+';
        if (mn === mx) return mn === 1 ? cls : cls + '{' + mn + '}';
        return cls + '{' + mn + ',' + mx + '}';
      };
      if (k === 'd') { src += q('\\d'); continue; }
      if (k === 's') { src += (level < 3 && mn === 1 && mx === 1) ? '\\s' : '\\s+'; continue; }
      var same = vals.every(function (v) { return v === vals[0]; });
      var sameCI = vals.every(function (v) { return v.toLowerCase() === vals[0].toLowerCase(); });
      if (level < 3 && same) { src += esc(vals[0]); continue; }
      if (level < 3 && sameCI) { src += esc(vals[0].toLowerCase()); needI = true; continue; }
      var up = vals.every(function (v) { return v === v.toUpperCase(); });
      var lo = vals.every(function (v) { return v === v.toLowerCase(); });
      src += q(up ? '[A-Z]' : lo ? '[a-z]' : '[A-Za-z]');
    }
    return { src: src, needI: needI };
  }
  function infer(strs, level, skel) {
    var ci = new Set(strs.map(function (s) { return s.toLowerCase(); })).size < new Set(strs).size;
    if (level === 1) {
      var base = ci ? strs.map(function (s) { return s.toLowerCase(); }) : strs;
      var u = Array.from(new Set(base)).sort(function (a, b) { return b.length - a.length; });
      var j = u.map(esc).join('|');
      return { src: u.length > 1 ? '(?:' + j + ')' : j, needI: ci };
    }
    var toks = strs.map(tokens), groups = new Map();
    toks.forEach(function (t) { var k = sig(t); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(t); });
    if (groups.size > 4) {
      return { src: strs.some(function (s) { return /\s/.test(s); }) ? '[^\\n]+' : '\\S+', needI: false, fallback: true };
    }
    var parts = [], needI = false;
    groups.forEach(function (g) { var r = buildGroup(g, level, skel); parts.push(r.src); needI = needI || r.needI; });
    var uniq = Array.from(new Set(parts));
    return { src: uniq.length > 1 ? '(?:' + uniq.join('|') + ')' : uniq[0], needI: needI, groups: groups, fallback: false };
  }

  /* ---------- flags advice ---------- */
  function flagAdvice(yesStrs, inf) {
    var text = $('sample').value, anchor = $('anchor').checked;
    var has = yesStrs.length > 0;
    var multiline = text.indexOf('\n') >= 0;
    return [
      { f: 'g', name: 'g  (global)', rec: true, why: 'Finds every match instead of stopping at the first one. You almost always want this when scanning logs.' },
      { f: 'i', name: 'i  (ignore case)', rec: has && !!inf && inf.needI,
        why: has ? (inf && inf.needI ? 'Your highlighted examples differ only in upper and lower case, so the pattern must ignore case.' : 'Your examples do not differ by case, so you can leave this off. Turn it on if you also want "ABC" to match "abc".') : 'Needed when the same word appears in different cases, like GET and get.' },
      { f: 'm', name: 'm  (multiline)', rec: has && anchor && multiline,
        why: anchor ? 'You asked for whole-line matches. With several lines, m lets ^ and $ match at every line, not just the start and end of the whole text.' : 'Only matters when you use ^ or $. It makes them work per line.' },
      { f: 's', name: 's  (dot matches newline)', rec: has && yesStrs.some(function (s) { return s.indexOf('\n') >= 0; }),
        why: 'Lets . match line breaks. Needed only if one match spans several lines and your pattern uses a dot.' },
      { f: 'u', name: 'u  (unicode)', rec: has && yesStrs.some(function (s) { return /[^\x00-\x7f]/.test(s); }),
        why: 'Treats text as Unicode, so emoji and accented letters count as single characters. Not needed for plain English text.' }
    ];
  }
  function recFlags(adv) { return adv.filter(function (a) { return a.rec; }).map(function (a) { return a.f; }).join(''); }

  /* ---------- coach ---------- */
  function commonSuffix(arr) { if (!arr.length) return ''; var s = arr[0]; arr.forEach(function (a) { while (s && !a.endsWith(s)) s = s.slice(1); }); return s; }
  function commonPrefix(arr) { if (!arr.length) return ''; var s = arr[0]; arr.forEach(function (a) { while (s && !a.startsWith(s)) s = s.slice(0, -1); }); return s; }

  function evaluate(src, flags) {
    var re;
    try { re = new RegExp(src, flags); } catch (e) { return { error: e.message }; }
    var text = $('sample').value, ms = allMatches(re, text), rows = [], yesOK = 0, noHit = 0;
    st.ex.forEach(function (k) {
      var over = ms.filter(function (m) { return m.s < k.e && m.e > k.s && m.e > m.s; });
      if (k.kind === 'yes') {
        var exact = ms.some(function (m) { return m.s === k.s && m.e === k.e; });
        if (exact) yesOK++;
        rows.push({ k: k, status: exact ? 'pass' : over.length ? 'partial' : 'miss', got: over[0] ? over[0].t : '' });
      } else {
        if (over.length) noHit++;
        rows.push({ k: k, status: over.length ? 'hit' : 'pass', got: over[0] ? over[0].t : '' });
      }
    });
    var extra = ms.filter(function (m) { return m.e > m.s && !st.ex.some(function (k) { return k.kind === 'yes' && m.s < k.e && m.e > k.s; }); });
    return { ms: ms, rows: rows, yesOK: yesOK, noHit: noHit, extra: extra };
  }

  function coach() {
    var text = $('sample').value;
    var yes = st.ex.filter(function (k) { return k.kind === 'yes'; });
    if (!yes.length) return null;
    var strs = yes.map(function (k) { return text.slice(k.s, k.e); });
    var level = +$('level').value, anchor = $('anchor').checked;
    var inf = infer(strs, level, false);
    var adv = flagAdvice(strs, inf);
    var flags = recFlags(adv);
    var pre = '', post = '', notes = [];
    var bounded = yes.every(function (k) {
      var a = text[k.s], b = text[k.e - 1];
      return isWord(a) && isWord(b) && !isWord(text[k.s - 1]) && !isWord(text[k.e]);
    });
    if (anchor) { pre = '^'; post = '$'; }
    else if (bounded) { pre = '\\b'; post = '\\b'; notes.push('\\b was added so the match must start and end at a word edge. That stops it matching inside longer words or numbers.'); }
    var src = pre + inf.src + post;
    var ev = evaluate(src, flags);
    if (!ev.error && ev.noHit > 0 && !anchor) {
      var before = commonSuffix(yes.map(function (k) { return text.slice(Math.max(0, k.s - 6), k.s); }));
      var after = commonPrefix(yes.map(function (k) { return text.slice(k.e, k.e + 6); }));
      var cands = [];
      if (before) cands.push({ s: '(?<=' + esc(before) + ')' + src, why: 'preceded by ' + JSON.stringify(before) });
      if (after) cands.push({ s: src + '(?=' + esc(after) + ')', why: 'followed by ' + JSON.stringify(after) });
      if (before && after) cands.push({ s: '(?<=' + esc(before) + ')' + src + '(?=' + esc(after) + ')', why: 'between ' + JSON.stringify(before) + ' and ' + JSON.stringify(after) });
      for (var i = 0; i < cands.length; i++) {
        var e2 = evaluate(cands[i].s, flags);
        if (!e2.error && e2.noHit === 0 && e2.yesOK === ev.yesOK) {
          src = cands[i].s; ev = e2;
          notes.push('Your "should not match" examples were being matched too, so context was added: the match must be ' + cands[i].why + '. That is a lookaround. It checks the surroundings without including them in the match.');
          break;
        }
      }
      if (ev.noHit > 0) notes.push('This pattern still matches something you marked as "should not". Try highlighting more examples of both kinds so the difference becomes clear.');
    }
    return { src: src, flags: flags, adv: adv, inf: inf, strs: strs, notes: notes, level: level, pre: pre, post: post };
  }

  function describeShape(strs) {
    var inf = infer(strs, 2, false);
    if (inf.fallback) return 'Your examples are quite different from each other. Try highlighting fewer, more similar ones first.';
    var words = { d: 'digits', a: 'letters', s: 'whitespace' };
    var out = [];
    inf.groups.forEach(function (g) {
      out.push(g[0].map(function (t) { return t.k === 'p' ? '"' + t.v + '"' : words[t.k]; }).join(' then '));
    });
    return (out.length > 1 ? 'Your examples come in ' + out.length + ' shapes. ' : 'Every example has the same shape. ') +
      out.map(function (o, i) { return (out.length > 1 ? 'Shape ' + (i + 1) + ': ' : 'It goes: ') + o + '.'; }).join(' ');
  }
  function blocksHint(strs) {
    var kinds = {}, specials = [];
    strs.forEach(function (s) { tokens(s).forEach(function (t) {
      kinds[t.k] = true;
      if (t.k === 'p' && /[.*+?^${}()|[\]\\]/.test(t.v) && specials.indexOf(t.v) < 0) specials.push(t.v);
    }); });
    var h = [];
    if (kinds.d) h.push('\\d matches one digit. Add {3} for exactly three, {1,3} for one to three, or + for one or more.');
    if (kinds.a) h.push('[A-Za-z] matches one letter. Plain letters that never change can simply be typed as they are.');
    if (kinds.s) h.push('\\s matches a space, tab or line break.');
    specials.slice(0, 3).forEach(function (c) { h.push('The character ' + c + ' has a special meaning in regex. To match it literally, put a backslash before it: \\' + c); });
    if (!h.length) h.push('Everything here is plain text, so you can type it as it is.');
    return h.join(' ');
  }
  function hintList(c) {
    var skel = infer(c.strs, 2, true).src;
    return [
      describeShape(c.strs),
      blocksHint(c.strs),
      'Fill in the blanks (the __ parts): ' + c.pre + skel + c.post
    ];
  }

  /* ---------- explain ---------- */
  function describeClass(cls) {
    var inner = cls.slice(1, -1).replace(/^\^/, '');
    return inner.replace(/\\d/g, '0-9 (digits)').replace(/\\w/g, 'letters, digits, _').replace(/\\s/g, 'whitespace').replace(/\\(.)/g, '$1').replace(/(.)-(.)/g, '$1 to $2');
  }
  function explain(src) {
    var out = [], i = 0;
    var E = { d: 'a digit (0 to 9)', D: 'anything except a digit', w: 'a letter, digit or underscore', W: 'anything except a letter, digit or underscore', s: 'whitespace (space, tab, line break)', S: 'anything except whitespace', b: 'a word edge (between a word character and a non-word character)', B: 'a spot that is not a word edge', n: 'a line break', t: 'a tab', r: 'a carriage return' };
    function add(t, m, lit) { out.push({ t: t, m: m, lit: !!lit }); }
    while (i < src.length) {
      var c = src[i], rest = src.slice(i), m;
      if (c === '\\') { var n = src[i + 1]; if (n === undefined) { add('\\', 'a stray backslash'); i++; } else { add('\\' + n, E[n] || ('the character ' + n)); i += 2; } continue; }
      if (c === '[') {
        var j = i + 1; if (src[j] === '^') j++; if (src[j] === ']') j++;
        while (j < src.length && src[j] !== ']') { if (src[j] === '\\') j++; j++; }
        var cls = src.slice(i, j + 1);
        add(cls, (cls[1] === '^' ? 'any ONE character that is not: ' : 'any ONE character from: ') + describeClass(cls)); i = j + 1; continue;
      }
      if (c === '(') {
        m = /^\((\?<=|\?<!|\?=|\?!|\?:|\?<[A-Za-z_]\w*>)?/.exec(rest);
        var g = m[1] || '';
        var mean = { '?:': 'start of a group (not remembered)', '?=': 'lookahead: what follows must be...', '?!': 'negative lookahead: what follows must NOT be...', '?<=': 'lookbehind: what comes before must be...', '?<!': 'negative lookbehind: what comes before must NOT be...', '': 'start of a capture group (remembers what it matched)' }[g] || 'start of a named capture group';
        add(m[0], mean); i += m[0].length; continue;
      }
      if (c === ')') { add(')', 'end of group'); i++; continue; }
      if (c === '|') { add('|', 'OR: the left side or the right side'); i++; continue; }
      if (c === '^') { add('^', 'start of the text (or of each line with the m flag)'); i++; continue; }
      if (c === '$') { add('$', 'end of the text (or of each line with the m flag)'); i++; continue; }
      if (c === '.') { add('.', 'any one character except a line break'); i++; continue; }
      m = /^(\*|\+|\?|\{\d+(?:,\d*)?\})(\?)?/.exec(rest);
      if (m) {
        var q = m[1], d = q === '*' ? 'zero or more times' : q === '+' ? 'one or more times' : q === '?' ? 'optional (zero or one time)' :
          (function () { var p = q.slice(1, -1).split(','); return p.length === 1 ? 'exactly ' + p[0] + ' times' : (p[1] === '' ? p[0] + ' or more times' : p[0] + ' to ' + p[1] + ' times'); })();
        add(m[0], 'repeat the previous part ' + d + (m[2] ? ', as few as possible (lazy)' : '')); i += m[0].length; continue;
      }
      add(c, 'the character ' + (c === ' ' ? '(space)' : c), true); i++;
    }
    var merged = [];
    out.forEach(function (o) {
      var last = merged[merged.length - 1];
      if (o.lit && last && last.lit) { last.t += o.t; last.m = 'the text "' + last.t + '"'; }
      else merged.push(o);
    });
    return merged;
  }

  /* ---------- snippets ---------- */
  function snippets(src, flags) {
    var f = flags.replace('g', '');
    var py = []; if (f.indexOf('i') >= 0) py.push('re.I'); if (f.indexOf('m') >= 0) py.push('re.M'); if (f.indexOf('s') >= 0) py.push('re.S');
    var ps = []; if (f.indexOf('i') >= 0) ps.push('IgnoreCase'); if (f.indexOf('m') >= 0) ps.push('Multiline'); if (f.indexOf('s') >= 0) ps.push('Singleline');
    var pyq = src.indexOf("'") < 0 ? "r'" + src + "'" : (src.indexOf('"') < 0 ? 'r"' + src + '"' : "r'''" + src + "'''");
    return [
      ['JavaScript', 'const re = /' + src.replace(/\//g, '\\/') + '/' + flags + ';\nconst found = text.match(re);'],
      ['Python', 'import re\nfound = re.findall(' + pyq + ', text' + (py.length ? ', ' + py.join(' | ') : '') + ')'],
      ['grep (Linux/macOS, PCRE)', "grep -o" + (f.indexOf('i') >= 0 ? 'i' : '') + "P '" + src.replace(/'/g, "'\\''") + "' file.txt"],
      ['PowerShell', "[regex]::Matches($text, '" + src.replace(/'/g, "''") + "'" + (ps.length ? ", '" + ps.join(', ') + "'" : '') + ') | ForEach-Object Value']
    ];
  }

  /* ---------- rendering ---------- */
  function activeRegex(c) {
    var mine = $('mine').value;
    if (mine) return { src: mine, flags: getFlags(), who: 'yours' };
    if (st.revealed && c) return { src: c.src, flags: c.flags, who: 'coach' };
    return null;
  }

  function renderView(act) {
    var text = $('sample').value, view = $('view');
    view.replaceChildren();
    if (!text) { view.append(el('span', 'rx-muted', 'Your text appears here once you paste it above.')); return; }
    var ms = [];
    if (act && !(act.who === 'yours' && risky(act.src))) {
      try { ms = allMatches(new RegExp(act.src, act.flags), text).filter(function (m) { return m.e > m.s; }); } catch (e) { ms = []; }
    }
    var pts = new Set([0, text.length]);
    st.ex.forEach(function (k) { pts.add(k.s); pts.add(k.e); });
    ms.forEach(function (m) { pts.add(m.s); pts.add(m.e); });
    var arr = Array.from(pts).sort(function (a, b) { return a - b; });
    for (var i = 0; i < arr.length - 1; i++) {
      var a = arr[i], b = arr[i + 1];
      if (a === b) continue;
      var cls = [];
      if (ms.some(function (m) { return m.s <= a && m.e >= b; })) cls.push('hit');
      st.ex.forEach(function (k) { if (k.s <= a && k.e >= b) cls.push(k.kind); });
      view.append(el('span', cls.join(' '), text.slice(a, b)));
    }
  }

  function renderChips() {
    var text = $('sample').value, box = $('chips');
    box.replaceChildren();
    st.ex.forEach(function (k, idx) {
      var c = el('span', 'rx-chip ' + k.kind);
      c.append(el('span', null, (k.kind === 'yes' ? '✓ ' : '✗ ') + text.slice(k.s, k.e).replace(/\n/g, '↵')));
      var x = el('button', null, '×'); x.type = 'button'; x.setAttribute('aria-label', 'Remove');
      x.addEventListener('click', function () { st.ex.splice(idx, 1); update(); });
      c.append(x); box.append(c);
    });
  }

  function renderFlags(adv) {
    var box = $('flags'), keep = {};
    box.querySelectorAll('input').forEach(function (i) { keep[i.dataset.f] = i.checked; });
    var first = !box.children.length;
    box.replaceChildren();
    adv.forEach(function (a) {
      var row = el('label', 'rx-flag');
      var cb = el('input'); cb.type = 'checkbox'; cb.dataset.f = a.f;
      cb.checked = first ? a.f === 'g' : !!keep[a.f];
      cb.addEventListener('change', update);
      var nm = el('span', 'nm', a.name);
      nm.append(el('span', 'badge ' + (a.rec ? 'rec' : 'opt'), a.rec ? 'recommended' : 'optional'));
      row.append(cb, nm, el('span', 'why', a.why));
      box.append(row);
    });
  }

  function renderFlagMsg(adv) {
    var have = getFlags(), msgs = [];
    adv.forEach(function (a) {
      var on = have.indexOf(a.f) >= 0;
      if (a.rec && !on) msgs.push('You probably need ' + a.f + ': ' + a.why);
      if (!a.rec && on && a.f !== 'g' && st.ex.length) msgs.push(a.f + ' is ticked but not needed for your examples. It is harmless here, but only add flags you can explain.');
    });
    $('flagmsg').textContent = msgs.join(' ');
  }

  function renderScore(act) {
    var box = $('score'), err = $('err');
    box.replaceChildren(); err.hidden = true;
    if (!act) return;
    if (act.who === 'yours') {
      try { new RegExp(act.src, act.flags); } catch (e) { err.textContent = 'This is not a valid regex yet: ' + e.message; err.hidden = false; return; }
      if (risky(act.src)) { err.textContent = 'This pattern repeats a repeat, like (a+)+. That can freeze a computer on some inputs, so the page will not run it. Rewrite it with a simpler shape.'; err.hidden = false; return; }
    }
    var ev = evaluate(act.src, act.flags.indexOf('g') >= 0 ? act.flags : act.flags + 'g');
    if (ev.error) return;
    var head = el('p', null, (act.who === 'coach' ? 'The coach\'s regex' : 'Your regex') + ' found ' + ev.ms.filter(function (m) { return m.e > m.s; }).length + ' match(es) in the sample.');
    box.append(head);
    if (st.ex.length) {
      var ul = el('ul', 'rx-res');
      ev.rows.forEach(function (r) {
        var li = el('li'), t = $('sample').value.slice(r.k.s, r.k.e);
        var ok = r.status === 'pass';
        li.append(el('span', ok ? 'ok' : 'bad', ok ? '✓' : '✗'));
        var msg = r.k.kind === 'yes'
          ? (ok ? 'matched exactly' : r.status === 'partial' ? 'matched the wrong amount: it found "' + r.got.replace(/\n/g, '↵') + '" instead' : 'was not matched')
          : (ok ? 'correctly left alone' : 'was matched but should not be');
        var code = el('code', null, t.replace(/\n/g, '↵'));
        li.append(code, el('span', null, msg));
        ul.append(li);
      });
      box.append(ul);
    }
    if (ev.extra.length) {
      var ex = ev.extra.slice(0, 5).map(function (m) { return '"' + m.t.replace(/\n/g, '↵') + '"'; }).join(', ');
      box.append(el('p', 'rx-muted', 'It also matches ' + ev.extra.length + ' other place(s) you did not highlight, such as ' + ex + '. Check they are what you want. They show in blue above.'));
    }
  }

  function renderUse(act) {
    var warn = $('warn'), ex = $('explain'), sn = $('snips');
    warn.replaceChildren(); ex.replaceChildren(); sn.replaceChildren();
    if (!act) {
      ex.append(el('p', 'rx-muted', 'Type a regex or reveal the coach\'s version to see it explained.'));
      sn.append(el('p', 'rx-muted', 'Appears once there is a regex to show.')); return;
    }
    if (risky(act.src)) warn.append(el('div', 'rx-warn', 'Warning: a repeat inside a repeat, like (a+)+, can make a regex run for a very long time on some text (called catastrophic backtracking).'));
    if (/(^|[^\\])\.[*+]/.test(act.src)) warn.append(el('div', 'rx-warn', 'Tip: .* and .+ grab as much as possible and can swallow more than you intend. A narrower class like [^"]+ or a lazy .+? is usually safer.'));
    var tbl = el('table');
    explain(act.src).forEach(function (p) { var tr = el('tr'); tr.append(el('td', null, p.t), el('td', null, p.m)); tbl.append(tr); });
    ex.append(tbl);
    snippets(act.src, act.flags).forEach(function (s) { sn.append(el('div', 'rx-lang', s[0]), el('pre', 'rx-code', s[1])); });
  }

  function update() {
    var c = coach(), yesStrs = [];
    var text = $('sample').value;
    yesStrs = st.ex.filter(function (k) { return k.kind === 'yes'; }).map(function (k) { return text.slice(k.s, k.e); });
    var inf = yesStrs.length ? infer(yesStrs, +$('level').value, false) : null;
    var adv = flagAdvice(yesStrs, inf);
    renderFlags(adv); renderFlagMsg(adv);
    renderChips();

    var ident = $('ident');
    var known = yesStrs.length ? identify(yesStrs) : null;
    ident.replaceChildren();
    if (known) {
      ident.hidden = false;
      ident.append(el('p', null, 'These look like ' + known.n + '. There is a well-tested standard pattern for that.'));
      var b = el('button', 'btn btn-small btn-ghost', 'Use the standard pattern'); b.type = 'button';
      b.addEventListener('click', function () {
        $('mine').value = (known.b ? '\\b' : '') + known.re + (known.b ? '\\b' : '');
        if (known.i) { var ci = document.querySelector('#flags input[data-f="i"]'); if (ci) ci.checked = true; }
        update();
      });
      ident.append(b);
    } else ident.hidden = true;

    var hb = $('hint-btn'), rb = $('reveal-btn');
    var hints = c ? hintList(c) : [];
    hb.disabled = !c || st.hintN >= hints.length;
    hb.textContent = !c ? 'Highlight an example first' : st.hintN >= hints.length ? 'No more hints' : st.hintN ? 'Another hint' : 'Give me a hint';
    rb.disabled = !c;
    var hbox = $('hints'); hbox.replaceChildren();
    for (var i = 0; i < Math.min(st.hintN, hints.length); i++) {
      var d = el('div', 'rx-hint'); d.append(el('b', null, 'Hint ' + (i + 1) + ' of ' + hints.length + ': ')); d.append(document.createTextNode(hints[i])); hbox.append(d);
    }
    var rv = $('reveal'); rv.replaceChildren();
    if (st.revealed && c) {
      rv.hidden = false;
      rv.append(el('div', 'rx-muted', 'The coach\'s answer, with flags: ' + (c.flags || 'none')), el('pre', 'rx-code', '/' + c.src + '/' + c.flags));
      c.notes.forEach(function (n) { rv.append(el('p', 'rx-muted', n)); });
      var ua = el('button', 'btn btn-small btn-ghost', 'Copy into my box and set the flags'); ua.type = 'button';
      ua.addEventListener('click', function () {
        $('mine').value = c.src;
        document.querySelectorAll('#flags input').forEach(function (i) { i.checked = c.flags.indexOf(i.dataset.f) >= 0; });
        update();
      });
      rv.append(ua);
    } else rv.hidden = true;

    var act = activeRegex(c);
    renderView(act); renderScore(act); renderUse(act);
  }

  /* ---------- selection ---------- */
  function readSelection() {
    var sel = window.getSelection(), view = $('view');
    if (!sel || !sel.rangeCount || sel.isCollapsed) return;
    var r = sel.getRangeAt(0);
    if (!view.contains(r.commonAncestorContainer)) return;
    var pre = document.createRange(); pre.selectNodeContents(view); pre.setEnd(r.startContainer, r.startOffset);
    var s = pre.toString().length, raw = r.toString(), e = s + raw.length;
    var text = $('sample').value;
    while (s < e && /\s/.test(text[s])) s++;
    while (e > s && /\s/.test(text[e - 1])) e--;
    if (e <= s) return;
    st.pending = { s: s, e: e };
    $('seltext').textContent = text.slice(s, e).replace(/\n/g, '↵');
    $('selbar').hidden = false;
  }
  function mark(kind) {
    var p = st.pending; if (!p) return;
    st.ex = st.ex.filter(function (k) { return !(k.s < p.e && k.e > p.s); });
    st.ex.push({ s: p.s, e: p.e, kind: kind });
    st.ex.sort(function (a, b) { return a.s - b.s; });
    st.pending = null; $('selbar').hidden = true;
    var sel = window.getSelection(); if (sel) sel.removeAllRanges();
    update();
  }
  function resetExamples() { st.ex = []; st.pending = null; $('selbar').hidden = true; st.hintN = 0; st.revealed = false; }

  /* ---------- wiring ---------- */
  $('view').addEventListener('mouseup', function () { setTimeout(readSelection, 0); });
  $('view').addEventListener('touchend', function () { setTimeout(readSelection, 50); });
  $('view').addEventListener('keyup', readSelection);
  $('mark-yes').addEventListener('click', function () { mark('yes'); });
  $('mark-no').addEventListener('click', function () { mark('no'); });
  $('sample').addEventListener('input', function () { resetExamples(); update(); });
  $('mine').addEventListener('input', update);
  $('level').addEventListener('change', function () { st.hintN = 0; update(); });
  $('anchor').addEventListener('change', update);
  $('hint-btn').addEventListener('click', function () { st.hintN++; update(); });
  $('reveal-btn').addEventListener('click', function () {
    st.revealed = true;
    var c = coach();
    if (c) document.querySelectorAll('#flags input').forEach(function (i) { i.checked = c.flags.indexOf(i.dataset.f) >= 0; });
    update();
  });
  document.querySelectorAll('[data-preset]').forEach(function (b) {
    b.addEventListener('click', function () { $('sample').value = PRESETS[b.dataset.preset]; $('mine').value = ''; resetExamples(); update(); });
  });
  $('clear-all').addEventListener('click', function () { $('sample').value = ''; $('mine').value = ''; $('anchor').checked = false; resetExamples(); update(); });

  update();
  window.__rx = { st: st, coach: coach, update: update, infer: infer, explain: explain, evaluate: evaluate };
})();
