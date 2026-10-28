// Rule tuner engine (SK.tuner): sanitize pasted text, parse logs, flag risky activity, propose narrow
// exclusions and write them in several rule formats. Pure functions: no network, no storage.
(function () {
  var SK = window.SK = window.SK || {};
  var X = SK.tuner = {};

  function escRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  X.escapeRegex = escRe;

  function lower(s) { return String(s || '').toLowerCase(); }
  function base(p) { var s = String(p || ''); return s.slice(Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/')) + 1); }
  X.basename = base;

  /* ---------------------------------------------------------------- sanitize */

  var IPV4_RE = /(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\d|\.\d)/g;
  var SAFE_USERS = { 'public': 1, 'default': 1, 'all users': 1, 'default user': 1, 'defaultuser0': 1 };

  function validV4(ip) {
    if (SK.net) return SK.net.parseIPv4(ip) !== null;
    return ip.split('.').every(function (o) { return +o <= 255; });
  }

  // Replaces IP addresses, email addresses, user-profile names and any extra terms with generic
  // placeholders. The same real value always gets the same placeholder, so patterns stay visible.
  // Returns { texts, map: [{type, original, placeholder}], counts }.
  X.sanitizeAll = function (texts, opts) {
    opts = opts || {};
    var map = [], ipMap = {}, v6Map = {}, mailMap = {}, userMap = {}, termMap = {};
    var counts = { ips: 0, emails: 0, users: 0, terms: 0 };

    // Placeholders from an earlier run stay as they are, and are never handed out again, so
    // running this twice cannot make two different real values share one placeholder.
    var placeholders = {};
    (opts.existing || []).forEach(function (e) {
      placeholders[e.placeholder] = true;
      var k = lower(e.original);
      if (e.type === 'IPv4 address') ipMap[e.original] = e.placeholder;
      else if (e.type === 'IPv6 address') v6Map[k] = e.placeholder;
      else if (e.type === 'Email address') mailMap[k] = e.placeholder;
      else if (e.type === 'Profile folder name') userMap[k] = e.placeholder;
      else if (e.type === 'Custom term') termMap[k] = e.placeholder;
    });

    // Do not hand out a placeholder that already appears as a real address in the text.
    var originals = {};
    texts.forEach(function (t) {
      String(t).replace(IPV4_RE, function (m, pre, ip) { if (!placeholders[ip]) originals[ip] = true; return m; });
    });
    var n4 = 0, n6 = Object.keys(v6Map).length + 1;
    function nextV4() {
      for (;;) {
        var i = n4++, c;
        if (i < 762) c = ['192.0.2.', '198.51.100.', '203.0.113.'][Math.floor(i / 254)] + (i % 254 + 1);
        else c = '198.18.' + (Math.floor((i - 762) / 254) % 256) + '.' + ((i - 762) % 254 + 1);
        if (!originals[c] && !placeholders[c]) return c;
      }
    }

    function record(type, original, placeholder) { map.push({ type: type, original: original, placeholder: placeholder }); }

    var terms = (opts.terms || []).map(function (t) { return String(t).trim(); }).filter(Boolean)
      .sort(function (a, b) { return b.length - a.length; });

    // Find profile-folder names first (C:\Users\name, also JSON-escaped C:\\Users\\name), so the same
    // name can be replaced everywhere it appears, such as in CORP\name.
    if (opts.users !== false) {
      texts.forEach(function (t) {
        String(t).replace(/(?:\\{1,2}Users\\{1,2}|\/home\/|\/Users\/)([^\\\/\s"'<>|:*?]+)/g, function (m, name) {
          var k = lower(name);
          if (SAFE_USERS[k] || /^USER\d+$/.test(name) || name.length < 3 || userMap[k]) return m;
          userMap[k] = 'USER' + (Object.keys(userMap).length + 1);
          record('Profile folder name', name, userMap[k]);
          counts.users++;
          return m;
        });
      });
    }

    function run(text) {
      var out = String(text);
      if (opts.emails !== false) {
        out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}/g, function (m) {
          if (placeholders[m]) return m;
          var k = lower(m);
          if (!mailMap[k]) { mailMap[k] = 'user' + (Object.keys(mailMap).length + 1) + '@example.com'; record('Email address', m, mailMap[k]); counts.emails++; }
          return mailMap[k];
        });
      }
      terms.forEach(function (term) {
        out = out.replace(new RegExp(escRe(term), 'gi'), function (m) {
          var k = lower(m);
          if (!termMap[k]) { termMap[k] = 'REDACTED-' + (Object.keys(termMap).length + 1); record('Custom term', m, termMap[k]); counts.terms++; }
          return termMap[k];
        });
      });
      if (opts.users !== false) {
        Object.keys(userMap).forEach(function (name) {
          out = out.replace(new RegExp('(^|[^A-Za-z0-9])' + escRe(name) + '(?![A-Za-z0-9])', 'gi'), function (m, pre) { return pre + userMap[name]; });
        });
      }
      if (opts.ips !== false) {
        out = out.replace(IPV4_RE, function (m, pre, ip) {
          if (!validV4(ip) || placeholders[ip]) return m;
          if (!ipMap[ip]) { ipMap[ip] = nextV4(); record('IPv4 address', ip, ipMap[ip]); counts.ips++; }
          return pre + ipMap[ip];
        });
        if (SK.net) {
          out = out.replace(/[0-9A-Fa-f:]{3,}/g, function (m) {
            if ((m.match(/:/g) || []).length < 2 || SK.net.parseIPv6(m) === null || placeholders[m]) return m;
            var k = lower(SK.net.ipv6Compress(SK.net.parseIPv6(m)));
            if (!v6Map[k]) { v6Map[k] = '2001:db8::' + (n6++).toString(16); record('IPv6 address', m, v6Map[k]); counts.ips++; }
            return v6Map[k];
          });
        }
      }
      return out;
    }
    return { texts: texts.map(run), map: map, counts: counts };
  };

  // Put the real values back (used only for output, in the page, on request).
  X.restore = function (text, map) {
    var out = String(text);
    map.slice().sort(function (a, b) { return b.placeholder.length - a.placeholder.length; }).forEach(function (e) {
      if (e.type === 'IPv4 address') {
        out = out.replace(new RegExp('(^|[^\\d.])' + escRe(e.placeholder) + '(?!\\d|\\.\\d)', 'g'), function (m, pre) { return pre + e.original; });
      } else {
        out = out.split(e.placeholder).join(e.original);
      }
    });
    return out;
  };

  /* ---------------------------------------------------------------- parse logs */

  function flatten(obj, prefix, out) {
    if (obj === null || obj === undefined) return;
    if (Array.isArray(obj)) {
      if (obj.every(function (x) { return x === null || typeof x !== 'object'; })) { out[prefix] = obj.join('; '); return; }
      obj.forEach(function (x, i) { flatten(x, prefix + '[' + i + ']', out); });
      return;
    }
    if (typeof obj === 'object') {
      Object.keys(obj).forEach(function (k) { flatten(obj[k], prefix ? prefix + '.' + k : k, out); });
      return;
    }
    out[prefix || 'value'] = String(obj);
  }

  function parseCsvLine(line, delim) {
    var out = [], cur = '', q = false;
    for (var i = 0; i < line.length; i++) {
      var c = line.charAt(i);
      if (q) {
        if (c === '"') { if (line.charAt(i + 1) === '"') { cur += '"'; i++; } else q = false; }
        else cur += c;
      } else if (c === '"') q = true;
      else if (c === delim) { out.push(cur); cur = ''; }
      else cur += c;
    }
    out.push(cur);
    return out;
  }

  // Auto-detects JSON, JSON lines, key=value, CSV/TSV, "Key: value" blocks, or plain lines.
  X.parseLogs = function (text, limit) {
    limit = limit || 5000;
    var src = String(text).replace(/\r\n?/g, '\n'), t = src.trim(), events = [], warnings = [], format = 'raw';
    if (!t) return { events: [], format: 'empty', warnings: [] };

    // JSON array or single object
    if (t.charAt(0) === '[' || t.charAt(0) === '{') {
      try {
        var parsed = JSON.parse(t);
        (Array.isArray(parsed) ? parsed : [parsed]).forEach(function (o) { var e = {}; flatten(o, '', e); events.push(e); });
        format = 'json';
      } catch (e) { events = []; }
    }
    // JSON lines
    if (!events.length && t.charAt(0) === '{') {
      var lines = t.split('\n').filter(function (l) { return l.trim(); }), ok = 0;
      lines.forEach(function (l) {
        try { var o = JSON.parse(l); var e = {}; flatten(o, '', e); events.push(e); ok++; } catch (err) { /* skip */ }
      });
      if (ok) { format = 'jsonl'; if (ok < lines.length) warnings.push((lines.length - ok) + ' line(s) were not valid JSON and were skipped.'); }
      else events = [];
    }
    // key=value
    if (!events.length) {
      var kvRe = /([A-Za-z_][\w.\-]*)=("([^"]*)"|'([^']*)'|[^\s,;]+)/g, kvEvents = [];
      src.split('\n').forEach(function (l) {
        var e = {}, m, n = 0;
        kvRe.lastIndex = 0;
        while ((m = kvRe.exec(l))) { e[m[1]] = m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : m[2]); n++; }
        if (n >= 2) kvEvents.push(e);
      });
      var nonEmpty = src.split('\n').filter(function (l) { return l.trim(); }).length;
      if (kvEvents.length && kvEvents.length >= nonEmpty * 0.6) { events = kvEvents; format = 'keyvalue'; }
    }
    // CSV / TSV
    if (!events.length) {
      var rows = src.split('\n').filter(function (l) { return l.trim(); });
      var delim = rows[0].indexOf('\t') >= 0 ? '\t' : (rows[0].indexOf(',') >= 0 ? ',' : null);
      if (delim && rows.length >= 2) {
        var head = parseCsvLine(rows[0], delim);
        if (head.length >= 2 && head.every(function (h) { return /^[\w .\-\/]{1,60}$/.test(h.trim()); })) {
          for (var r = 1; r < rows.length; r++) {
            var cells = parseCsvLine(rows[r], delim);
            if (cells.length < 2) continue;
            var ev = {};
            head.forEach(function (h, i) { ev[h.trim()] = cells[i] === undefined ? '' : cells[i]; });
            events.push(ev);
          }
          if (events.length) format = delim === '\t' ? 'tsv' : 'csv';
        }
      }
    }
    // "Key: value" blocks (Event Viewer / Sysmon text)
    if (!events.length) {
      var cur = {}, count = 0, blockEvents = [];
      src.split('\n').forEach(function (l) {
        var m = /^\s*([A-Za-z][\w .\-]{0,40}):\s+(.*)$/.exec(l);
        if (!l.trim()) { if (count) { blockEvents.push(cur); cur = {}; count = 0; } return; }
        if (m) {
          var key = m[1].trim();
          if (Object.prototype.hasOwnProperty.call(cur, key)) { blockEvents.push(cur); cur = {}; count = 0; }
          cur[key] = m[2].trim(); count++;
        }
      });
      if (count) blockEvents.push(cur);
      if (blockEvents.length && blockEvents.some(function (b) { return Object.keys(b).length >= 3; })) { events = blockEvents; format = 'blocks'; }
    }
    // plain lines
    if (!events.length) {
      src.split('\n').forEach(function (l) { if (l.trim()) events.push({ _raw: l.trim() }); });
      format = 'raw';
    }
    if (events.length > limit) { warnings.push('Only the first ' + limit + ' events were used.'); events = events.slice(0, limit); }
    return { events: events, format: format, warnings: warnings };
  };

  /* ---------------------------------------------------------------- roles */

  var VOLATILE = /(^|\.)(pid|ppid|processid|parentprocessid|threadid|logonid|sessionid|id|guid|processguid|parentprocessguid|logonguid|recordid|eventrecordid|utctime|timestamp|time|timecreated|date|@timestamp|_time)$/;

  // Which job does this field do? Returns a role name or null.
  X.roleOf = function (key) {
    var k = lower(key).replace(/[\s_\-]/g, ''), leaf = k.slice(k.lastIndexOf('.') + 1);
    if (VOLATILE.test(k) || /(^|\.)(processid|parentprocessid)$/.test(k)) return null;
    if (/^(parent|creator)/.test(leaf) || /(^|\.)(parent|principal\.process)/.test(k) && !/target/.test(k)) {
      if (/commandline|cmdline|args/.test(leaf)) return 'parentCmd';
      if (/image|path|exe|name|file|fullpath/.test(leaf) && !/id$/.test(leaf)) return 'parentImage';
    }
    if (/commandline|cmdline/.test(leaf) || leaf === 'command') return 'cmd';
    if (/^(image|newprocessname|processname|processpath|exe|executable|fullpath)$/.test(leaf) || /(^|\.)(process\.executable|process\.name|target\.process\.file\.fullpath)$/.test(k)) return 'image';
    if (/^(user|username|subjectusername|targetusername|accountname|userid)$/.test(leaf) || /(^|\.)user\.name$/.test(k)) return 'user';
    if (/signer|publisher|signedby|company|vendor/.test(leaf)) return 'signer';
    if (/sha256|md5|sha1|imphash|^hashes?$/.test(leaf)) return 'hash';
    if (/^(computer|computername|hostname|host|devicename)$/.test(leaf) || /(^|\.)host\.name$/.test(k)) return 'host';
    if (/(src|source|client|principal).*ip|^ipaddress$|^sourceaddress$/.test(leaf)) return 'srcIp';
    if (/(dst|dest|destination|target).*ip|^destinationaddress$/.test(leaf)) return 'dstIp';
    return null;
  };

  // Picks one value and field name for each role from an event.
  X.rolesOf = function (ev) {
    var roles = {}, names = {};
    Object.keys(ev).forEach(function (key) {
      var r = X.roleOf(key);
      if (r && !roles[r] && String(ev[key]).trim() && ev[key] !== '-') { roles[r] = String(ev[key]); names[r] = key; }
    });
    return { values: roles, names: names };
  };

  /* ---------------------------------------------------------------- risk flags */

  var OFFICE = { 'winword.exe': 1, 'excel.exe': 1, 'powerpnt.exe': 1, 'outlook.exe': 1, 'msaccess.exe': 1, 'onenote.exe': 1, 'mspub.exe': 1, 'visio.exe': 1 };
  var BROWSERS = { 'chrome.exe': 1, 'msedge.exe': 1, 'firefox.exe': 1, 'iexplore.exe': 1, 'brave.exe': 1, 'opera.exe': 1 };
  var SHELLS = { 'cmd.exe': 1, 'powershell.exe': 1, 'pwsh.exe': 1, 'wscript.exe': 1, 'cscript.exe': 1, 'mshta.exe': 1, 'rundll32.exe': 1, 'regsvr32.exe': 1,
    'certutil.exe': 1, 'bitsadmin.exe': 1, 'msiexec.exe': 1, 'wmic.exe': 1, 'schtasks.exe': 1, 'curl.exe': 1, 'installutil.exe': 1, 'msbuild.exe': 1,
    'forfiles.exe': 1, 'odbcconf.exe': 1, 'regasm.exe': 1, 'regsvcs.exe': 1, 'cmstp.exe': 1 };
  var WRITABLE = /[\\\/](appdata|temp|tmp|downloads|users[\\\/]public|programdata|windows[\\\/]temp|\$recycle\.bin)[\\\/]/i;

  var RISK_TESTS = {
    'office-child': function (c) { return !!(OFFICE[lower(base(c.parent))] && SHELLS[lower(base(c.image))]); },
    'browser-child': function (c) { return !!(BROWSERS[lower(base(c.parent))] && SHELLS[lower(base(c.image))]); },
    'encoded-command': function (c) { return /(^|\s)-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+\/=]{16,}/i.test(c.cmd) || /frombase64string/i.test(c.cmd); },
    'download-cradle': function (c) { return /downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|invoke-restmethod|bitsadmin.*\/transfer|certutil.*-urlcache|\bcurl(\.exe)?\s.*https?:|\bwget\s.*https?:/i.test(c.cmd); },
    'invoke-expression': function (c) { return /\binvoke-expression\b|(^|[\s;|(])iex(\s|\()/i.test(c.cmd); },
    'hidden-bypass': function (c) { return /-w(indowstyle)?\s+h(idden)?\b/i.test(c.cmd) && /-nop(rofile)?\b|-ep\s+bypass|executionpolicy\s+bypass/i.test(c.cmd); },
    'writable-path': function (c) { return WRITABLE.test(c.image) || /[\\\/](appdata|temp|downloads|users[\\\/]public|programdata)[\\\/][^\s"']*\.(ps1|vbs|js|jse|hta|bat|cmd|exe|dll|scr)\b/i.test(c.cmd); },
    'lolbin-remote': function (c) { return /^(mshta|regsvr32|rundll32|msiexec)\.exe$/i.test(base(c.image)) && /https?:\/\/|javascript:|scrobj\.dll|vbscript:/i.test(c.cmd); },
    'credential-theft': function (c) { return /sekurlsa|mimikatz|lsadump|procdump.*lsass|comsvcs\.dll.*minidump|ntds\.dit|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)/i.test(c.cmd); },
    'persistence': function (c) { return /schtasks(\.exe)?.*\/create|reg(\.exe)?\s+add.*\\run(once)?\b|\bsc(\.exe)?\s+create\b.*binpath/i.test(c.cmd); },
    'recovery-tamper': function (c) { return /vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wevtutil(\.exe)?\s+(cl|clear-log)/i.test(c.cmd); },
    'remote-exec': function (c) { return /psexec|wmic.*\/node:|invoke-command|enter-pssession|\bwinrs\b/i.test(c.cmd + ' ' + c.image); },
    'svchost-oddity': function (c) {
      if (lower(base(c.image)) !== 'svchost.exe') return false;
      var badParent = c.parent && lower(base(c.parent)) !== 'services.exe';
      var badPath = c.image.indexOf('\\') >= 0 && !/\\windows\\(system32|syswow64)\\svchost\.exe$/i.test(c.image);
      return !!(badParent || badPath);
    },
    'double-extension': function (c) { return /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|lnk|com)\b/i.test(c.cmd + ' ' + c.image); },
    'very-long-command': function (c) { return c.cmd.length > 800; }
  };

  X.flagsFor = function (ev, roles) {
    var v = roles.values;
    var ctx = { image: v.image || '', parent: v.parentImage || '', cmd: v.cmd || '', raw: Object.keys(ev).map(function (k) { return ev[k]; }).join(' ') };
    if (!ctx.image && !ctx.cmd && ev._raw) { ctx.cmd = ev._raw; }
    var out = [];
    ((SK.tunerData && SK.tunerData.RISKS) || []).forEach(function (r) {
      var test = RISK_TESTS[r.id];
      if (test && test(ctx)) out.push(r);
    });
    return out;
  };

  /* ---------------------------------------------------------------- command line patterns */

  X.normalizeCmd = function (cmd) {
    return String(cmd)
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '{GUID}')
      .replace(/\b[0-9a-f]{16,}\b/gi, '{HEX}')
      .replace(/\d{4}-\d{2}-\d{2}(?:[T_ ]\d{2}[:.]\d{2}[:.]\d{2})?/g, '{DATE}')
      // Numbers that stand alone (job IDs, counters). Digits glued to letters (ps1, v2, x64) stay literal.
      .replace(/(^|[^A-Za-z0-9])\d+/g, '$1{NUM}');
  };

  function normalizedToRegex(norm) {
    return norm.split(/(\{GUID\}|\{HEX\}|\{DATE\}|\{NUM\})/).map(function (p) {
      if (p === '{GUID}') return '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
      if (p === '{HEX}') return '[0-9a-fA-F]{16,}';
      if (p === '{DATE}') return '\\d{4}-\\d{2}-\\d{2}(?:[T_ ]\\d{2}[:.]\\d{2}[:.]\\d{2})?';
      if (p === '{NUM}') return '\\d+';
      return escRe(p);
    }).join('');
  }

  // Longest common start of several strings, cut back to a word boundary.
  function commonPrefix(list) {
    var first = list[0], n = first.length, i, j;
    for (j = 1; j < list.length; j++) {
      var s = list[j], m = 0;
      while (m < n && m < s.length && lower(first.charAt(m)) === lower(s.charAt(m))) m++;
      n = m;
    }
    var shortest = list.reduce(function (a, s) { return Math.min(a, s.length); }, first.length);
    var p = first.slice(0, n);
    if (n < shortest) {
      for (i = p.length - 1; i > 0; i--) { if (' \\/="'.indexOf(p.charAt(i)) >= 0) { p = p.slice(0, i + 1); break; } }
      if (i === 0) p = '';
    }
    return p;
  }

  // Describes how safely a group of command lines can be matched.
  X.cmdPattern = function (cmds) {
    var uniq = {}; cmds.forEach(function (c) { uniq[c] = true; });
    var list = Object.keys(uniq);
    if (list.length === 1) return { type: 'exact', exact: list[0], prefix: list[0], regex: '^' + escRe(list[0]) + '$' };
    var norms = {}; list.forEach(function (c) { norms[X.normalizeCmd(c)] = true; });
    var nl = Object.keys(norms);
    if (nl.length === 1) return { type: 'pattern', prefix: commonPrefix(list), regex: '^' + normalizedToRegex(nl[0]) + '$', example: list[0] };
    var pre = commonPrefix(list);
    if (pre.length >= 12) return { type: 'prefix', prefix: pre, regex: '^' + escRe(pre), example: list[0] };
    return { type: 'none' };
  };

  /* ---------------------------------------------------------------- analysis */

  function condText(c) {
    var label = { parent: 'Parent program', image: 'Program', imageName: 'Program file name', cmd: 'Command line', user: 'User', signer: 'Signer', host: 'Host', line: 'Whole log line' }[c.role];
    var op = { equals: 'is exactly', startswith: 'starts with', regex: 'matches the pattern', endswith: 'ends with' }[c.op];
    return label + ' ' + op + ' ' + c.value;
  }
  X.condText = condText;

  // Analyze parsed events. Returns summary data and candidate exclusions.
  X.analyze = function (events) {
    var items = events.map(function (ev, i) {
      var roles = X.rolesOf(ev);
      return { i: i, ev: ev, roles: roles, v: roles.values, flags: X.flagsFor(ev, roles) };
    });
    var total = items.length;

    // Flag summary
    var flagMap = {};
    items.forEach(function (it) { it.flags.forEach(function (f) { (flagMap[f.id] = flagMap[f.id] || { risk: f, count: 0, examples: [] }); flagMap[f.id].count++; if (flagMap[f.id].examples.length < 2) flagMap[f.id].examples.push(it.i); }); });
    var flagged = Object.keys(flagMap).map(function (k) { return flagMap[k]; }).sort(function (a, b) { return (b.risk.sev === 'high') - (a.risk.sev === 'high') || b.count - a.count; });
    var flaggedEvents = items.filter(function (it) { return it.flags.length; }).length;

    // Field statistics
    var keys = {};
    events.forEach(function (ev) { Object.keys(ev).forEach(function (k) { keys[k] = true; }); });
    var fieldStats = Object.keys(keys).map(function (k) {
      var counts = {}, filled = 0;
      events.forEach(function (ev) { if (ev[k] !== undefined && String(ev[k]) !== '') { filled++; counts[ev[k]] = (counts[ev[k]] || 0) + 1; } });
      var vals = Object.keys(counts).map(function (v) { return { v: v, count: counts[v] }; }).sort(function (a, b) { return b.count - a.count; });
      return { key: k, role: X.roleOf(k), filled: filled, distinct: vals.length, top: vals.slice(0, 4) };
    }).sort(function (a, b) { return a.distinct - b.distinct; });

    // Field name per role (first one seen)
    var mapping = {};
    items.forEach(function (it) { Object.keys(it.roles.names).forEach(function (r) { if (!mapping[r]) mapping[r] = it.roles.names[r]; }); });

    var cands = [];
    function dangerFor(group) {
      var seen = {};
      group.forEach(function (it) { it.flags.forEach(function (f) { seen[f.id] = f; }); });
      return Object.keys(seen).map(function (k) { return seen[k]; });
    }
    function push(c) {
      c.coverage = c.items.length;
      c.ids = c.items.map(function (it) { return it.i; });
      c.dangers = dangerFor(c.items);
      c.blocked = c.dangers.length > 0;
      var writable = c.items.some(function (it) { return WRITABLE.test(it.v.image || ''); });
      if (writable) c.risk = 'high', c.reasons.push('The program runs from a folder users can write to, so an attacker could place a file there.');
      cands.push(c);
    }
    function group(list, keyFn) {
      var g = {};
      list.forEach(function (it) { var k = keyFn(it); (g[k] = g[k] || []).push(it); });
      return Object.keys(g).map(function (k) { return g[k]; });
    }

    // Level A: parent + program + command line (+ user / signer when they never vary)
    var withBoth = items.filter(function (it) { return it.v.image && it.v.parentImage; });
    group(withBoth, function (it) { return lower(it.v.parentImage) + '|' + lower(it.v.image); }).forEach(function (grp) {
      var first = grp[0].v;
      var conds = [{ role: 'parent', op: 'equals', value: first.parentImage }, { role: 'image', op: 'equals', value: first.image }];
      var reasons = [], risk = 'medium';
      var cmds = grp.map(function (it) { return it.v.cmd; });
      if (cmds.every(Boolean)) {
        var pat = X.cmdPattern(cmds);
        if (pat.type !== 'none') {
          if (pat.type === 'exact') conds.push({ role: 'cmd', op: 'equals', value: pat.exact });
          else if (pat.type === 'pattern') conds.push({ role: 'cmd', op: 'regex', value: pat.regex, prefix: pat.prefix, example: pat.example });
          else conds.push({ role: 'cmd', op: 'startswith', value: pat.prefix, regex: pat.regex });
          risk = pat.type === 'prefix' ? 'medium' : 'low';
          reasons.push(pat.type === 'prefix' ? 'The command line varies, so only its start is matched. Anything an attacker appends after that start would also be excluded.' : 'The command line is matched closely, so a different command from the same program would still alert.');
        } else {
          reasons.push('Command lines vary too much to match safely, so this uses the program paths only.');
        }
      }
      var users = {}; grp.forEach(function (it) { users[lower(it.v.user || '')] = it.v.user; });
      if (Object.keys(users).length === 1 && grp[0].v.user) conds.push({ role: 'user', op: 'equals', value: grp[0].v.user });
      var signers = {}; grp.forEach(function (it) { signers[lower(it.v.signer || '')] = it.v.signer; });
      if (Object.keys(signers).length === 1 && grp[0].v.signer) conds.push({ role: 'signer', op: 'equals', value: grp[0].v.signer });
      push({ level: conds.length > 2 ? 'strict' : 'path', title: base(first.parentImage) + ' starting ' + base(first.image), conds: conds, items: grp, risk: risk, reasons: reasons });
    });

    // Level B: program + command line when the parent is missing
    var noParent = items.filter(function (it) { return it.v.image && !it.v.parentImage && it.v.cmd; });
    group(noParent, function (it) { return lower(it.v.image); }).forEach(function (grp) {
      var pat = X.cmdPattern(grp.map(function (it) { return it.v.cmd; }));
      if (pat.type === 'none') return;
      var conds = [{ role: 'image', op: 'equals', value: grp[0].v.image }];
      if (pat.type === 'exact') conds.push({ role: 'cmd', op: 'equals', value: pat.exact });
      else if (pat.type === 'pattern') conds.push({ role: 'cmd', op: 'regex', value: pat.regex, prefix: pat.prefix, example: pat.example });
      else conds.push({ role: 'cmd', op: 'startswith', value: pat.prefix, regex: pat.regex });
      push({ level: 'path', title: base(grp[0].v.image) + ' with a known command line', conds: conds, items: grp, risk: 'medium', reasons: ['The parent program is not in the logs, so who started it is not checked.'] });
    });

    // Level C: raw lines only
    var rawOnly = items.filter(function (it) { return it.ev._raw && !it.v.image && !it.v.cmd; });
    group(rawOnly, function (it) { return X.normalizeCmd(it.ev._raw); }).forEach(function (grp) {
      var norm = X.normalizeCmd(grp[0].ev._raw);
      if (norm.replace(/\{[A-Z]+\}/g, '').length < 20) return;
      push({ level: 'path', title: 'Log line pattern (' + grp.length + ' events)', conds: [{ role: 'line', op: 'regex', value: '^' + normalizedToRegex(norm) + '$', example: grp[0].ev._raw }], items: grp, risk: 'medium', reasons: ['The whole log line is matched, because no separate fields were found.'] });
    });

    // Level D: program name only (shown to explain why it is a bad idea)
    group(items.filter(function (it) { return it.v.image; }), function (it) { return lower(base(it.v.image)); }).forEach(function (grp) {
      push({ level: 'name', title: 'Any ' + base(grp[0].v.image), conds: [{ role: 'imageName', op: 'endswith', value: base(grp[0].v.image) }], items: grp, risk: 'high',
        reasons: ['Matching only the file name is the weakest option. An attacker can copy or rename a tool to this name and the alert will be skipped.'] });
    });

    // Sort: unblocked first, then narrowest, then coverage
    var rank = { strict: 0, path: 1, name: 2 }, riskRank = { low: 0, medium: 1, high: 2 };
    cands.sort(function (a, b) {
      return (a.blocked - b.blocked) || (rank[a.level] - rank[b.level]) || (riskRank[a.risk] - riskRank[b.risk]) || (b.coverage - a.coverage);
    });
    cands.forEach(function (c, idx) { c.id = 'c' + idx; });

    // Default selection: top three unblocked candidates from the narrowest level present
    var best = cands.filter(function (c) { return !c.blocked && c.level !== 'name'; });
    var firstLevel = best.length ? best[0].level : null;
    var defaults = best.filter(function (c) { return c.level === firstLevel; }).slice(0, 3).map(function (c) { return c.id; });

    // Hints that are not exclusions
    var hints = [];
    function share(role) {
      var c = {}; items.forEach(function (it) { if (it.v[role]) c[lower(it.v[role])] = (c[lower(it.v[role])] || 0) + 1; });
      var k = Object.keys(c).sort(function (a, b) { return c[b] - c[a]; })[0];
      return k ? { value: k, frac: c[k] / total, distinct: Object.keys(c).length } : null;
    }
    var hostShare = share('host'), userShare = share('user');
    if (hostShare && total >= 5 && hostShare.frac >= 0.7) hints.push('Most hits (' + Math.round(hostShare.frac * 100) + '%) come from one host. Look at that machine first; the fix may be on the host, or the rule may need to be scoped to a group of systems.');
    if (userShare && total >= 5 && userShare.frac >= 0.7 && /system|service|svc/i.test(userShare.value)) hints.push('Most hits run as a system or service account. That points to automation, which makes the owner easy to ask.');

    return { total: total, items: items, flagged: flagged, flaggedEvents: flaggedEvents, fieldStats: fieldStats, mapping: mapping, candidates: cands, defaults: defaults, hints: hints };
  };

  // Which events a set of selected candidates would hide.
  X.impact = function (analysis, selectedIds) {
    var removed = {};
    analysis.candidates.forEach(function (c) { if (selectedIds.indexOf(c.id) >= 0) c.ids.forEach(function (i) { removed[i] = true; }); });
    var removedList = Object.keys(removed).map(Number);
    var remaining = analysis.items.filter(function (it) { return !removed[it.i]; });
    return { removed: removedList.length, remaining: remaining };
  };

  /* ---------------------------------------------------------------- rule info */

  X.ruleInfo = function (text, format) {
    var fields = {}, strings = [];
    var t = String(text || '');
    if (format === 'yaral') {
      (t.match(/\$\w+\.[A-Za-z_][\w.]*/g) || []).forEach(function (f) { fields[f] = true; });
      (t.match(/"(?:[^"\\]|\\.)*"/g) || []).slice(0, 20).forEach(function (s) { strings.push(s); });
      (t.match(/`[^`]*`/g) || []).slice(0, 10).forEach(function (s) { strings.push(s); });
    } else if (format === 'sigma') {
      var re = /^\s{2,}([A-Za-z][\w.]*)(\|[\w|]+)?:/gm, m;
      var skip = /^(selection|filter|condition|keywords|category|product|service|title|status|level|logsource|detection|id|description|author|date|tags|references|falsepositives|fields)/i;
      while ((m = re.exec(t))) { if (!skip.test(m[1])) fields[m[1] + (m[2] || '')] = true; }
      (t.match(/'(?:[^']|'')*'/g) || []).slice(0, 20).forEach(function (s) { strings.push(s); });
    } else {
      (t.match(/"(?:[^"\\]|\\.)*"/g) || []).slice(0, 20).forEach(function (s) { strings.push(s); });
    }
    return { fields: Object.keys(fields), strings: strings };
  };

  // Warn when an exclusion uses a field the rule itself depends on.
  X.overlapWarnings = function (ruleInfo, mapping, selected) {
    var out = [];
    var used = {};
    selected.forEach(function (c) { c.conds.forEach(function (cd) { used[cd.role] = true; }); });
    Object.keys(used).forEach(function (role) {
      var f = mapping[role];
      if (!f) return;
      var leaf = lower(f.slice(f.lastIndexOf('.') + 1));
      ruleInfo.fields.forEach(function (rf) {
        var rleaf = lower(rf.replace(/\|.*$/, '').replace(/^\$\w+\./, '')); rleaf = rleaf.slice(rleaf.lastIndexOf('.') + 1);
        if (rleaf && rleaf === leaf && out.indexOf(role) < 0) out.push(role);
      });
    });
    return out;
  };

  /* ---------------------------------------------------------------- rule writers */

  var ROLE_FIELD_DEFAULTS = {
    yaral: { image: '$e.target.process.file.full_path', parent: '$e.principal.process.file.full_path', cmd: '$e.target.process.command_line', user: '$e.principal.user.userid', signer: '$e.target.file.pe_file.signature_info.signer' },
    sigma: { image: 'Image', parent: 'ParentImage', cmd: 'CommandLine', user: 'User', signer: 'Signature' },
    splunk: { image: 'Image', parent: 'ParentImage', cmd: 'CommandLine', user: 'User', signer: 'Signature' },
    kql: { image: 'FolderPath', parent: 'InitiatingProcessFolderPath', cmd: 'ProcessCommandLine', user: 'AccountName', signer: 'ProcessVersionInfoCompanyName' },
    regex: { image: 'Image', parent: 'ParentImage', cmd: 'CommandLine', user: 'User', signer: 'Signer' },
    generic: { image: 'Image', parent: 'ParentImage', cmd: 'CommandLine', user: 'User', signer: 'Signer' }
  };
  X.defaultFields = function (format, observed) {
    var out = {}, defs = ROLE_FIELD_DEFAULTS[format] || ROLE_FIELD_DEFAULTS.generic;
    ['image', 'parent', 'cmd', 'user', 'signer'].forEach(function (r) {
      var obsKey = { image: 'image', parent: 'parentImage', cmd: 'cmd', user: 'user', signer: 'signer' }[r];
      // YARA-L and KQL need their own schema names; other formats follow the pasted log field names.
      out[r] = (format === 'yaral' || format === 'kql') ? defs[r] : ((observed && observed[obsKey]) || defs[r]);
    });
    out.line = '_raw';
    return out;
  };

  function yamlQ(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
  function yaralStr(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  function splunkStr(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  function kqlStr(s) { return '@"' + String(s).replace(/"/g, '""') + '"'; }

  var COMMENT = { yaral: '// ', sigma: '# ', kql: '// ', regex: '# ', generic: '# ' };

  X.metaLines = function (meta, format) {
    var lines = [
      'Tuning exclusion' + (meta.ref ? ' for ' + meta.ref : ''),
      'Created (UTC): ' + (meta.created || new Date().toISOString().slice(0, 10)),
      'Reviewer: ' + (meta.reviewer || '(add your name)'),
      'Review or remove by: ' + (meta.reviewBy || '(add a date)'),
      'Historical check: ' + (meta.lookback ? meta.lookback + ' days of history searched' : '(not recorded)'),
      'Basis: ' + (meta.basis || 'pasted sample events'),
      'Test in a non-alerting or staging copy of the rule before enabling.'
    ];
    if (format === 'splunk') return lines.map(function (l) { return '```' + l + '```'; });
    var p = COMMENT[format] || '# ';
    return lines.map(function (l) { return p + l; });
  };

  function condForSigma(c, f) {
    if (c.role === 'imageName') return f.image + '|endswith: ' + yamlQ('\\' + c.value);
    var field = f[c.role] || c.role;
    if (c.op === 'equals') return field + ': ' + yamlQ(c.value);
    if (c.op === 'startswith') return field + '|startswith: ' + yamlQ(c.value);
    if (c.op === 'regex') return field + '|re: ' + yamlQ(c.value);
    return field + ': ' + yamlQ(c.value);
  }

  function yaralNeg(c, f) {
    var field = f[c.role] || ('$e.' + c.role);
    if (c.role === 'imageName') return 'not re.regex(' + field + ', `(^|\\\\)' + escRe(c.value) + '$`) nocase';
    // Equality is written as an anchored regex so it can use the documented "not re.regex(...) nocase" form.
    if (c.op === 'equals') return 'not re.regex(' + field + ', `^' + escRe(c.value) + '$`) nocase';
    if (c.op === 'startswith') return 'not re.regex(' + field + ', `^' + escRe(c.value) + '`) nocase';
    return 'not re.regex(' + field + ', `' + c.value + '`) nocase';
  }

  function splunkPos(c, f) {
    var field = f[c.role] || c.role;
    if (c.role === 'imageName') return f.image + '=' + splunkStr('*\\' + c.value);
    if (c.op === 'equals') return field + '=' + splunkStr(c.value);
    if (c.op === 'startswith') return field + '=' + splunkStr(c.value + '*');
    // regex conditions fall back to the literal start of the command line
    return field + '=' + splunkStr((c.prefix || c.example || '') + '*');
  }

  function kqlPos(c, f) {
    var field = f[c.role] || c.role;
    if (c.role === 'imageName') return f.image + ' endswith ' + kqlStr('\\' + c.value);
    if (c.op === 'equals') return field + ' =~ ' + kqlStr(c.value);
    if (c.op === 'startswith') return field + ' startswith ' + kqlStr(c.value);
    return field + ' startswith ' + kqlStr(c.prefix || c.example || '');
  }

  function patternFor(c) {
    if (c.role === 'imageName') return '(?:^|[\\\\/])' + escRe(c.value) + '$';
    if (c.op === 'equals') return '^' + escRe(c.value) + '$';
    if (c.op === 'startswith') return '^' + escRe(c.value);
    return c.value;
  }

  // Build the output text. o = { format, candidates: [selected], fields, meta, ruleText }
  X.generate = function (o) {
    var f = o.fields, cands = o.candidates, format = o.format, head = X.metaLines(o.meta || {}, format), out = [];
    if (!cands.length) return 'Select at least one candidate exclusion above.';
    out.push.apply(out, head);
    out.push('');

    if (format === 'sigma') {
      var blocks = cands.map(function (c, i) {
        var lines = ['filter_tuning_' + (i + 1) + ':'];
        c.conds.forEach(function (cd) { lines.push('    ' + condForSigma(cd, f)); });
        return lines.join('\n');
      });
      var hasPatch = false;
      var rule = String(o.ruleText || '');
      var cm = /^([ \t]*)condition:[ \t]*(.+)$/m.exec(rule);
      if (cm && !/^[|>]/.test(cm[2].trim())) {
        var indent = cm[1];
        var oldCond = cm[2].trim();
        var wrapped = / or /i.test(oldCond) ? '(' + oldCond + ')' : oldCond;
        var newCond = indent + 'condition: ' + wrapped + ' and not 1 of filter_tuning_*';
        var blockText = blocks.map(function (b) { return b.split('\n').map(function (l) { return indent + l; }).join('\n'); }).join('\n');
        var patched = rule.replace(cm[0], function () { return blockText + '\n' + newCond; });
        out.push('# Patched rule (check the result against your original):');
        out.push(patched);
        hasPatch = true;
      }
      if (!hasPatch) {
        out.push('# Add these blocks under "detection:" and extend the condition:');
        out.push(blocks.join('\n'));
        out.push('');
        out.push('# condition: <your existing condition> and not 1 of filter_tuning_*');
      }
      return out.join('\n');
    }

    if (format === 'yaral') {
      out.push('// Add to the events: section. Each group excludes one known-benign pattern.');
      out.push('// Field names assume PROCESS_LAUNCH events (principal = parent, target = child). Parsers differ, so');
      out.push('// change them to match how your own rule reads the process, and check the grouping in the rule editor.');
      cands.forEach(function (c) {
        out.push('// ' + c.title);
        out.push('and (');
        out.push('  ' + c.conds.map(function (cd) { return yaralNeg(cd, f); }).join(' or\n  '));
        out.push(')');
      });
      return out.join('\n');
    }

    if (format === 'splunk') {
      out.push('<your base search>');
      out.push('| search NOT (');
      out.push(cands.map(function (c) { return '    (' + c.conds.map(function (cd) { return splunkPos(cd, f); }).join(' ') + ')'; }).join('\n    OR\n'));
      out.push('  )');
      return out.join('\n');
    }

    if (format === 'kql') {
      out.push('<your base query>');
      out.push('| where not (');
      out.push(cands.map(function (c) { return '    (' + c.conds.map(function (cd) { return kqlPos(cd, f); }).join(' and ') + ')'; }).join('\n    or\n'));
      out.push('  )');
      return out.join('\n');
    }

    if (format === 'regex') {
      out.push('# Ignore the alert when ALL patterns for one entry match their field.');
      cands.forEach(function (c, i) {
        out.push('# Exclusion ' + (i + 1) + ': ' + c.title);
        c.conds.forEach(function (cd) {
          out.push('#   ' + (f[cd.role] || cd.role) + ' ~ ' + patternFor(cd));
        });
      });
      out.push('');
      out.push('# If your engine supports lookahead (PCRE, .NET), this single pattern skips matching log lines:');
      var looks = cands.map(function (c) { return '(?=' + c.conds.map(function (cd) { return '(?=.*' + patternFor(cd).replace(/^\^/, '').replace(/\$$/, '') + ')'; }).join('') + ')'; });
      out.push('^(?!' + looks.join('|') + ')' + '.*' + (o.ruleText && String(o.ruleText).trim() ? '(?:' + String(o.ruleText).trim() + ')' : '<your original pattern>'));
      out.push('# RE2-style engines (Go, Google SecOps, many SIEMs) have no lookahead. Use a separate exclusion step there.');
      return out.join('\n');
    }

    // generic
    out.push('Ignore (do not alert) when ALL conditions in one entry are true:');
    cands.forEach(function (c, i) {
      out.push('');
      out.push('Entry ' + (i + 1) + ': ' + c.title);
      c.conds.forEach(function (cd) { out.push('  - ' + condText(cd)); });
    });
    return out.join('\n');
  };
})();
