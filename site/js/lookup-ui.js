// Shared page helpers for the lookup tools (SK.lu): input checks, rendering, and the "arrive from a link" flow.
// Remote text is only ever shown with textContent, never as HTML.
(function () {
  var SK = window.SK = window.SK || {};
  var LU = SK.lu = {};

  // want: which kinds the tool accepts ('domain', 'ip'). Takes a URL or an email address and uses its host or domain.
  // Returns { kind, value } or { error }.
  LU.parseTarget = function (raw, want) {
    want = want || ['domain', 'ip'];
    var v = window.SKRoute ? window.SKRoute.refang(raw) : String(raw || '').trim();
    if (!v) return { error: 'Enter something to look up.' };
    v = v.split(/\s+/)[0];
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
      try { v = new URL(v).hostname; } catch (e) { return { error: 'That does not look like a valid URL.' }; }
    } else if (/^[^@\s]+@[^@\s]+$/.test(v)) {
      v = v.split('@')[1];
    }
    v = v.replace(/^\[|\]$/g, '');
    var ip = SK.nl.parseIp(v);
    if (ip) {
      if (want.indexOf('ip') < 0) return { error: 'This tool needs a domain name, not an IP address.', kind: 'ip', value: ip.text };
      if (!ip.routable) return { error: ip.text + ' is ' + ip.label + ', not a public address. Private and internal addresses are never sent to outside services.' };
      return { kind: 'ip', value: ip.text };
    }
    var name = SK.nl.cleanName(v);
    if (!name) return { error: 'That is not a valid domain name or IP address.' };
    if (SK.nl.isReservedName(name)) return { error: name + ' looks like an internal name, so it is never sent to outside services.' };
    if (want.indexOf('domain') < 0) return { error: 'This tool needs an IP address, not a domain name.', kind: 'domain', value: name };
    return { kind: 'domain', value: name };
  };

  LU.callout = function (kind, kids) {
    return SK.el('div', { className: 'kit-callout ' + (kind || '') }, [].concat(kids).map(function (k) { return typeof k === 'string' ? SK.el('p', { text: k }) : k; }));
  };

  LU.chip = function (text, kind) { return SK.el('span', { className: 'chip2 ' + (kind || ''), text: text }); };

  LU.link = function (href, text) {
    return SK.el('a', { text: text, attrs: { href: href, target: '_blank', rel: 'noopener noreferrer' } });
  };

  // An email address as a mailto link (only when it looks like an address).
  LU.mail = function (email) {
    if (/^[^\s@<>"]+@[^\s@<>"]+$/.test(email)) return SK.el('a', { text: email, attrs: { href: 'mailto:' + email } });
    return document.createTextNode(email);
  };

  LU.table = function (headers, rows, monoCols) {
    var t = SK.el('table', { className: 'kit-table' });
    if (headers) t.appendChild(SK.el('tr', {}, headers.map(function (h) { return SK.el('th', { text: h }); })));
    rows.forEach(function (r) {
      t.appendChild(SK.el('tr', {}, r.map(function (c, i) {
        var td = SK.el('td', { className: (monoCols || []).indexOf(i) >= 0 ? 'mono' : '' });
        if (c && c.nodeType) td.appendChild(c); else td.textContent = c == null ? '' : String(c);
        return td;
      })));
    });
    return SK.el('div', { className: 'kit-table-wrap' }, [t]);
  };

  // Label and value rows. Empty values are skipped. A value can be text or a DOM node.
  LU.kv = function (rows) {
    var t = SK.el('table', { className: 'kit-table' });
    rows.forEach(function (r) {
      if (r[1] === '' || r[1] == null || (Array.isArray(r[1]) && !r[1].length)) return;
      var td = SK.el('td', { className: 'mono' });
      var v = Array.isArray(r[1]) ? r[1].join('\n') : r[1];
      if (v && v.nodeType) td.appendChild(v); else td.textContent = String(v);
      t.appendChild(SK.el('tr', {}, [SK.el('th', { text: r[0] }), td]));
    });
    return SK.el('div', { className: 'kit-table-wrap' }, [t]);
  };

  var LEVEL = { error: 'bad', warn: 'warn', info: 'dim', pass: 'good' };
  var LEVEL_LABEL = { error: 'Problem', warn: 'Warning', info: 'Note', pass: 'Good' };
  var LEVEL_ORDER = { error: 0, warn: 1, info: 2, pass: 3 };

  LU.findings = function (list) {
    var box = SK.el('div', { className: 'kit-results' });
    list.slice().sort(function (a, b) { return LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level]; }).forEach(function (f) {
      box.appendChild(SK.el('div', { className: 'kit-result ' + LEVEL[f.level] }, [
        SK.el('h4', {}, [f.title, LU.chip(LEVEL_LABEL[f.level], f.level === 'pass' ? 'good' : (f.level === 'warn' ? 'warn' : (f.level === 'error' ? 'bad' : '')))]),
        f.detail ? SK.el('p', { className: 'kit-note', text: f.detail }) : null
      ]));
    });
    return box;
  };

  LU.raw = function (title, obj) {
    var text = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    if (text.length > 30000) text = text.slice(0, 30000) + '\n... (truncated)';
    return SK.el('details', { className: 'kit-details' }, [SK.el('summary', { text: title }), SK.el('div', { className: 'kit-out', text: text })]);
  };

  LU.humanTtl = function (s) {
    if (s == null) return '';
    if (s < 60) return s + 's';
    if (s < 3600) return Math.round(s / 60) + ' min';
    if (s < 86400) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' d';
  };

  LU.working = function (box, text) {
    SK.clear(box);
    box.appendChild(SK.el('p', { className: 'kit-note', text: text || 'Looking it up…', attrs: { role: 'status' } }));
  };

  // Network problems get a friendly message. Anything else is a bug in this page, so say so instead of blaming the network.
  LU.error = function (box, err) {
    SK.clear(box);
    var network = err && (err.userMessage || err.name === 'AbortError' || (err instanceof TypeError && /fetch|network|load failed/i.test(err.message)));
    if (window.console) console.error('lookup failed:', err && err.name, err && err.message, err);
    box.appendChild(LU.callout('bad', [network ? SK.nl.friendlyError(err) : 'Something went wrong in this page' + (err && err.message ? ' (' + err.message + ')' : '') + '. Please try again.']));
  };

  // Wires an input, a button and the "arrive from a link" flow.
  // cfg: { input, button, out, run(raw) -> Promise, multiline }
  // A link from the search box carries go=1 and runs at once; any other arrival only fills the box.
  LU.start = function (cfg) {
    var input = SK.$(cfg.input), btn = SK.$(cfg.button), out = SK.$(cfg.out), busy = false;
    function go() {
      if (busy) return;
      busy = true; btn.disabled = true;
      Promise.resolve().then(function () { return cfg.run(input.value); })
        .then(null, function (e) { LU.error(out, e); })
        .then(function () { busy = false; btn.disabled = false; });
    }
    btn.addEventListener('click', go);
    if (!cfg.multiline) input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go(); } });
    var q = SK.hashQuery();
    if (q.q) {
      input.value = q.q;
      if (q.go === '1' || cfg.offline) go();
      else out.appendChild(LU.callout('', ['Filled in from a link. Press the button to look it up.']));
    }
    return go;
  };
})();
