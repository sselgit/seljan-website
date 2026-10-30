// Highlight tuner page. All work happens in this browser tab; nothing is sent, saved or cached.
(function () {
  var SK = window.SK = window.SK || {};

  function init() {
    var fmtSel = SK.$('hl-format');
    if (!fmtSel || !SK.hl) return;
    var X = SK.tuner, H = SK.hl;
    var state = { fp: [], al: [], conds: [], map: [], udm: false, result: null };

    H.FORMATS.forEach(function (f) { fmtSel.appendChild(SK.el('option', { text: f.label, attrs: { value: f.id } })); });
    fmtSel.value = 'chronicle';

    function para(t) { return SK.el('p', { text: t }); }
    function chip(text, kind) { return SK.el('span', { className: 'chip2 ' + (kind || ''), text: text }); }
    function callout(kind, kids) { return SK.el('div', { className: 'kit-callout ' + kind }, kids); }
    function today(plus) { var d = new Date(); d.setUTCDate(d.getUTCDate() + (plus || 0)); return d.toISOString().slice(0, 10); }

    /* ---------- sanitize ---------- */
    SK.$('hl-san-run').addEventListener('click', function () {
      var res = X.sanitizeAll([SK.$('hl-al').value, SK.$('hl-fp').value], {
        ips: SK.$('hl-san-ips').checked, emails: SK.$('hl-san-emails').checked, users: SK.$('hl-san-users').checked,
        terms: SK.$('hl-san-terms').value.split('\n'), existing: state.map
      });
      SK.$('hl-al').value = res.texts[0]; SK.$('hl-fp').value = res.texts[1];
      state.map = state.map.concat(res.map);
      var box = SK.$('hl-san-out'); SK.clear(box);
      box.appendChild(callout(res.map.length ? 'warn' : 'good', [para(res.map.length
        ? 'Replaced ' + res.map.length + ' value(s) with generic ones. Highlight the generic values, then put your real ones back in the output with the box that appears there. The originals live only in this page\'s memory.'
        : 'Nothing to replace was found with the selected options.')]));
    });

    /* ---------- load and render logs ---------- */

    function load() {
      var p1 = X.parseLogs(SK.$('hl-fp').value, 60), p2 = X.parseLogs(SK.$('hl-al').value, 60);
      var box = SK.$('hl-load-msg'); SK.clear(box);
      if (!p1.events.length) { box.appendChild(callout('warn', [para('Paste the false-positive log first.')])); return; }
      if (!p2.events.length) { box.appendChild(callout('warn', [para('Paste the alerting log too. It is what the page checks your exclusion against: if the exclusion would also hide it, you are tuning out a real detection.')])); return; }
      state.fp = p1.events; state.al = p2.events; state.conds = [];
      state.udm = H.looksLikeUdm(p1.events);
      var msgs = [state.fp.length + ' false-positive event(s) (' + p1.format + ') and ' + state.al.length + ' alerting event(s) (' + p2.format + ') read.'];
      msgs.push(state.udm ? 'These look like Chronicle UDM already, so field names are used as they are.' : 'These look like raw logs. Field names are guessed into UDM names; check each one in the conditions list.');
      p1.warnings.concat(p2.warnings).forEach(function (w) { msgs.push(w); });
      box.appendChild(callout('good', msgs.map(para)));
      var keysFp = Object.keys(state.fp[0]), keysAl = Object.keys(state.al[0]);
      var shared = keysFp.filter(function (k) { return keysAl.indexOf(k) >= 0; });
      if (shared.length < Math.min(keysFp.length, keysAl.length) * 0.6) box.appendChild(callout('warn', [para('The two logs use mostly different field names, so a condition can only match one of them. Paste both in the same format, or the check against the alerting log will be unreliable.')]));
      SK.$('hl-work').hidden = false;
      render();
      SK.$('hl-work').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    SK.$('hl-load').addEventListener('click', load);

    // Paint a value, marking where conditions on this key match.
    function paintValue(span, key, value, mark) {
      SK.clear(span);
      var ranges = [];
      if (mark) state.conds.forEach(function (c) { if (c.key === key) { var r = H.span(c, value); if (r) ranges.push(r); } });
      ranges.sort(function (a, b) { return a[0] - b[0]; });
      var pos = 0, v = String(value);
      ranges.forEach(function (r) {
        if (r[0] < pos) return;
        if (r[0] > pos) span.appendChild(document.createTextNode(v.slice(pos, r[0])));
        span.appendChild(SK.el('mark', { className: 'hl-mark ' + mark, text: v.slice(r[0], r[1]) }));
        pos = r[1];
      });
      if (pos < v.length) span.appendChild(document.createTextNode(v.slice(pos)));
    }

    function eventCard(ev, i, selectable, hit, result) {
      var keys = Object.keys(ev);
      var badge = hit ? chip(selectable ? 'would be hidden' : 'WOULD BE HIDDEN', selectable ? 'good' : 'bad') : chip(selectable ? 'still alerts' : 'still alerts', selectable ? 'warn' : 'good');
      var card = SK.el('div', { className: 'hl-event' + (hit && !selectable ? ' hl-bad' : '') }, [SK.el('div', { className: 'hl-event-head' }, [SK.el('strong', { text: (selectable ? 'False positive #' : 'Alerting #') + (i + 1) + ' ' }), result ? badge : null])]);
      var t = SK.el('table', { className: 'hl-table' });
      keys.forEach(function (k) {
        var val = String(ev[k]);
        var vs = SK.el('span', { className: 'hl-val mono' + (selectable ? ' hl-sel' : ''), attrs: { 'data-i': String(i), 'data-k': k } });
        paintValue(vs, k, val, selectable ? 'good' : (hit ? 'bad' : ''));
        var kc = SK.el('td', { className: 'hl-key' }, [selectable
          ? SK.el('button', { className: 'hl-keybtn', text: k, attrs: { type: 'button', 'data-i': String(i), 'data-k': k, title: 'Use this whole value' } })
          : SK.el('span', { text: k })]);
        t.appendChild(SK.el('tr', {}, [kc, SK.el('td', {}, [vs])]));
      });
      card.appendChild(t);
      return card;
    }

    function render() {
      state.result = H.challenge(state.conds, state.fp, state.al);
      var r = state.result;
      var fpBox = SK.$('hl-fp-view'), alBox = SK.$('hl-al-view');
      SK.clear(fpBox); SK.clear(alBox);
      var fpHit = r.fpHitIdx || [], aHit = r.aHitIdx || [];
      state.fp.slice(0, 25).forEach(function (ev, i) { fpBox.appendChild(eventCard(ev, i, true, fpHit.indexOf(ev) >= 0, state.conds.length > 0)); });
      if (state.fp.length > 25) fpBox.appendChild(para('Showing the first 25 of ' + state.fp.length + ' events. All are used in the checks.'));
      state.al.slice(0, 25).forEach(function (ev, i) { alBox.appendChild(eventCard(ev, i, false, aHit.indexOf(ev) >= 0, state.conds.length > 0)); });
      renderConds(); renderFindings(); renderOutput();
    }

    /* ---------- selecting ---------- */

    function addCond(c) {
      // One condition per field: a new highlight on the same field replaces the old one.
      state.conds = state.conds.filter(function (x) { return !(x.key === c.key); });
      state.conds.push(c);
      render();
    }
    var fpView = SK.$('hl-fp-view');
    fpView.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.hl-keybtn') : null;
      if (!b) return;
      var key = b.getAttribute('data-k'), ev = state.fp[+b.getAttribute('data-i')];
      var existing = state.conds.filter(function (c) { return c.key === key; })[0];
      if (existing) { state.conds = state.conds.filter(function (c) { return c !== existing; }); render(); return; }
      addCond(H.condFromSelection(key, ev[key], 0, String(ev[key]).length));
    });
    fpView.addEventListener('mouseup', function () {
      var sel = window.getSelection ? window.getSelection() : null;
      if (!sel || sel.isCollapsed || !sel.rangeCount) return;
      var rg = sel.getRangeAt(0);
      function valOf(n) { while (n && n !== fpView) { if (n.nodeType === 1 && n.classList && n.classList.contains('hl-val')) return n; n = n.parentNode; } return null; }
      var a = valOf(rg.startContainer), b = valOf(rg.endContainer);
      if (!a || a !== b) return;
      var key = a.getAttribute('data-k'), ev = state.fp[+a.getAttribute('data-i')];
      var full = String(ev[key]);
      function offset(node, off) {
        var pre = document.createRange(); pre.selectNodeContents(a); pre.setEnd(node, off); return pre.toString().length;
      }
      var s = offset(rg.startContainer, rg.startOffset), t = offset(rg.endContainer, rg.endOffset);
      var text = full.slice(s, t);
      // Trim stray spaces from the selection edges.
      var lead = text.length - text.replace(/^\s+/, '').length, trail = text.length - text.replace(/\s+$/, '').length;
      s += lead; t -= trail;
      if (t <= s) return;
      sel.removeAllRanges();
      addCond(H.condFromSelection(key, full, s, t));
    });

    /* ---------- conditions list ---------- */

    function renderConds() {
      var box = SK.$('hl-conds'); SK.clear(box);
      if (!state.conds.length) { box.appendChild(para('Nothing highlighted yet. Drag across text in a false-positive event, or click a field name to use its whole value.')); return; }
      state.conds.forEach(function (c, i) {
        var mode = SK.el('select', { className: 'kit' });
        H.MODES.forEach(function (m) { mode.appendChild(SK.el('option', { text: ({ exact: 'equals', startswith: 'starts with', endswith: 'ends with', contains: 'contains', regex: 'regular expression' })[m], attrs: { value: m } })); });
        mode.value = c.mode;
        mode.addEventListener('change', function () { c.mode = mode.value; render(); });
        var val = SK.el('input', { className: 'kit mono', attrs: { type: 'text', 'aria-label': 'Value' } }); val.value = c.value;
        val.addEventListener('change', function () { c.value = val.value; render(); });
        var udm = SK.el('input', { className: 'kit mono', attrs: { type: 'text', 'aria-label': 'UDM field name', placeholder: 'UDM field, e.g. target.process.command_line' } }); udm.value = c.udm;
        udm.addEventListener('change', function () { c.udm = udm.value.trim(); render(); });
        var rm = SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Remove', attrs: { type: 'button' } });
        rm.addEventListener('click', function () { state.conds.splice(i, 1); render(); });
        box.appendChild(SK.el('div', { className: 'hl-cond' }, [
          SK.el('div', {}, [SK.el('span', { className: 'kit-label', text: 'Log field: ' + c.key }), udm]),
          SK.el('div', {}, [SK.el('span', { className: 'kit-label', text: 'Match' }), mode]),
          SK.el('div', { className: 'hl-cond-val' }, [SK.el('span', { className: 'kit-label', text: 'Value' }), val]),
          SK.el('div', { className: 'hl-cond-rm' }, [rm])
        ]));
        if (!c.udm) box.appendChild(callout('warn', [para('No UDM name could be guessed for ' + c.key + '. Type it in, or the Chronicle output will have a blank to fill.')]));
      });
    }

    /* ---------- challenge results ---------- */

    var acks = {};
    function renderFindings() {
      var box = SK.$('hl-findings'); SK.clear(box);
      var r = state.result;
      var head = r.verdict === 'block' ? ['bad', 'Blocked: this exclusion is not safe yet'] : (r.verdict === 'warn' ? ['warn', 'Caution: review each warning below'] : ['good', 'No problems found in the sample you gave it']);
      box.appendChild(callout(head[0], [SK.el('p', {}, [SK.el('strong', { text: head[1] })]),
        para('Hides ' + r.fpHit + ' of ' + state.fp.length + ' false-positive event(s) and ' + r.aHit + ' of ' + state.al.length + ' alerting event(s). Passing these checks does not make it safe: they only test the events you pasted.')]));
      var list = SK.el('div', { className: 'kit-results' });
      r.findings.forEach(function (f) {
        var kids = [SK.el('h4', {}, [chip(f.level === 'block' ? 'blocked' : f.level, f.level === 'block' ? 'bad' : (f.level === 'warn' ? 'warn' : ''))].concat([document.createTextNode(' ' + f.title)])), para(f.detail)];
        if (f.level === 'warn') {
          var id = 'hl-warn-' + f.title;
          var cb = SK.el('input', { attrs: { type: 'checkbox' } }); cb.checked = !!acks[id];
          cb.addEventListener('change', function () { acks[id] = cb.checked; renderOutput(); });
          kids.push(SK.el('label', { className: 'kit-check' }, [cb, 'I considered this and accept it, or I will narrow the exclusion.']));
        }
        list.appendChild(SK.el('div', { className: 'kit-result ' + (f.level === 'block' ? 'bad' : (f.level === 'warn' ? 'warn' : 'good')) }, kids));
      });
      box.appendChild(list);
    }

    /* ---------- checklist and output ---------- */

    var CHECKS = [
      'I searched historical data (30 days at least) for this exact activity and know how often, where and for whom it happens.',
      'I know which product, team or person causes it, and confirmed with them that it is expected.',
      'I looked at every occurrence that differs (new host, user, path or parent) and none of them is suspicious.',
      'I will test the exclusion on a copy of the rule, or with the platform\'s test, before it goes live.',
      'I will review or remove this exclusion by the date below.'
    ];
    (function buildChecklist() {
      var wrap = SK.$('hl-check'); var grid = SK.el('div', { className: 'kit-cols two' });
      function field(id, label, type, value, ph) {
        var inp = SK.el('input', { className: 'kit', attrs: { type: type, id: id, placeholder: ph || '' } }); inp.value = value || '';
        inp.addEventListener('input', renderOutput);
        grid.appendChild(SK.el('div', {}, [SK.el('label', { className: 'kit-label', text: label, attrs: { 'for': id } }), inp]));
      }
      field('hl-ref', 'Ticket or reference', 'text', '', 'e.g. TUNE-123');
      field('hl-owner', 'Your name', 'text', '', '');
      field('hl-reviewby', 'Review or remove by', 'date', today(90));
      wrap.appendChild(grid);
      CHECKS.forEach(function (t, i) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'hl-ack-' + i } }); cb.addEventListener('change', renderOutput);
        wrap.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'hl-ack-' + i } }, [cb, t]));
      });
    })();

    function renderOutput() {
      var box = SK.$('hl-output'); SK.clear(box);
      var r = state.result;
      if (!r) return;
      if (r.verdict === 'block') { box.appendChild(callout('bad', [para('Locked. Fix the blocked items above first. This page will not write an exclusion it considers unsafe.')])); return; }
      var unacked = r.findings.filter(function (f) { return f.level === 'warn' && !acks['hl-warn-' + f.title]; });
      if (unacked.length) { box.appendChild(callout('warn', [para('Locked. Tick each warning above once you have considered it (' + unacked.length + ' left).')])); return; }
      for (var i = 0; i < CHECKS.length; i++) { var c = SK.$('hl-ack-' + i); if (!c || !c.checked) { box.appendChild(callout('warn', [para('Locked. Confirm the checklist above. A tuning change is only safe after you check the history, and this page cannot do that for you.')])); return; } }
      var meta = { ref: SK.$('hl-ref').value.trim(), owner: SK.$('hl-owner').value.trim(), reviewBy: SK.$('hl-reviewby').value, basis: state.fp.length + ' false-positive and ' + state.al.length + ' alerting sample events' };
      var text = H.write(fmtSel.value, state.conds, meta);
      if (state.map.length) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'hl-showreal' } });
        var prev = SK.$('hl-showreal-state');
        cb.checked = !!(prev && prev.value === '1');
        cb.addEventListener('change', function () { SK.$('hl-showreal-state').value = cb.checked ? '1' : '0'; renderOutput(); });
        box.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'hl-showreal' } }, [cb, 'Put my real values back into this text (done in this page only)']));
        if (cb.checked) text = X.restore(text, state.map);
        else box.appendChild(callout('warn', [para('This text contains generic placeholder values. Replace them before use, or tick the box above.')]));
      }
      box.appendChild(SK.el('div', { className: 'kit-out', text: text }));
      box.appendChild(SK.el('div', { className: 'kit-row' }, [
        SK.copyButton('Copy exclusion', function () { return text; }),
        SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Download', attrs: { type: 'button' }, on: { click: function () { SK.download('tuning-exclusion.txt', text, 'text/plain'); } } })
      ]));
      box.appendChild(SK.el('p', { className: 'kit-note', text: 'A starting point. Syntax is not validated against your platform: paste it into the editor, validate it and test it on past data first.' }));
    }
    fmtSel.addEventListener('change', renderOutput);

    /* ---------- misc ---------- */

    SK.$('hl-sample').addEventListener('click', function () {
      SK.$('hl-al').value = H.SAMPLE.alerting; SK.$('hl-fp').value = H.SAMPLE.fp; state.map = [];
      SK.clear(SK.$('hl-san-out'));
    });
    SK.$('hl-clear').addEventListener('click', function () {
      ['hl-al', 'hl-fp', 'hl-san-terms'].forEach(function (id) { SK.$(id).value = ''; });
      state.fp = []; state.al = []; state.conds = []; state.map = []; state.result = null; acks = {};
      SK.clear(SK.$('hl-san-out')); SK.clear(SK.$('hl-load-msg'));
      SK.$('hl-work').hidden = true;
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
