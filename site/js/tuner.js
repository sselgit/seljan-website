// Rule tuner page. All work happens in this browser tab; nothing is sent, saved or cached.
(function () {
  var SK = window.SK = window.SK || {};

  function init() {
    var fmtSel = SK.$('tn-format');
    if (!fmtSel || !SK.tuner) return;
    var X = SK.tuner, DATA = SK.tunerData;

    var state = { map: [], analysis: null, selected: [], fields: {}, parsed: null, showAll: false };

    DATA.FORMATS.forEach(function (f) { fmtSel.appendChild(SK.el('option', { text: f.label, attrs: { value: f.id } })); });

    function trunc(s, n) { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
    function chip(text, kind) { return SK.el('span', { className: 'chip2 ' + (kind || ''), text: text }); }
    function callout(kind, kids) { return SK.el('div', { className: 'kit-callout ' + kind }, kids); }
    function para(text) { return SK.el('p', { text: text }); }
    function today(plus) {
      var d = new Date(); d.setUTCDate(d.getUTCDate() + (plus || 0));
      return d.toISOString().slice(0, 10);
    }

    /* ---------- education panels ---------- */

    (function education() {
      var a = SK.$('tn-abnormal'), r = SK.$('tn-routine'), h = SK.$('tn-historical');
      function table(rows, c1, c2) {
        var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, [SK.el('th', { text: c1 }), SK.el('th', { text: c2 })])]);
        rows.forEach(function (x) { t.appendChild(SK.el('tr', {}, [SK.el('td', { text: x[0] }), SK.el('td', { text: x[1] })])); });
        return SK.el('div', { className: 'kit-table-wrap' }, [t]);
      }
      a.appendChild(table(DATA.ABNORMAL, 'Activity', 'Why it matters'));
      r.appendChild(table(DATA.ROUTINE, 'Activity', 'How to tune it safely'));
      var ol = SK.el('ol');
      DATA.HISTORICAL.forEach(function (x) { ol.appendChild(SK.el('li', { text: x })); });
      h.appendChild(ol);
    })();

    /* ---------- sanitize ---------- */

    function sanitize() {
      var res = X.sanitizeAll([SK.$('tn-alert').value, SK.$('tn-rule').value, SK.$('tn-logs').value], {
        ips: SK.$('tn-san-ips').checked, emails: SK.$('tn-san-emails').checked, users: SK.$('tn-san-users').checked,
        terms: SK.$('tn-san-terms').value.split('\n'), existing: state.map
      });
      SK.$('tn-alert').value = res.texts[0];
      SK.$('tn-rule').value = res.texts[1];
      SK.$('tn-logs').value = res.texts[2];
      state.map = state.map.concat(res.map);
      var box = SK.$('tn-san-out');
      SK.clear(box);
      if (!state.map.length) { box.appendChild(callout('good', [para('Nothing to replace was found with the selected options.')])); return; }
      box.appendChild(callout('warn', [
        para('Replaced ' + res.map.length + ' value(s) in the three boxes above with generic ones (documentation addresses such as 192.0.2.1, example.com, USER1).'),
        para('What you copy out of this page will contain those generic values. Put your own values back before you use a rule. Your originals are kept only in this page\'s memory, so they disappear if you reload or close the tab.')
      ]));
      var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, [SK.el('th', { text: 'Type' }), SK.el('th', { text: 'Your value' }), SK.el('th', { text: 'Replaced with' })])]);
      state.map.forEach(function (e) { t.appendChild(SK.el('tr', {}, [SK.el('td', { text: e.type }), SK.el('td', { className: 'mono', text: e.original }), SK.el('td', { className: 'mono', text: e.placeholder })])); });
      box.appendChild(SK.el('details', { className: 'kit-details', attrs: { open: '' } }, [SK.el('summary', { text: 'Your values and what replaced them (' + state.map.length + ')' }), SK.el('div', { className: 'kit-table-wrap' }, [t])]));
    }
    SK.$('tn-san-run').addEventListener('click', sanitize);

    /* ---------- analyze ---------- */

    function countRealIps(text) {
      var n = 0;
      String(text).replace(/(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\d|\.\d)/g, function (m, pre, ip) {
        if (SK.net && SK.net.parseIPv4(ip) !== null && !/^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)) n++;
        return m;
      });
      return n;
    }

    function analyze() {
      var out = SK.$('tn-results');
      SK.clear(out);
      out.hidden = false;
      var format = fmtSel.value;
      if (!format) { out.appendChild(callout('warn', [para('Choose the rule format first. The suggestions are written in that format, so it needs to match your platform.')])); fmtSel.focus(); return; }
      var parsed = X.parseLogs(SK.$('tn-logs').value);
      if (!parsed.events.length) { out.appendChild(callout('warn', [para('Paste some log events first. One event per line works, as do JSON, key=value, CSV, or Event Viewer text.')])); return; }
      var allText = SK.$('tn-alert').value + SK.$('tn-rule').value + SK.$('tn-logs').value;
      var ips = countRealIps(allText);

      state.parsed = parsed;
      state.analysis = X.analyze(parsed.events);
      state.fields = X.defaultFields(format, state.analysis.mapping);
      state.selected = state.analysis.defaults.slice();
      state.showAll = false;
      render(format, ips);
      out.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    SK.$('tn-run').addEventListener('click', analyze);

    function render(format, ips) {
      var out = SK.$('tn-results'), an = state.analysis;
      SK.clear(out);

      out.appendChild(SK.el('h2', { text: 'What the logs show' }));
      out.appendChild(para(an.total + ' event' + (an.total === 1 ? '' : 's') + ' read (' + state.parsed.format + ' format). ' +
        (an.flaggedEvents ? an.flaggedEvents + ' of them show signs that deserve investigation, not tuning.' : 'None of them matched the abnormal-activity checks.')));
      state.parsed.warnings.forEach(function (w) { out.appendChild(callout('warn', [para(w)])); });
      if (ips > 0) out.appendChild(callout('warn', [para('Your text still contains ' + ips + ' IP address(es). Use "Replace my identifying values" above if you want them removed.')]));

      // Abnormal activity
      if (an.flagged.length) {
        var kids = [SK.el('p', {}, [SK.el('strong', { text: 'Do not tune these away. Investigate them first.' })])];
        an.flagged.forEach(function (f) {
          var ex = an.items[f.examples[0]], v = ex.v;
          kids.push(SK.el('div', { className: 'kit-result bad' }, [
            SK.el('h4', {}, [f.risk.title, chip(f.count + ' event' + (f.count > 1 ? 's' : ''), 'bad')].concat(f.risk.mitre.map(function (m) { return chip(m); }))),
            SK.el('p', { className: 'kit-note', text: f.risk.why }),
            SK.el('div', { className: 'kit-out', text: trunc((v.parentImage ? v.parentImage + '  ->  ' : '') + (v.image || '') + '\n' + (v.cmd || ex.ev._raw || ''), 400) })
          ]));
        });
        out.appendChild(callout('bad', kids));
      }

      // Rule overview
      var rinfo = X.ruleInfo(SK.$('tn-rule').value, format);
      if (rinfo.fields.length || rinfo.strings.length) {
        var det = SK.el('details', { className: 'kit-details' }, [SK.el('summary', { text: 'What your rule appears to match on' })]);
        if (rinfo.fields.length) det.appendChild(SK.el('p', { text: 'Fields: ' + rinfo.fields.join(', ') }));
        if (rinfo.strings.length) det.appendChild(SK.el('p', { text: 'Literal values and patterns: ' + rinfo.strings.slice(0, 8).join('  ') }));
        det.appendChild(SK.el('p', { className: 'kit-note', text: 'Read from the text by simple pattern matching, so treat it as a hint.' }));
        out.appendChild(det);
      }

      // MITRE ATT&CK: what the rule text, the alert and any flagged risks point to
      var attText = SK.$('tn-rule').value + ' ' + SK.$('tn-alert').value + ' ' + an.flagged.map(function (f) { return f.risk.title; }).join(' ');
      var attPanel = SK.attackPanel ? SK.attackPanel(attText, {}) : null;
      if (attPanel) out.appendChild(attPanel);

      // Candidates
      out.appendChild(SK.el('h2', { text: 'Candidate exclusions' }));
      out.appendChild(para('Each entry hides only events that match all of its conditions. Narrower entries are safer. Entries that would hide risky events are locked.'));
      var list = SK.el('div', { className: 'kit-results', attrs: { id: 'tn-cands' } });
      out.appendChild(list);
      renderCandidates();

      // Field names
      var fm = SK.el('details', { className: 'kit-details' }, [SK.el('summary', { text: 'Field names used in the generated text (edit to match your rule)' })]);
      var grid = SK.el('div', { className: 'kit-cols two' });
      [['parent', 'Parent program field'], ['image', 'Program field'], ['cmd', 'Command line field'], ['user', 'User field'], ['signer', 'Signer field']].forEach(function (p) {
        var id = 'tn-f-' + p[0];
        var inp = SK.el('input', { className: 'kit', attrs: { type: 'text', id: id, spellcheck: 'false' } });
        inp.value = state.fields[p[0]] || '';
        inp.addEventListener('input', function () { state.fields[p[0]] = inp.value.trim(); renderOutput(); });
        grid.appendChild(SK.el('div', {}, [SK.el('label', { className: 'kit-label', text: p[1], attrs: { 'for': id } }), inp]));
      });
      fm.appendChild(grid);
      if (format === 'yaral') fm.appendChild(SK.el('p', { className: 'kit-note', text: 'The YARA-L defaults assume PROCESS_LAUNCH events where principal.process is the parent and target.process is the new process. Parsers differ, and some published examples use principal.process for the program itself, so copy the field names your own rule uses.' }));
      out.appendChild(fm);

      // Impact
      out.appendChild(SK.el('h2', { text: 'What the selection would hide' }));
      out.appendChild(SK.el('div', { attrs: { id: 'tn-impact' } }));
      renderImpact();

      // Alternatives
      out.appendChild(SK.el('h2', { text: 'Other ways to cut noise' }));
      var alt = SK.el('ul');
      an.hints.forEach(function (h) { alt.appendChild(SK.el('li', { text: h })); });
      [
        'Fix the source: if a product causes the activity, ask its owner whether it can run differently (for example a signed script in an admin-only folder).',
        'Add context instead of removing coverage: require a second signal (unsigned file, unusual parent, new host) before the alert fires.',
        'Move it to hunting: keep the rule but run it as a periodic report or at lower severity, so analysts see trends without being paged.',
        'Use a threshold: alert only when the activity is far above its normal rate for that host or user.',
        'Give every exclusion an owner and an end date, and review it when the software changes.'
      ].forEach(function (x) { alt.appendChild(SK.el('li', { text: x })); });
      out.appendChild(alt);

      // Checklist
      out.appendChild(SK.el('h2', { text: 'Before you use any of this' }));
      out.appendChild(buildChecklist());

      out.appendChild(SK.el('h2', { text: 'Rule text' }));
      out.appendChild(SK.el('div', { attrs: { id: 'tn-output' } }));
      renderOutput();
    }

    function riskKind(c) { return c.blocked ? 'bad' : (c.risk === 'low' ? 'good' : (c.risk === 'medium' ? 'warn' : 'bad')); }
    var LEVEL_LABEL = { strict: 'Narrow', path: 'Medium', name: 'Weak: name only' };

    function renderCandidates() {
      var an = state.analysis, list = SK.$('tn-cands');
      SK.clear(list);
      var cands = an.candidates, limit = state.showAll ? cands.length : 10;
      cands.slice(0, limit).forEach(function (c) {
        var id = 'tn-' + c.id;
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: id } });
        cb.checked = state.selected.indexOf(c.id) >= 0;
        cb.disabled = c.blocked;
        cb.addEventListener('change', function () {
          var i = state.selected.indexOf(c.id);
          if (cb.checked && i < 0) state.selected.push(c.id);
          if (!cb.checked && i >= 0) state.selected.splice(i, 1);
          renderImpact(); renderOutput();
        });
        var title = SK.el('label', { attrs: { 'for': id }, className: 'kit-check' }, [cb, SK.el('strong', { text: c.title })]);
        var chips = SK.el('div', { className: 'kit-row tight' }, [
          chip(LEVEL_LABEL[c.level], c.level === 'name' ? 'bad' : (c.level === 'strict' ? 'good' : 'warn')),
          chip('covers ' + c.coverage + ' of ' + an.total + ' events'),
          chip(c.blocked ? 'locked' : c.risk + ' risk', riskKind(c))
        ]);
        var conds = SK.el('ul');
        c.conds.forEach(function (cd) { conds.appendChild(SK.el('li', {}, [SK.el('span', { className: 'mono', text: trunc(X.condText(cd), 220) })])); });
        var kids = [title, chips, conds];
        c.reasons.forEach(function (r) { kids.push(SK.el('p', { className: 'kit-note', text: r })); });
        if (c.blocked) {
          kids.push(SK.el('p', { className: 'kit-note', text: 'Locked because it would also hide: ' + c.dangers.map(function (d) { return d.title; }).join('; ') + '.' }));
        }
        list.appendChild(SK.el('div', { className: 'kit-result ' + (c.blocked ? 'bad' : (c.level === 'name' ? 'warn' : 'good')) }, kids));
      });
      if (cands.length > limit) {
        list.appendChild(SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Show all ' + cands.length + ' candidates', attrs: { type: 'button' }, on: { click: function () { state.showAll = true; renderCandidates(); } } }));
      }
      if (!cands.length) list.appendChild(callout('warn', [para('No stable pattern was found. The events may be too varied, or the fields were not recognised. Check that the logs include the program, parent program and command line.')]));
    }

    function renderImpact() {
      var box = SK.$('tn-impact'), an = state.analysis;
      SK.clear(box);
      var imp = X.impact(an, state.selected);
      if (!state.selected.length) { box.appendChild(para('Nothing is selected yet.')); return; }
      box.appendChild(callout(imp.remaining.length ? 'warn' : 'good', [
        para('Selected exclusions would hide ' + imp.removed + ' of ' + an.total + ' events. ' + imp.remaining.length + ' would still alert.'),
        imp.remaining.length === 0 ? para('Every pasted event is hidden. Check that this is intended: a rule that never fires on the sample may also be missing something.') : null
      ]));
      if (imp.remaining.length) {
        var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, ['Host', 'Parent', 'Program', 'Command'].map(function (h) { return SK.el('th', { text: h }); }))]);
        imp.remaining.slice(0, 8).forEach(function (it) {
          t.appendChild(SK.el('tr', {}, [it.v.host, it.v.parentImage, it.v.image, it.v.cmd || it.ev._raw].map(function (x) { return SK.el('td', { className: 'mono', text: trunc(x || '', 120) }); })));
        });
        box.appendChild(SK.el('details', { className: 'kit-details', attrs: { open: '' } }, [SK.el('summary', { text: 'Events that would still alert (' + imp.remaining.length + ')' }), SK.el('div', { className: 'kit-table-wrap' }, [t])]));
      }
    }

    /* ---------- checklist and output ---------- */

    var CHECKS = [
      'I searched historical data (30 days at least) for this exact activity and know how often, where and for whom it happens.',
      'I know which product, team or person causes it, and confirmed that it is expected.',
      'I checked that an attacker could not trigger this exclusion by renaming a file, using the same path, or copying the command line.',
      'I will test the exclusion in a non-alerting or staging copy of the rule before it goes live.',
      'I will review or remove this exclusion by the date below.'
    ];

    function buildChecklist() {
      var wrap = SK.el('div', { className: 'kit-panel' });
      wrap.appendChild(SK.el('p', { className: 'sub', text: 'The rule text stays locked until each item is confirmed. This page cannot check any of it for you.' }));
      var grid = SK.el('div', { className: 'kit-cols two' });
      function field(id, label, type, value, placeholder) {
        var inp = SK.el('input', { className: 'kit', attrs: { type: type, id: id, placeholder: placeholder || '' } });
        inp.value = value || '';
        inp.addEventListener('input', renderOutput);
        grid.appendChild(SK.el('div', {}, [SK.el('label', { className: 'kit-label', text: label, attrs: { 'for': id } }), inp]));
      }
      field('tn-ref', 'Ticket or reference', 'text', '', 'e.g. TUNE-123');
      field('tn-reviewer', 'Your name', 'text', '', '');
      field('tn-reviewby', 'Review or remove by', 'date', today(90));
      var sel = SK.el('select', { className: 'kit', attrs: { id: 'tn-lookback' } });
      [['30', '30 days'], ['60', '60 days'], ['90', '90 days'], ['180', '180 days or more']].forEach(function (o) { sel.appendChild(SK.el('option', { text: o[1], attrs: { value: o[0] } })); });
      sel.value = '90';
      sel.addEventListener('change', renderOutput);
      grid.appendChild(SK.el('div', {}, [SK.el('label', { className: 'kit-label', text: 'History you searched', attrs: { 'for': 'tn-lookback' } }), sel]));
      wrap.appendChild(grid);
      CHECKS.forEach(function (text, i) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'tn-ack-' + i } });
        cb.addEventListener('change', renderOutput);
        wrap.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'tn-ack-' + i } }, [cb, text]));
      });
      return wrap;
    }

    function allAcked() {
      for (var i = 0; i < CHECKS.length; i++) { var c = SK.$('tn-ack-' + i); if (!c || !c.checked) return false; }
      return true;
    }

    function renderOutput() {
      var box = SK.$('tn-output');
      if (!box) return;
      SK.clear(box);
      if (!state.selected.length) { box.appendChild(para('Select at least one candidate exclusion.')); return; }
      if (!allAcked()) {
        box.appendChild(callout('warn', [para('Locked. Confirm the checklist above to see the rule text. This is deliberate: a tuning change is only safe after you have checked the history.')]));
        return;
      }
      var an = state.analysis, format = fmtSel.value;
      var chosen = an.candidates.filter(function (c) { return state.selected.indexOf(c.id) >= 0 && !c.blocked; });
      var meta = {
        ref: SK.$('tn-ref').value.trim(), reviewer: SK.$('tn-reviewer').value.trim(), reviewBy: SK.$('tn-reviewby').value,
        lookback: SK.$('tn-lookback').value, basis: an.total + ' pasted events'
      };
      var text = X.generate({ format: format, candidates: chosen, fields: state.fields, meta: meta, ruleText: SK.$('tn-rule').value });

      var show = SK.$('tn-showreal');
      var withReal = show && show.checked && state.map.length;
      if (withReal) text = X.restore(text, state.map);

      var warn = X.overlapWarnings(X.ruleInfo(SK.$('tn-rule').value, format), state.fields, chosen);
      if (warn.length) box.appendChild(callout('warn', [para('Your rule appears to match on the same field(s) these exclusions use (' + warn.join(', ') + '). Check that the exclusion does not switch off the rule\'s own logic.')]));
      if (state.map.length && !withReal) {
        box.appendChild(callout('warn', [para('This text contains generic placeholder values where your real values were. Replace them before use, or tick the box below.')]));
      }
      if (state.map.length) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'tn-showreal' } });
        cb.checked = !!withReal;
        cb.addEventListener('change', renderOutput);
        box.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'tn-showreal' } }, [cb, 'Put my real values back into this text (done in this page only)']));
      }
      box.appendChild(SK.el('div', { className: 'kit-out', text: text }));
      box.appendChild(SK.el('div', { className: 'kit-row' }, [
        SK.copyButton('Copy rule text', function () { return text; }),
        SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Download', attrs: { type: 'button' }, on: { click: function () { SK.download('tuning-exclusion.txt', text, 'text/plain'); } } })
      ]));
      box.appendChild(SK.el('p', { className: 'kit-note', text: 'This text is a starting point. It has not been checked against your platform\'s syntax, so paste it into the rule editor, validate it, and test it before it goes live.' }));
    }

    /* ---------- other buttons ---------- */

    SK.$('tn-sample').addEventListener('click', function () {
      var s = DATA.SAMPLE;
      fmtSel.value = s.format;
      SK.$('tn-alert').value = s.alert; SK.$('tn-rule').value = s.rule; SK.$('tn-logs').value = s.logs;
      state.map = [];
      SK.clear(SK.$('tn-san-out'));
    });
    SK.$('tn-clear').addEventListener('click', function () {
      ['tn-alert', 'tn-rule', 'tn-logs', 'tn-san-terms'].forEach(function (id) { SK.$(id).value = ''; });
      fmtSel.value = '';
      state.map = []; state.analysis = null; state.selected = [];
      SK.clear(SK.$('tn-san-out'));
      SK.clear(SK.$('tn-results'));
      SK.$('tn-results').hidden = true;
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
