// Snort/Suricata tuner page. Captures are read and matched in this browser tab; nothing is sent, saved or cached.
(function () {
  var SK = window.SK = window.SK || {};

  function init() {
    var engSel = SK.$('ids-engine');
    if (!engSel || !SK.idsTune) return;
    var IDS = SK.ids, T = SK.idsTune, DATA = SK.idsData, P = SK.pcap;
    var state = { fp: null, tp: null, an: null, rule: null, alert: null, selected: [], names: {} };

    function chip(text, kind) { return SK.el('span', { className: 'chip2 ' + (kind || ''), text: text }); }
    function callout(kind, kids) { return SK.el('div', { className: 'kit-callout ' + kind }, kids); }
    function para(text) { return SK.el('p', { text: text }); }
    function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
    function range(s) { return !s ? 'none' : (s.min === s.max ? String(s.min) : s.min + ' to ' + s.max); }

    /* ---------- hiding real addresses ---------- */

    var maskMap = {};
    function mask(text) {
      if (!SK.$('ids-mask').checked) return text;
      return String(text).replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/gi, function (ip) {
        if (/^\d+(?:\.\d+){3}$/.test(ip) && ip.split('.').some(function (n) { return +n > 255; })) return ip;
        if (!maskMap[ip]) {
          var n = Object.keys(maskMap).length + 1;
          maskMap[ip] = ip.indexOf(':') >= 0 ? '2001:db8::' + n.toString(16) : '192.0.2.' + (((n - 1) % 253) + 1);
        }
        return maskMap[ip];
      });
    }

    /* ---------- education ---------- */

    (function education() {
      function table(rows, heads) {
        var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, heads.map(function (h) { return SK.el('th', { text: h }); }))]);
        rows.forEach(function (x) { t.appendChild(SK.el('tr', {}, x.map(function (c, i) { return SK.el('td', { className: i === 0 && heads.length === 3 ? 'mono' : '', text: c }); }))); });
        return SK.el('div', { className: 'kit-table-wrap' }, [t]);
      }
      SK.$('ids-cheat').appendChild(table(DATA.CHEATSHEET, ['Keyword', 'What it does', 'Engine notes']));
      SK.$('ids-abnormal').appendChild(table(DATA.ABNORMAL, ['Activity', 'Why it matters']));
      SK.$('ids-routine').appendChild(table(DATA.ROUTINE, ['Activity', 'How to tune it safely']));
      var ol = SK.el('ol'); DATA.HISTORICAL.forEach(function (x) { ol.appendChild(SK.el('li', { text: x })); });
      SK.$('ids-historical').appendChild(ol);
    })();

    /* ---------- captures ---------- */

    function describeCap(cap, name) {
      var kinds = {}; cap.sessions.forEach(function (s) { kinds[s.proto] = (kinds[s.proto] || 0) + 1; });
      var parts = Object.keys(kinds).map(function (k) { return kinds[k] + ' ' + k.toUpperCase(); });
      var span = cap.end && cap.start ? Math.max(0, Math.round((cap.end - cap.start) / 1000)) + ' seconds' : 'unknown span';
      return name + ': ' + cap.format.toUpperCase() + ', ' + plural(cap.packetCount, 'packet') + ', ' + plural(cap.sessions.length, 'conversation') + ' (' + (parts.join(', ') || 'none') + '), ' + span + '.';
    }

    function showCap(which, cap, name) {
      var box = SK.$('ids-' + which + '-info'); SK.clear(box);
      if (!cap) return;
      box.appendChild(para(describeCap(cap, name)));
      (cap.warnings || []).forEach(function (w) { box.appendChild(callout('warn', [para(w)])); });
      if (cap.skipped) box.appendChild(para(cap.skipped + ' packets were not IP traffic or were fragments, and were skipped.'));
      if (cap.stats && cap.stats.gaps) box.appendChild(callout('warn', [para('Missing TCP segments in this capture: ' + cap.stats.gaps + '. Positions after a gap may be off.')]));
    }

    function loadBytes(which, bytes, name) {
      return P.read(bytes).then(function (cap) { state[which] = cap; state.names[which] = name; showCap(which, cap, name); }, function (e) {
        state[which] = null; var box = SK.$('ids-' + which + '-info'); SK.clear(box);
        box.appendChild(callout('bad', [para(name + ' could not be read. ' + (e.userMessage || 'It is not a PCAP or PCAPNG file.'))]));
      });
    }

    ['fp', 'tp'].forEach(function (which) {
      SK.$('ids-' + which + '-file').addEventListener('change', function (ev) {
        var f = ev.target.files[0];
        if (!f) { state[which] = null; showCap(which, null); return; }
        if (f.size > 64 * 1024 * 1024) { var b = SK.$('ids-' + which + '-info'); SK.clear(b); b.appendChild(callout('bad', [para('That file is over 64 MB. Trim it to the traffic around the alert (for example with editcap or tcpdump) and try again.')])); return; }
        SK.readFile(f).then(function (buf) { return loadBytes(which, new Uint8Array(buf), f.name); });
      });
    });

    /* ---------- examples ---------- */

    var exBox = SK.$('ids-examples');
    DATA.EXAMPLES.forEach(function (ex) {
      var b = SK.el('button', { className: 'btn btn-ghost', text: ex.title, attrs: { type: 'button', title: ex.blurb } });
      b.addEventListener('click', function () {
        engSel.value = ex.engine; SK.$('ids-rule').value = ex.rule; SK.$('ids-alert').value = ex.alert;
        SK.$('ids-fp-file').value = ''; SK.$('ids-tp-file').value = '';
        var caps = ex.build(SK.pcapBuild);
        Promise.all([loadBytes('fp', caps.fp, 'Example false-positive capture'), loadBytes('tp', caps.tp, 'Example true-positive capture')]).then(function () {
          SK.$('ids-example-note').textContent = ex.blurb;
          run();
        });
      });
      exBox.appendChild(b);
    });

    SK.$('ids-clear').addEventListener('click', function () {
      ['ids-rule', 'ids-alert'].forEach(function (id) { SK.$(id).value = ''; });
      SK.$('ids-fp-file').value = ''; SK.$('ids-tp-file').value = '';
      state.fp = state.tp = state.an = null; maskMap = {};
      ['fp', 'tp'].forEach(function (w) { SK.clear(SK.$('ids-' + w + '-info')); });
      SK.$('ids-example-note').textContent = '';
      SK.$('ids-results').hidden = true; SK.clear(SK.$('ids-results'));
    });

    /* ---------- running the analysis ---------- */

    function problem(msg) {
      var res = SK.$('ids-results'); SK.clear(res); res.hidden = false;
      res.appendChild(callout('bad', [para(msg)]));
    }

    function run() {
      var engine = engSel.value, text = SK.$('ids-rule').value.trim();
      if (!engine) return problem('Choose your engine first. Snort 2, Snort 3 and Suricata write the same rule differently, so the suggested text depends on it.');
      if (!text) return problem('Paste the rule that fired.');
      if (!state.fp) return problem('Add the false-positive capture (the traffic that should not have alerted).');
      var parsed = IDS.parseRules(text, engine);
      if (!parsed.length) return problem('No rule found. A rule starts with an action such as alert and has options in brackets.');
      if (!parsed[0].ok) return problem('The rule could not be read: ' + parsed[0].error);
      var notes = [];
      var rule = parsed[0].rule;
      var sid = null;
      var alert = SK.$('ids-alert').value.trim() ? T.parseAlert(SK.$('ids-alert').value) : null;
      if (alert && alert.kind === 'unknown') { notes.push('The alert text was not recognized (it should be EVE JSON, a Suricata fast.log line or a Snort alert_fast line). Continuing without it.'); alert = null; }
      if (alert && alert.sid && rule.sid && +alert.sid !== +rule.sid) notes.push('The alert is for rule ' + alert.sid + ' but the rule you pasted is ' + rule.sid + '. Make sure they belong together.');
      if (parsed.length > 1) notes.push('You pasted ' + parsed.length + ' rules. Only the first one is analyzed.');
      var an;
      try { an = T.analyze({ rule: rule, engine: engine, fp: state.fp, tp: state.tp, alert: alert }); }
      catch (e) { return problem('Something went wrong while analyzing: ' + e.message); }
      state.an = an; state.rule = rule; state.alert = alert; maskMap = {};
      an.notes = notes.concat(an.notes);
      state.selected = an.steps.length ? an.steps.map(function (s) { return s.id; }) : (an.recs.length && an.recs[0].effect && an.recs[0].effect.removesFp > 0 && an.recs[0].effect.keepsTp !== false ? [an.recs[0].id] : []);
      render();
    }
    SK.$('ids-run').addEventListener('click', run);
    ['ids-mask'].forEach(function (id) { SK.$(id).addEventListener('change', function () { if (state.an) render(); }); });

    /* ---------- rendering ---------- */

    function effectChips(e) {
      var out = [];
      if (!e) return out;
      out.push(chip('False positives ' + e.fpBefore + ' to ' + e.fpAfter, e.fpAfter === 0 ? 'good' : (e.fpAfter < e.fpBefore ? 'warn' : '')));
      if (e.tpBefore !== null && e.tpBefore !== undefined) out.push(chip('Real activity ' + (e.keepsTp === false ? 'LOST (' + e.tpBefore + ' to ' + e.tpAfter + ')' : 'still detected'), e.keepsTp === false ? 'bad' : 'good'));
      else out.push(chip('Not checked against real activity', 'warn'));
      return out;
    }
    function riskChip(r) { return chip(r + ' risk', r === 'low' ? 'good' : (r === 'medium' ? 'warn' : 'bad')); }

    function ctxLine(m) {
      return SK.el('div', { className: 'kit-ctx mono' }, [
        SK.el('span', { text: mask(m.before) }), SK.el('span', { className: 'kit-hit', text: mask(m.matched) }), SK.el('span', { text: mask(m.after) })]);
    }

    function evidenceList(list, title, total) {
      var wrap = SK.el('div', {});
      wrap.appendChild(SK.el('h3', { text: title }));
      list.forEach(function (ev) {
        var head = ev.client.ip + ':' + ev.client.port + (ev.dir === 'toServer' ? ' to ' : ' from ') + ev.server.ip + ':' + ev.server.port + ' (' + ev.proto.toUpperCase() + ', ' + (ev.dir === 'toServer' ? 'client to server' : 'server to client') + ')';
        var kids = [SK.el('h4', { text: mask(head) })];
        if (ev.line) kids.push(SK.el('div', { className: 'kit-note mono', text: mask(ev.line) }));
        ev.matches.forEach(function (m) {
          kids.push(SK.el('p', { className: 'kit-note', text: m.label + ' matched at byte ' + m.start + ' to ' + m.end + ' of ' + m.bufferLabel + (m.bufLen ? ' (' + m.bufLen + ' bytes long)' : '') + (m.prevEnd ? ', ' + (m.start - m.prevEnd) + ' bytes after the previous match' : '') }));
          kids.push(ctxLine(m));
        });
        wrap.appendChild(SK.el('div', { className: 'kit-result' }, kids));
      });
      if (total > list.length) wrap.appendChild(para('Showing the first ' + list.length + ' of ' + total + ' alerts.'));
      return wrap;
    }

    function positionTable(label, rows) {
      if (!rows.length || !rows.some(function (r) { return r.count; })) return null;
      var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, ['Content', 'Buffer', 'Hits', 'Starts at byte', 'Ends at byte', 'Bytes after previous'].map(function (h) { return SK.el('th', { text: h }); }))]);
      rows.forEach(function (r) {
        t.appendChild(SK.el('tr', {}, [SK.el('td', { className: 'mono', text: r.label }), SK.el('td', { text: IDS.bufferLabel(r.buffer) }), SK.el('td', { className: 'num', text: String(r.count) }),
          SK.el('td', { className: 'num', text: range(r.starts) }), SK.el('td', { className: 'num', text: range(r.ends) }), SK.el('td', { className: 'num', text: r.gaps ? range(r.gaps) : 'n/a' })]));
      });
      return SK.el('div', {}, [SK.el('h3', { text: label }), SK.el('div', { className: 'kit-table-wrap' }, [t])]);
    }

    function render() {
      var an = state.an, res = SK.$('ids-results'); SK.clear(res); res.hidden = false;
      var engineName = { suricata: 'Suricata', snort3: 'Snort 3', snort2: 'Snort 2' }[an.engine];

      // summary
      var sum = [para('Rule ' + (state.rule.sid || '(no sid)') + ' for ' + engineName + '. It fired ' + plural(an.fp.alerts, 'time') + ' in ' + plural(an.fp.sessions, 'conversation') + ' of the false-positive capture (' + an.fp.total + ' conversations)' +
        (an.tp ? ' and ' + plural(an.tp.alerts, 'time') + ' in ' + plural(an.tp.sessions, 'conversation') + ' of the true-positive capture.' : '.'))];
      if (state.alert && state.alert.kind !== 'unknown') {
        sum.push(para(an.alertSessions.length ? 'The alert you pasted matches ' + plural(an.alertSessions.length, 'conversation') + ' in the false-positive capture.' : 'The alert you pasted was not found in the false-positive capture (the addresses, ports or times do not line up). The analysis uses everything the rule matched instead.'));
      }
      res.appendChild(SK.el('div', { className: 'kit-panel' }, [SK.el('h2', { text: '5. What we found' })].concat(sum)));

      an.notes.forEach(function (n) { res.lastChild.appendChild(callout('warn', [para(n)])); });
      an.unsupported.length && res.lastChild.appendChild(callout('warn', [para('Not simulated (kept as written): ' + an.unsupported.join(', ') + '.')]));

      if (an.noFpHit) {
        var reasons = (an.fp.reasons || []).slice(0, 8);
        var kids = [para('The rule did not fire on the false-positive capture in this simulation, so there is nothing to tune from here.')];
        if (reasons.length) { var ul = SK.el('ul'); reasons.forEach(function (r) { ul.appendChild(SK.el('li', { text: r })); }); kids.push(para('Why it may not have matched:')); kids.push(ul); }
        kids.push(para('Check the engine choice, that the capture contains the alert, and that the rule is complete (the simulator supports a subset of rule options).'));
        res.lastChild.appendChild(callout('bad', kids));
        return;
      }
      if (an.noTpHit) {
        var rs = (an.tp.reasons || []).slice(0, 6);
        var k2 = [para('The rule did not fire on the true-positive capture, so recommendations cannot be checked against real activity.')];
        if (rs.length) { var ul2 = SK.el('ul'); rs.forEach(function (r) { ul2.appendChild(SK.el('li', { text: r })); }); k2.push(ul2); }
        res.lastChild.appendChild(callout('warn', k2));
      }

      // evidence
      var evp = SK.el('div', { className: 'kit-panel' }, [SK.el('h2', { text: '6. Why it fired' }), SK.el('p', { className: 'sub', text: 'The highlighted text is what the rule matched. Positions count from byte 0 of the buffer the content searched.' })]);
      evp.appendChild(evidenceList(an.evidence.fp, 'False positives', an.fp.alerts));
      if (an.evidence.tp.length) evp.appendChild(evidenceList(an.evidence.tp, 'Real activity', an.tp.alerts));
      var fpTab = positionTable('Where the rule matched in the false positives', T.positionTable(state.rule, an.fpAlerts));
      var tpTab = an.tpAlerts.length ? positionTable('Where the rule matched in the real activity', T.positionTable(state.rule, an.tpAlerts)) : null;
      if (fpTab) evp.appendChild(fpTab);
      if (tpTab) evp.appendChild(tpTab);
      res.appendChild(evp);

      // MITRE ATT&CK
      var ct = /classtype\s*:\s*([\w-]+)/i.exec(state.rule.raw);
      var att = SK.attackPanel ? SK.attackPanel(state.rule.raw + ' ' + (state.alert ? state.alert.msg + ' ' + state.alert.classification : ''), { classtype: ct ? ct[1] : '' }) : null;
      if (att) res.appendChild(att);

      // recommendations
      var rp = SK.el('div', { className: 'kit-panel' }, [SK.el('h2', { text: '7. Recommended changes' }),
        SK.el('p', { className: 'sub', text: 'Each change was re-run against your captures. Tick the ones you want in the tuned rule below.' })]);
      var list = SK.el('div', { className: 'kit-results' });
      if (!an.recs.length) list.appendChild(callout('warn', [para('No rule change separates these captures with the evidence given. See the other options below, and consider whether the rule needs tuning at all.')]));
      an.recs.forEach(function (rec) { list.appendChild(recCard(rec, true)); });
      rp.appendChild(list);
      if (an.others.length) {
        rp.appendChild(SK.el('h3', { text: 'Other options' }));
        rp.appendChild(SK.el('p', { className: 'sub', text: 'These do not change what the rule matches, or they reduce coverage. Use them when rule changes are not enough.' }));
        var l2 = SK.el('div', { className: 'kit-results' });
        an.others.forEach(function (o) { l2.appendChild(recCard(o, !!o.apply)); });
        rp.appendChild(l2);
      }
      res.appendChild(rp);

      // checklist + output
      var op = SK.el('div', { className: 'kit-panel', attrs: { id: 'ids-output-panel' } }, [SK.el('h2', { text: '8. Your tuned rule' })]);
      op.appendChild(SK.el('p', { className: 'sub', text: 'The rule text stays locked until each item is confirmed. This page cannot check any of it for you.' }));
      DATA.CHECKS.forEach(function (c, i) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'ids-ack-' + i } });
        cb.addEventListener('change', renderOutput);
        op.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'ids-ack-' + i } }, [cb, c]));
      });
      op.appendChild(SK.el('div', { attrs: { id: 'ids-output' } }));
      res.appendChild(op);
      renderOutput();
    }

    function recCard(rec, selectable) {
      var e = rec.effect, bad = e && e.keepsTp === false;
      var kids = [];
      var head = SK.el('h4', {});
      if (selectable) {
        var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'ids-rec-' + rec.id, 'aria-label': 'Include in tuned rule' } });
        cb.checked = state.selected.indexOf(rec.id) >= 0;
        cb.addEventListener('change', function () {
          var i = state.selected.indexOf(rec.id);
          if (cb.checked && i < 0) state.selected.push(rec.id);
          if (!cb.checked && i >= 0) state.selected.splice(i, 1);
          renderOutput();
        });
        head.appendChild(cb);
      }
      head.appendChild(SK.el('span', { text: rec.title }));
      kids.push(head);
      var chips = SK.el('div', { className: 'kit-chips' }, effectChips(e).concat([riskChip(rec.risk || 'medium')]));
      kids.push(chips);
      kids.push(SK.el('div', { className: 'kit-out', text: rec.change }));
      (rec.why || []).forEach(function (w) { kids.push(para(w)); });
      if (rec.warn) kids.push(callout('warn', [para(rec.warn)]));
      (rec.warnings || []).forEach(function (w) { kids.push(para(w)); });
      return SK.el('div', { className: 'kit-result ' + (bad ? 'bad' : (rec.risk === 'high' ? 'warn' : 'good')) }, kids);
    }

    function acknowledged() {
      for (var i = 0; i < DATA.CHECKS.length; i++) { var c = SK.$('ids-ack-' + i); if (!c || !c.checked) return false; }
      return true;
    }

    function renderOutput() {
      var box = SK.$('ids-output'); if (!box || !state.an) return;
      SK.clear(box);
      if (!acknowledged()) { box.appendChild(callout('warn', [para('Locked. Confirm the checklist above to see the rule text. This is deliberate: a tuning change is only safe after you have checked the history.')])); return; }
      var an = state.an, picked = state.selected.slice();
      if (!picked.length) { box.appendChild(callout('warn', [para('Nothing is selected. Tick at least one change above, or keep the original rule.')])); }
      var comp = picked.length ? an.compose(picked) : null;
      var text = comp ? comp.ruleText : state.rule.raw;
      if (comp && comp.effect.keepsTp === false) box.appendChild(callout('bad', [para('With this selection the rule no longer detects the real activity in your true-positive capture. Do not use it.')]));
      if (comp) box.appendChild(SK.el('div', { className: 'kit-chips' }, effectChips(comp.effect)));
      if (comp && !an.hasTp) box.appendChild(callout('warn', [para('No true-positive capture was provided, so this rule is unverified against real attack traffic. Treat the numbers as suggestions only.')]));
      box.appendChild(SK.el('h3', { text: 'Original rule' }));
      box.appendChild(SK.el('div', { className: 'kit-out', text: mask(state.rule.raw) }));
      if (comp) {
        box.appendChild(SK.el('h3', { text: 'Tuned rule' }));
        box.appendChild(SK.el('div', { className: 'kit-out', text: mask(text) }));
        (comp.warnings || []).forEach(function (w) { box.appendChild(callout('warn', [para(w)])); });
        box.appendChild(SK.el('div', { className: 'kit-row' }, [SK.copyButton('Copy tuned rule', function () { return mask(text); })]));
        var v = T.verifyCommands(an.engine);
        box.appendChild(SK.el('h3', { text: 'Test it with the engine' }));
        box.appendChild(SK.el('div', { className: 'kit-out', text: v[0] }));
        box.appendChild(para(v[1]));
        box.appendChild(SK.el('p', { className: 'kit-note', text: 'The numbers above come from a simulation that supports a subset of rule options. The engine is the final judge: run the command on both captures before you deploy the rule. Replace the generic addresses with your own if you masked them.' }));
      }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
