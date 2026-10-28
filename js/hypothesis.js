// Hypothesis worksheet (SK.ach): a simplified Analysis of Competing Hypotheses.
// Nothing is stored in the browser. Use Export to keep your work.
(function () {
  var SK = window.SK = window.SK || {};
  var A = SK.ach = {};

  // Ratings: C consistent, I inconsistent, N neutral / not applicable
  A.score = function (state) {
    return state.hypotheses.map(function (h) {
      var against = 0, support = 0, answered = 0;
      state.evidence.forEach(function (e) {
        var r = e.ratings[h.id], w = e.weight || 1;
        if (r === 'I') { against += w; answered++; }
        else if (r === 'C') { support += w; answered++; }
        else if (r === 'N') { answered++; }
      });
      return { id: h.id, label: h.label, against: against, support: support, answered: answered };
    });
  };

  // Evidence that fits every hypothesis cannot tell them apart.
  A.diagnostic = function (state) {
    return state.evidence.map(function (e) {
      var set = {};
      state.hypotheses.forEach(function (h) { set[e.ratings[h.id] || '-'] = true; });
      var keys = Object.keys(set);
      return { id: e.id, low: keys.length === 1 && keys[0] !== '-' };
    });
  };

  A.toMarkdown = function (state) {
    var scores = A.score(state), lines = [];
    lines.push('# Hypothesis worksheet', '');
    lines.push('**Question:** ' + (state.question || '(not set)'), '');
    lines.push('## Hypotheses');
    state.hypotheses.forEach(function (h, i) { lines.push((i + 1) + '. ' + h.label); });
    lines.push('', '## Evidence matrix', '');
    lines.push('| Evidence | Weight | Source | ' + state.hypotheses.map(function (h, i) { return 'H' + (i + 1); }).join(' | ') + ' |');
    lines.push('|---|---|---|' + state.hypotheses.map(function () { return '---'; }).join('|') + '|');
    state.evidence.forEach(function (e) {
      lines.push('| ' + e.text.replace(/\|/g, '/') + ' | ' + e.weight + ' | ' + (e.source || '').replace(/\|/g, '/') + ' | ' + state.hypotheses.map(function (h) { return e.ratings[h.id] || '-'; }).join(' | ') + ' |');
    });
    lines.push('', '(C = consistent, I = inconsistent, N = neutral)', '', '## Score (weight of evidence against; lower is better)');
    scores.slice().sort(function (a, b) { return a.against - b.against; }).forEach(function (s) {
      lines.push('- ' + s.label + ': ' + s.against + ' against, ' + s.support + ' supporting');
    });
    lines.push('', '## Assessment');
    lines.push('- Leading hypothesis: ' + (state.lead || '(not chosen)'));
    lines.push('- Likelihood term: ' + (state.term || '(not chosen)'));
    lines.push('- Confidence in the sources and reasoning: ' + (state.confidence || '(not chosen)'));
    lines.push('', '## What would change my mind', state.changeMind || '(not filled in)');
    lines.push('', '## Assumptions', state.assumptions || '(not filled in)');
    lines.push('', '## Next steps and data still needed', state.next || '(not filled in)');
    return lines.join('\n');
  };

  var TERMS = [
    ['', '(choose)'],
    ['Almost no chance (1-5%)', 'Almost no chance (1-5%)'], ['Very unlikely (5-20%)', 'Very unlikely (5-20%)'],
    ['Unlikely (20-45%)', 'Unlikely (20-45%)'], ['Roughly even chance (45-55%)', 'Roughly even chance (45-55%)'],
    ['Likely (55-80%)', 'Likely (55-80%)'], ['Very likely (80-95%)', 'Very likely (80-95%)'], ['Almost certain (95-99%)', 'Almost certain (95-99%)']
  ];

  function blank() {
    return {
      question: '', hypotheses: [{ id: 'h1', label: '' }, { id: 'h2', label: '' }], evidence: [{ id: 'e1', text: '', weight: 2, source: '', ratings: {} }],
      lead: '', term: '', confidence: '', changeMind: '', assumptions: '', next: '', seq: 3
    };
  }

  function init() {
    var host = SK.$('ach-matrix');
    if (!host) return;
    var state = blank();

    function field(id, key) {
      var el = SK.$(id);
      el.value = state[key] || '';
      el.addEventListener('input', function () { state[key] = el.value; renderScores(); });
    }

    function renderMatrix() {
      SK.clear(host);
      var t = SK.el('table', { className: 'kit-table kit-matrix' });
      var head = SK.el('tr', {}, [SK.el('th', { text: 'Evidence' }), SK.el('th', { text: 'Weight' }), SK.el('th', { text: 'Source' })]);
      state.hypotheses.forEach(function (h, i) {
        var inp = SK.el('input', { className: 'kit', attrs: { type: 'text', 'aria-label': 'Hypothesis ' + (i + 1), placeholder: 'H' + (i + 1) + ': e.g. phishing', value: h.label } });
        inp.value = h.label;
        inp.addEventListener('input', function () { h.label = inp.value; renderScores(); renderLead(); });
        var rm = SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Remove', attrs: { type: 'button', 'aria-label': 'Remove hypothesis ' + (i + 1) }, on: { click: function () {
          if (state.hypotheses.length <= 2) { SK.toast('Keep at least two hypotheses'); return; }
          state.hypotheses.splice(i, 1); renderMatrix(); renderScores(); renderLead();
        } } });
        head.appendChild(SK.el('th', {}, [inp, rm]));
      });
      head.appendChild(SK.el('th', { text: '' }));
      t.appendChild(head);

      var notes = [];
      // Update the "fits every hypothesis" notes in place so keyboard focus is not lost.
      function updateNotes() {
        var d = A.diagnostic(state);
        notes.forEach(function (n, i) { n.hidden = !(d[i] && d[i].low); });
      }
      var diag = A.diagnostic(state);
      state.evidence.forEach(function (e, ei) {
        var txt = SK.el('input', { className: 'kit', attrs: { type: 'text', 'aria-label': 'Evidence ' + (ei + 1), placeholder: 'A fact you observed' } });
        txt.value = e.text;
        txt.addEventListener('input', function () { e.text = txt.value; });
        var w = SK.el('select', { className: 'kit', attrs: { 'aria-label': 'Weight of evidence ' + (ei + 1) } }, [
          SK.el('option', { text: 'High (3)', attrs: { value: '3' } }), SK.el('option', { text: 'Medium (2)', attrs: { value: '2' } }), SK.el('option', { text: 'Low (1)', attrs: { value: '1' } })
        ]);
        w.value = String(e.weight);
        w.addEventListener('change', function () { e.weight = parseInt(w.value, 10); renderScores(); });
        var src = SK.el('input', { className: 'kit', attrs: { type: 'text', 'aria-label': 'Source of evidence ' + (ei + 1), placeholder: 'Log, ticket, interview...' } });
        src.value = e.source;
        src.addEventListener('input', function () { e.source = src.value; });
        var note = SK.el('p', { className: 'kit-note', text: 'Fits every hypothesis, so it does not help you choose between them.' });
        note.hidden = !diag[ei].low;
        notes.push(note);
        var row = SK.el('tr', {}, [SK.el('td', {}, [txt, note]), SK.el('td', {}, [w]), SK.el('td', {}, [src])]);
        state.hypotheses.forEach(function (h) {
          var sel = SK.el('select', { className: 'kit', attrs: { 'aria-label': 'Evidence ' + (ei + 1) + ' against hypothesis ' + h.label } }, [
            SK.el('option', { text: '-', attrs: { value: '' } }), SK.el('option', { text: 'Consistent', attrs: { value: 'C' } }),
            SK.el('option', { text: 'Inconsistent', attrs: { value: 'I' } }), SK.el('option', { text: 'Neutral', attrs: { value: 'N' } })
          ]);
          sel.value = e.ratings[h.id] || '';
          sel.addEventListener('change', function () { e.ratings[h.id] = sel.value; renderScores(); updateNotes(); });
          row.appendChild(SK.el('td', {}, [sel]));
        });
        row.appendChild(SK.el('td', {}, [SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Remove', attrs: { type: 'button', 'aria-label': 'Remove evidence ' + (ei + 1) }, on: { click: function () {
          state.evidence.splice(ei, 1); renderMatrix(); renderScores();
        } } })]));
        t.appendChild(row);
      });
      host.appendChild(SK.el('div', { className: 'kit-table-wrap' }, [t]));
    }

    function renderScores() {
      var box = SK.$('ach-scores');
      SK.clear(box);
      var scores = A.score(state), max = 1;
      scores.forEach(function (s) { max = Math.max(max, s.against, s.support); });
      var sorted = scores.slice().sort(function (a, b) { return a.against - b.against || b.support - a.support; });
      sorted.forEach(function (s, i) {
        var anyRated = s.answered > 0;
        box.appendChild(SK.el('div', { className: 'kit-result ' + (i === 0 && anyRated ? 'good' : '') }, [
          SK.el('h4', {}, [s.label || '(unnamed hypothesis)', i === 0 && anyRated ? SK.el('span', { className: 'chip2 good', text: 'least evidence against' }) : null]),
          SK.el('p', { className: 'kit-note', text: s.against + ' weight against, ' + s.support + ' weight supporting, ' + s.answered + ' of ' + state.evidence.length + ' pieces of evidence rated' }),
          (function () {
            var bar = SK.el('div', { className: 'kit-bar bad' }, [SK.el('span')]);
            bar.firstChild.style.width = Math.round(s.against / max * 100) + '%';
            return bar;
          })()
        ]));
      });
    }

    function renderLead() {
      var sel = SK.$('ach-lead'), cur = state.lead;
      SK.clear(sel);
      sel.appendChild(SK.el('option', { text: '(choose)', attrs: { value: '' } }));
      state.hypotheses.forEach(function (h) { if (h.label) sel.appendChild(SK.el('option', { text: h.label, attrs: { value: h.label } })); });
      sel.value = cur;
      if (sel.value !== cur) { state.lead = ''; sel.value = ''; }
    }

    SK.$('ach-add-h').addEventListener('click', function () {
      if (state.hypotheses.length >= 6) { SK.toast('Six hypotheses is the limit'); return; }
      state.hypotheses.push({ id: 'h' + (state.seq++), label: '' }); renderMatrix(); renderScores();
    });
    SK.$('ach-add-e').addEventListener('click', function () {
      state.evidence.push({ id: 'e' + (state.seq++), text: '', weight: 2, source: '', ratings: {} }); renderMatrix();
    });

    field('ach-question', 'question');
    ['ach-change', 'ach-assume', 'ach-next'].forEach(function (id, i) { field(id, ['changeMind', 'assumptions', 'next'][i]); });
    TERMS.forEach(function (t) { SK.$('ach-term').appendChild(SK.el('option', { text: t[1], attrs: { value: t[0] } })); });
    SK.$('ach-term').addEventListener('change', function () { state.term = SK.$('ach-term').value; });
    SK.$('ach-conf').addEventListener('change', function () { state.confidence = SK.$('ach-conf').value; });
    SK.$('ach-lead').addEventListener('change', function () { state.lead = SK.$('ach-lead').value; });

    SK.$('ach-copy').addEventListener('click', function () { SK.copyText(A.toMarkdown(state)); });
    SK.$('ach-md').addEventListener('click', function () { SK.download('hypothesis-worksheet.md', A.toMarkdown(state), 'text/markdown'); });
    SK.$('ach-save').addEventListener('click', function () { SK.download('hypothesis-worksheet.json', JSON.stringify(state, null, 2), 'application/json'); });
    SK.$('ach-load').addEventListener('change', function (e) {
      var f = e.target.files[0];
      if (!f) return;
      var r = new FileReader();
      r.onload = function () {
        try {
          var s = JSON.parse(r.result);
          if (!s || !Array.isArray(s.hypotheses) || !Array.isArray(s.evidence)) throw new Error('bad file');
          state = Object.assign(blank(), s);
          SK.$('ach-question').value = state.question; SK.$('ach-change').value = state.changeMind;
          SK.$('ach-assume').value = state.assumptions; SK.$('ach-next').value = state.next;
          SK.$('ach-term').value = state.term; SK.$('ach-conf').value = state.confidence;
          renderMatrix(); renderScores(); renderLead();
          SK.toast('Worksheet loaded');
        } catch (err) { SK.toast('That file is not a worksheet saved from this page'); }
      };
      r.readAsText(f);
    });
    SK.$('ach-reset').addEventListener('click', function () {
      state = blank();
      ['ach-question', 'ach-change', 'ach-assume', 'ach-next'].forEach(function (id) { SK.$(id).value = ''; });
      SK.$('ach-term').value = ''; SK.$('ach-conf').value = '';
      renderMatrix(); renderScores(); renderLead();
    });

    renderMatrix(); renderScores(); renderLead();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
