// Incident note builder (SK.report). Fill the form, copy the Markdown. Nothing is stored or sent.
(function () {
  var SK = window.SK = window.SK || {};
  var R = SK.report = {};

  R.FIELDS = ['title', 'severity', 'status', 'detected', 'analyst', 'summary', 'impact', 'timeline', 'indicators', 'actions', 'recommendations', 'open'];

  function section(title, body) {
    return '## ' + title + '\n' + (body && body.trim() ? body.trim() : '_Not provided._') + '\n';
  }

  R.toMarkdown = function (v) {
    var out = ['# ' + (v.title || 'Incident note'), ''];
    out.push('- **Severity:** ' + (v.severity || 'Not set'));
    out.push('- **Status:** ' + (v.status || 'Not set'));
    out.push('- **First detected (UTC):** ' + (v.detected || 'Not set'));
    out.push('- **Analyst:** ' + (v.analyst || 'Not set'));
    out.push('- **Written (UTC):** ' + new Date().toISOString(), '');
    out.push(section('Summary', v.summary));
    out.push(section('Impact and scope', v.impact));
    var tl = (v.timeline || '').split('\n').map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) { return '- ' + l; }).join('\n');
    out.push(section('Timeline (UTC)', tl));
    var ind = (v.indicators || '').split('\n').map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) { return '- `' + (SK.ioc ? SK.ioc.defang(l) : l) + '`'; }).join('\n');
    out.push(section('Indicators (defanged)', ind));
    out.push(section('Actions taken', v.actions));
    out.push(section('Recommendations', v.recommendations));
    out.push(section('Open questions', v.open));
    return out.join('\n');
  };

  function init() {
    if (!SK.$('rep-title')) return;
    function values() {
      var v = {};
      R.FIELDS.forEach(function (f) { v[f] = SK.$('rep-' + f).value; });
      return v;
    }
    function update() { SK.$('rep-out').textContent = R.toMarkdown(values()); }
    R.FIELDS.forEach(function (f) { SK.$('rep-' + f).addEventListener('input', update); SK.$('rep-' + f).addEventListener('change', update); });
    SK.$('rep-copy').addEventListener('click', function () { SK.copyText(SK.$('rep-out').textContent); });
    SK.$('rep-download').addEventListener('click', function () { SK.download('incident-note.md', SK.$('rep-out').textContent, 'text/markdown'); });
    SK.$('rep-now').addEventListener('click', function () { SK.$('rep-detected').value = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); update(); });
    SK.$('rep-extract').addEventListener('click', function () {
      if (!SK.ioc) return;
      var res = SK.ioc.extract(SK.$('rep-summary').value + '\n' + SK.$('rep-timeline').value + '\n' + SK.$('rep-actions').value);
      var all = [];
      ['ips', 'ipv6', 'domains', 'urls', 'emails', 'md5', 'sha1', 'sha256', 'sha512', 'cves'].forEach(function (k) { all = all.concat(res[k]); });
      if (!all.length) { SK.toast('No indicators found in the summary, timeline or actions'); return; }
      var existing = SK.$('rep-indicators').value.split('\n').map(function (l) { return l.trim(); });
      all.forEach(function (x) { if (existing.indexOf(x) < 0) existing.push(x); });
      SK.$('rep-indicators').value = existing.filter(Boolean).join('\n');
      update();
    });
    update();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
