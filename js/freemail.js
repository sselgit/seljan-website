// Free, disposable and ISP email check. The list is built in, so the first table needs no network.
// The optional second step asks public DNS which provider actually hosts a domain's mail.
(function () {
  var SK = window.SK = window.SK || {};
  if (!SK.nl || !SK.lu) return;
  var NL = SK.nl, LU = SK.lu;

  var MEANING = {
    free: ['Free email provider', 'Anyone can get an address here for free, so it says little about who the sender is. Common for personal mail and for impersonation.', 'warn'],
    disposable: ['Disposable email provider', 'Addresses are throwaway and often anonymous. Frequently used for sign-up abuse, spam and one-off scams.', 'bad'],
    isp: ['Internet provider mailbox', 'Mail from a consumer internet provider. Tied to a paying customer, but not a business domain.', ''],
    none: ['Not on the list', 'Not a known free, disposable or consumer provider. It is probably a business or personal domain, but the list is short and cannot be complete.', 'good']
  };

  function targets(raw) {
    var seen = {}, out = [];
    String(raw).split(/[\s,;]+/).filter(Boolean).slice(0, 50).forEach(function (tk) {
      var v = (window.SKRoute ? window.SKRoute.refang(tk) : tk).trim();
      var c = NL.classifyEmailDomain(v);
      if (!c.domain || seen[c.domain]) return;
      seen[c.domain] = true;
      out.push({ input: tk, domain: c.domain, category: c.category });
    });
    return out;
  }

  function init() {
    if (!SK.$('fm-in')) return;
    var out = SK.$('fm-out'), mxOut = SK.$('fm-mx-out'), last = [];

    function run(raw) {
      SK.clear(out); SK.clear(mxOut);
      last = targets(raw);
      SK.$('fm-mx').hidden = !last.length;
      if (!last.length) { out.appendChild(LU.callout('warn', ['Enter an email address or a domain, one per line.'])); return; }
      out.appendChild(LU.table(['Input', 'Domain', 'Category', 'What it means'], last.map(function (t) {
        var m = MEANING[t.category];
        return [t.input, t.domain, LU.chip(m[0], m[2]), m[1]];
      }), [0, 1]));
    }
    SK.$('fm-run').addEventListener('click', function () { run(SK.$('fm-in').value); });

    SK.$('fm-mx').addEventListener('click', function () {
      var list = last.slice(0, 10), btn = SK.$('fm-mx');
      var rows = [];
      LU.working(mxOut, 'Asking public DNS about mail servers…');
      btn.disabled = true;
      Promise.all(list.map(function (t) {
        var name = NL.cleanName(t.domain);
        if (!name || NL.isReservedName(name)) return Promise.resolve([t.domain, 'Not sent: looks like an internal name.', '']);
        return NL.query(name, NL.TYPE.MX, { resolver: 'google' }).then(function (r) {
          var mx = NL.dataOf(r, NL.TYPE.MX);
          if (r.rcode === 3) return [t.domain, 'Domain does not exist', ''];
          if (!mx.length) return [t.domain, 'No mail servers (cannot receive email)', ''];
          var providers = {};
          mx.forEach(function (m) { var p = NL.mxProvider(m); if (p) providers[p] = true; });
          return [t.domain, Object.keys(providers).join(', ') || 'Self-hosted or an unlisted provider', mx.slice(0, 4).join('\n')];
        }, function (e) { return [t.domain, NL.friendlyError(e), '']; });
      })).then(function (r) {
        SK.clear(mxOut);
        mxOut.appendChild(SK.el('h3', { text: 'Who handles the mail' }));
        mxOut.appendChild(LU.table(['Domain', 'Mail hosted by', 'Mail servers'], r, [0, 2]));
        mxOut.appendChild(SK.el('p', { className: 'kit-note', text: 'A company domain hosted by Google or Microsoft is normal and paid. It is not the same as a free personal address. The mail host does not tell you the sender is who they claim to be.' }));
        btn.disabled = false;
      });
    });

    var q = SK.hashQuery();
    if (q.q) { SK.$('fm-in').value = q.q; run(q.q); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
