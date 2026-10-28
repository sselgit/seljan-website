// Page wiring for the DNS tools: records, report, DNSSEC, propagation and reverse DNS.
// Answers come straight from public resolvers to this browser; see netlookup.js.
(function () {
  var SK = window.SK = window.SK || {};
  if (!SK.nl || !SK.lu) return;
  var NL = SK.nl, LU = SK.lu;

  function resolverSelect(id) {
    var sel = SK.$(id);
    if (!sel) return;
    NL.RESOLVERS.filter(function (r) { return r.json; }).forEach(function (r) { sel.appendChild(SK.el('option', { text: r.name, attrs: { value: r.id } })); });
  }

  /* ---------------------------------------------------------------- DNS records */

  function initRecords() {
    if (!SK.$('dns-in')) return;
    var TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'DNSKEY', 'DS', 'HTTPS'], DEFAULT = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
    var box = SK.$('dns-types');
    TYPES.forEach(function (t) {
      var cb = SK.el('input', { attrs: { type: 'checkbox', id: 'dns-t-' + t, value: t } });
      cb.checked = DEFAULT.indexOf(t) >= 0;
      box.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'dns-t-' + t } }, [cb, t]));
    });
    resolverSelect('dns-resolver');
    var out = SK.$('dns-out');

    LU.start({ input: 'dns-in', button: 'dns-run', out: 'dns-out', run: function (raw) {
      var t = LU.parseTarget(raw, ['domain', 'ip']);
      SK.clear(out);
      if (t.error && t.kind !== 'ip') { out.appendChild(LU.callout('warn', [t.error])); return; }
      if (t.kind === 'ip') {
        out.appendChild(LU.callout('warn', ['That is an IP address. To find the name for an address, use ', SK.el('a', { text: 'reverse DNS', attrs: { href: 'reverse.html#q=' + encodeURIComponent(t.value) + '&k=ip&go=1' } }), '.']));
        return;
      }
      var types = TYPES.filter(function (x) { return SK.$('dns-t-' + x).checked; });
      if (!types.length) { out.appendChild(LU.callout('warn', ['Pick at least one record type.'])); return; }
      var resolver = SK.$('dns-resolver').value || 'google';
      LU.working(out, 'Asking ' + resolver + ' for ' + types.join(', ') + '…');
      return Promise.all(types.map(function (type) {
        return NL.query(t.value, NL.TYPE[type], { resolver: resolver, dnssec: type === 'DS' || type === 'DNSKEY' }).then(function (r) { return { type: type, res: r }; }, function (e) { return { type: type, error: e }; });
      })).then(function (results) {
        SK.clear(out);
        var rows = [], empty = [], failed = [], rc = '', ad = false;
        results.forEach(function (r) {
          if (r.error) { failed.push(r.type + ': ' + NL.friendlyError(r.error)); return; }
          if (r.res.rcode === 3) rc = 'NXDOMAIN';
          if (r.res.ad) ad = true;
          var mine = r.res.answers.filter(function (a) { return a.type === NL.TYPE[r.type]; });
          if (!mine.length) empty.push(r.type);
          mine.forEach(function (a) { rows.push([a.typeName, a.name.replace(/\.$/, ''), LU.humanTtl(a.ttl) + ' (' + a.ttl + 's)', a.data]); });
          r.res.answers.filter(function (a) { return a.type === 5 && NL.TYPE[r.type] !== 5; }).forEach(function (a) { rows.push(['CNAME', a.name.replace(/\.$/, ''), LU.humanTtl(a.ttl) + ' (' + a.ttl + 's)', a.data]); });
        });
        var seen = {};
        rows = rows.filter(function (r) { var k = r.join('|'); if (seen[k]) return false; seen[k] = true; return true; });
        if (rc === 'NXDOMAIN') out.appendChild(LU.callout('bad', ['This domain does not exist (NXDOMAIN). Check the spelling, or it may be unregistered or expired.']));
        else out.appendChild(LU.callout(rows.length ? 'good' : 'warn', [rows.length + ' record' + (rows.length === 1 ? '' : 's') + ' found for ' + t.value + (ad ? '. The resolver reports the DNSSEC-validated flag on some answers.' : '.')]));
        if (rows.length) {
          out.appendChild(LU.table(['Type', 'Name', 'TTL', 'Data'], rows, [1, 3]));
          var text = rows.map(function (r) { return r[1] + '\t' + r[2].replace(/ .*/, '') + '\tIN\t' + r[0] + '\t' + r[3]; }).join('\n');
          out.appendChild(SK.el('div', { className: 'kit-row tight' }, [SK.copyButton('Copy as text', function () { return text; })]));
        }
        if (empty.length && rc !== 'NXDOMAIN') out.appendChild(SK.el('p', { className: 'kit-note', text: 'No records of these types: ' + empty.join(', ') + '.' }));
        if (failed.length) out.appendChild(LU.callout('warn', ['Some lookups failed: ' + failed.join('; ')]));
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'Answers are a snapshot from one public resolver and may be cached. TTL is how long a resolver may keep the answer.' }));
      });
    } });
  }

  /* ---------------------------------------------------------------- DNS report */

  function initReport() {
    if (!SK.$('drep-in')) return;
    resolverSelect('drep-resolver');
    var out = SK.$('drep-out');
    LU.start({ input: 'drep-in', button: 'drep-run', out: 'drep-out', run: function (raw) {
      var t = LU.parseTarget(raw, ['domain']);
      SK.clear(out);
      if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
      LU.working(out, 'Gathering name servers, mail records, DNSSEC and more for ' + t.value + '…');
      return NL.gatherReport(t.value, { resolver: SK.$('drep-resolver').value || 'google' }).then(function (d) {
        SK.clear(out);
        var findings = NL.analyzeReport(d);
        var count = { error: 0, warn: 0, info: 0, pass: 0 };
        findings.forEach(function (f) { count[f.level]++; });
        out.appendChild(SK.el('div', { className: 'kit-row' }, [
          LU.chip(count.error + ' problem' + (count.error === 1 ? '' : 's'), count.error ? 'bad' : ''), LU.chip(count.warn + ' warning' + (count.warn === 1 ? '' : 's'), count.warn ? 'warn' : ''),
          LU.chip(count.info + ' note' + (count.info === 1 ? '' : 's')), LU.chip(count.pass + ' good', count.pass ? 'good' : '')
        ]));
        out.appendChild(LU.findings(findings));
        if (d.errors.length) out.appendChild(LU.callout('warn', ['These lookups failed and are not part of the findings: ' + d.errors.join(', ') + '.']));
        var rec = SK.el('details', { className: 'kit-details' }, [SK.el('summary', { text: 'Records behind the report' })]);
        var rows = [];
        d.ns.forEach(function (x) { rows.push(['NS', x]); });
        if (d.soa) rows.push(['SOA', d.soa]);
        d.a.forEach(function (x) { rows.push(['A', x]); });
        d.aaaa.forEach(function (x) { rows.push(['AAAA', x]); });
        d.cname.forEach(function (x) { rows.push(['CNAME', x]); });
        d.mx.forEach(function (x) {
          var host = x.replace(/^\d+\s+/, ''), tg = d.mxTargets && d.mxTargets[host.toLowerCase()];
          var prov = NL.mxProvider(host);
          rows.push(['MX', x + (tg ? '  ->  ' + (tg.a.concat(tg.aaaa).join(', ') || 'no address') : '') + (prov ? '  (' + prov + ')' : '')]);
        });
        d.txt.forEach(function (x) { rows.push(['TXT', NL.txtValue(x)]); });
        d.dmarc.forEach(function (x) { rows.push(['_dmarc TXT', NL.txtValue(x)]); });
        d.caa.forEach(function (x) { rows.push(['CAA', x]); });
        rec.appendChild(LU.table(['Type', 'Value'], rows, [1]));
        out.appendChild(rec);
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'This report reads public DNS from one resolver at one moment. It cannot see private DNS, and some findings are judgement calls. See the DNSSEC tool for details on signing.' }));
        out.appendChild(SK.el('div', { className: 'kit-row tight' }, [
          SK.el('a', { className: 'btn btn-small btn-ghost', text: 'DNSSEC details', attrs: { href: 'dnssec.html#q=' + encodeURIComponent(t.value) + '&k=domain&go=1' } }),
          SK.el('a', { className: 'btn btn-small btn-ghost', text: 'Compare resolvers', attrs: { href: 'propagation.html#q=' + encodeURIComponent(t.value) + '&k=domain&go=1' } })
        ]));
      });
    } });
  }

  /* ---------------------------------------------------------------- DNSSEC */

  var VERDICT_KIND = { valid: 'good', unsigned: '', island: 'warn', brokenDs: 'bad', bogus: 'bad', unknown: 'warn' };
  var VERDICT_ADVICE = {
    valid: 'A DS record at the parent matches the zone\'s keys and a validating resolver accepts the signed answers. Visitors on validating resolvers are protected from forged DNS answers.',
    unsigned: 'The domain does not use DNSSEC. That is common and not an error, but answers cannot be checked for tampering. Ask your DNS host about enabling it.',
    island: 'The zone publishes signing keys, but there is no DS record at the parent, so no resolver treats them as trusted. Add the DS record at the registrar, or remove the keys.',
    brokenDs: 'The parent publishes a DS record but the zone returns no DNSKEY. Validating resolvers will treat the domain as broken. Remove the DS record or restore the keys.',
    bogus: 'Validating resolvers reject this domain: the normal lookup fails, but the same lookup works when validation is switched off. The DS at the registrar probably does not match the zone\'s keys, or signatures have expired. Fix this soon: affected users cannot reach the domain.',
    unknown: 'The keys and DS record are present, but the resolver did not mark the answer as validated. Try again, or check with a validating resolver such as 1.1.1.1.'
  };

  function initDnssec() {
    if (!SK.$('dsec-in')) return;
    resolverSelect('dsec-resolver');
    var out = SK.$('dsec-out');
    LU.start({ input: 'dsec-in', button: 'dsec-run', out: 'dsec-out', run: function (raw) {
      var t = LU.parseTarget(raw, ['domain']);
      SK.clear(out);
      if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
      LU.working(out, 'Checking DS, DNSKEY and validation for ' + t.value + '…');
      return NL.dnssecCheck(t.value, { resolver: SK.$('dsec-resolver').value || 'google' }).then(function (r) {
        SK.clear(out);
        if (r.error) { LU.error(out, r.error); return; }
        out.appendChild(LU.callout(VERDICT_KIND[r.verdict], [SK.el('p', {}, [SK.el('strong', { text: t.value + ' is ' + NL.dnssecText(r.verdict) + '.' })]), SK.el('p', { text: VERDICT_ADVICE[r.verdict] })]));
        if (r.ds.length) {
          out.appendChild(SK.el('h3', { text: 'DS records at the parent' }));
          out.appendChild(LU.table(['Key tag', 'Algorithm', 'Digest type', 'Digest'], r.ds.map(function (x) { var p = NL.parseDs(x); return [p.keyTag, NL.dnssecAlgName(p.alg), NL.dsDigestName(p.digestType), p.digest]; }), [3]));
        }
        if (r.dnskey.length) {
          out.appendChild(SK.el('h3', { text: 'DNSKEY records in the zone' }));
          out.appendChild(LU.table(['Role', 'Algorithm', 'Key (start)', 'Length'], r.dnskey.map(function (x) { var p = NL.parseDnskey(x); return [p.role, NL.dnssecAlgName(p.alg), p.key.slice(0, 32) + '…', p.key.length + ' base64 chars']; }), [2]));
        }
        if (r.rrsigs.length) {
          out.appendChild(SK.el('h3', { text: 'Signature on the DNSKEY set' }));
          var now = Date.now();
          function day(ms) { return isNaN(ms) ? '(unknown)' : new Date(ms).toISOString().slice(0, 10); }
          out.appendChild(LU.table(['Signed by', 'Key tag', 'Valid from', 'Valid until', 'Time left'], r.rrsigs.map(function (s) {
            var left = Math.floor((s.expires - now) / 86400000);
            return [s.signer, s.keyTag, day(s.inception), day(s.expires), isNaN(left) ? '' : (left < 0 ? 'EXPIRED' : left + ' days')];
          }), []));
          if (r.rrsigs.some(function (s) { return s.expires - now < 3 * 86400000; })) out.appendChild(LU.callout('warn', ['A signature expires within three days or has already expired. Signing should renew it automatically; check that it is running.']));
        }
        r.ds.concat(r.dnskey).forEach(function (x) { /* nothing: weak algorithm warnings below */ });
        var weak = r.ds.map(NL.parseDs).filter(function (p) { return p.alg === 5 || p.alg === 7 || p.digestType === 1; });
        if (weak.length) out.appendChild(LU.callout('warn', ['This zone uses a deprecated algorithm or SHA-1 digest. Plan a key rollover to ECDSA P-256 (13) or Ed25519 (15) with a SHA-256 digest.']));
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'Checked through ' + (SK.$('dsec-resolver').selectedOptions[0] || { text: 'Google Public DNS' }).text + ', which validates DNSSEC. The "validation fails" result compares a normal lookup with one that skips validation.' }));
      });
    } });
  }

  /* ---------------------------------------------------------------- propagation */

  function initPropagation() {
    if (!SK.$('prop-in')) return;
    var out = SK.$('prop-out');
    ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'].forEach(function (t) { SK.$('prop-type').appendChild(SK.el('option', { text: t, attrs: { value: t } })); });
    LU.start({ input: 'prop-in', button: 'prop-run', out: 'prop-out', run: function (raw) {
      var t = LU.parseTarget(raw, ['domain']);
      SK.clear(out);
      if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
      var type = SK.$('prop-type').value;
      LU.working(out, 'Asking five public resolvers for ' + type + ' records of ' + t.value + '…');
      return NL.propagation(t.value, NL.TYPE[type]).then(function (p) {
        SK.clear(out);
        var s = p.summary;
        if (!s.answered) out.appendChild(LU.callout('bad', ['None of the resolvers could be reached from this browser.']));
        else if (s.consistent) out.appendChild(LU.callout('good', ['All ' + s.answered + ' resolvers that answered agree.' + (s.failed ? ' ' + s.failed + ' could not be reached.' : '')]));
        else out.appendChild(LU.callout('warn', ['The resolvers give different answers (' + s.groups.length + ' variants). If you changed this record recently, some resolvers are still serving the old one until its TTL runs out.']));
        out.appendChild(LU.table(['Resolver', 'Result', 'Answer', 'TTL', 'Time'], p.results.map(function (r) {
          if (!r.ok) return [r.resolver.name, LU.chip('No answer', 'bad'), r.error, '', r.ms + ' ms'];
          return [r.resolver.name, LU.chip(r.rcodeName, r.rcode === 0 ? 'good' : 'warn'), r.answers.join('\n') || '(no records)', r.ttl == null ? '' : LU.humanTtl(r.ttl), r.ms + ' ms'];
        }), [2]));
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'This compares five public resolvers (Google, Cloudflare, DNS.SB, Control D, RethinkDNS) reached from your browser. It is not a worldwide check: resolvers keep their own caches, and large services return different answers by location on purpose.' }));
      });
    } });
  }

  /* ---------------------------------------------------------------- reverse DNS */

  function initReverse() {
    if (!SK.$('rev-in')) return;
    var out = SK.$('rev-out');
    LU.start({ multiline: true, input: 'rev-in', button: 'rev-run', out: 'rev-out', run: function (raw) {
      var lines = String(raw).split(/[\s,;]+/).filter(Boolean).slice(0, 20);
      SK.clear(out);
      if (!lines.length) { out.appendChild(LU.callout('warn', ['Enter one or more IP addresses.'])); return; }
      LU.working(out, 'Looking up PTR records for ' + lines.length + ' address' + (lines.length > 1 ? 'es' : '') + '…');
      var jobs = lines.map(function (line) {
        var t = LU.parseTarget(line, ['ip']);
        if (t.error || t.kind !== 'ip') return Promise.resolve({ line: line, skip: t.error || 'Not an IP address.' });
        return NL.reverseLookup(t.value).then(function (r) { return { line: t.value, r: r }; }, function (e) { return { line: t.value, fail: NL.friendlyError(e) }; });
      });
      return Promise.all(jobs).then(function (res) {
        SK.clear(out);
        var rows = res.map(function (x) {
          if (x.skip) return [x.line, x.skip, ''];
          if (x.fail) return [x.line, x.fail, ''];
          if (x.r.rcode === 3 || !x.r.ptr.length) return [x.line, '(no PTR record)', ''];
          return [x.line, x.r.ptr.map(function (p) { return p.name.replace(/\.$/, ''); }).join('\n'),
            x.r.ptr.map(function (p) { return p.confirmed ? 'Yes: ' + p.name.replace(/\.$/, '') + ' resolves back to this address' : 'No: ' + p.name.replace(/\.$/, '') + ' does not resolve back to it'; }).join('\n')];
        });
        out.appendChild(LU.table(['Address', 'Reverse name (PTR)', 'Forward-confirmed?'], rows, [0, 1]));
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'A forward-confirmed name means the name points back to the same address. Mail servers and some security tools expect this; a name that does not confirm is not proof of anything on its own, because anyone controlling an address\'s reverse zone can set any name there.' }));
      });
    } });
  }

  function init() { initRecords(); initReport(); initDnssec(); initPropagation(); initReverse(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
