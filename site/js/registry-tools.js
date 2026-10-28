// Page wiring for WHOIS (RDAP), abuse contacts and ASN lookups. Data comes straight from registries and
// public sources to this browser; see netlookup.js. Everything remote is shown with textContent.
(function () {
  var SK = window.SK = window.SK || {};
  if (!SK.nl || !SK.lu) return;
  var NL = SK.nl, LU = SK.lu;

  function humanAge(days) {
    if (days < 1) return 'today';
    if (days < 60) return days + ' day' + (days === 1 ? '' : 's');
    if (days < 730) return Math.floor(days / 30) + ' months';
    return Math.floor(days / 365) + ' years';
  }

  // Abuse contacts as one DOM node: email link plus phone, one per line.
  function contactsNode(list) {
    var box = SK.el('div');
    var seen = {};
    list.forEach(function (c) {
      var key = (c.email || '') + '|' + (c.phone || '');
      if (seen[key]) return;
      seen[key] = true;
      var line = SK.el('div');
      if (c.email) line.appendChild(LU.mail(c.email));
      if (c.phone) line.appendChild(document.createTextNode((c.email ? '  ' : '') + c.phone));
      if (c.name && c.name !== c.email) line.appendChild(document.createTextNode('  (' + c.name + ')'));
      box.appendChild(line);
    });
    return box.firstChild ? box : '';
  }

  function icannLink(value) { return 'https://lookup.icann.org/en/lookup?name=' + encodeURIComponent(value); }

  /* ---------------------------------------------------------------- WHOIS */

  function renderWhois(out, res) {
    var s = res.summary;
    SK.clear(out);
    if (res.kind === 'domain') {
      if (s.ageDays !== null && s.ageDays < 30) out.appendChild(LU.callout('warn', ['Registered only ' + humanAge(s.ageDays) + ' ago. Brand-new domains are a common sign of phishing and fraud.']));
      if (s.daysToExpiry !== null && s.daysToExpiry < 0) out.appendChild(LU.callout('bad', ['The registration expired ' + humanAge(-s.daysToExpiry) + ' ago. It may be in a grace period, up for sale, or about to be dropped.']));
      else if (s.daysToExpiry !== null && s.daysToExpiry < 30) out.appendChild(LU.callout('warn', ['The registration expires in ' + s.daysToExpiry + ' day' + (s.daysToExpiry === 1 ? '' : 's') + '.']));
      out.appendChild(LU.kv([
        ['Domain', s.name], ['Registered', s.registered ? s.registered + (s.ageDays !== null ? '  (' + humanAge(s.ageDays) + ' ago)' : '') : ''],
        ['Expires', s.expires ? s.expires + (s.daysToExpiry !== null ? '  (' + (s.daysToExpiry < 0 ? 'expired' : 'in ' + humanAge(s.daysToExpiry)) + ')' : '') : ''], ['Last changed', s.updated],
        ['Registrar', s.registrar ? s.registrar + (s.registrarId ? '  (IANA ID ' + s.registrarId + ')' : '') : ''], ['Status', s.status], ['Name servers', s.nameservers],
        ['DNSSEC', s.dnssec], ['Abuse contact', contactsNode(s.abuse)]
      ]));
      if (s.contacts.length) {
        out.appendChild(SK.el('h3', { text: 'Contacts published by the registry' }));
        out.appendChild(LU.table(['Role', 'Name', 'Organization', 'Email'], s.contacts.map(function (c) { return [c.roles, c.name, c.org, c.email]; }), []));
      } else out.appendChild(SK.el('p', { className: 'kit-note', text: 'No owner details are published. Since privacy rules such as GDPR, most registries hide the registrant. ' + (s.abuse.length ? 'The registrar abuse contact above is usually the way to reach the owner.' : 'To reach the owner, contact the registrar through its website.') }));
      out.appendChild(SK.el('div', { className: 'kit-row tight' }, [
        SK.el('a', { className: 'btn btn-small btn-ghost', text: 'DNS report', attrs: { href: 'dnsreport.html#q=' + encodeURIComponent(res.value) + '&k=domain&go=1' } }),
        SK.el('a', { className: 'btn btn-small btn-ghost', text: 'Abuse contacts', attrs: { href: 'abuse.html#q=' + encodeURIComponent(res.value) + '&k=domain&go=1' } })
      ]));
    } else if (res.kind === 'ip') {
      out.appendChild(LU.kv([['Network name', s.name], ['Address range', s.range], ['CIDR', s.cidrs], ['Organization', s.organization], ['Country', s.country], ['Type', s.type],
        ['Handle', s.handle], ['Registered', s.registered], ['Last changed', s.updated], ['Description', s.description], ['Abuse contact', contactsNode(s.abuse)]]));
      out.appendChild(SK.el('div', { className: 'kit-row tight' }, [
        SK.el('a', { className: 'btn btn-small btn-ghost', text: 'ASN and routing', attrs: { href: 'asn.html#q=' + encodeURIComponent(res.value) + '&k=ip&go=1' } }),
        SK.el('a', { className: 'btn btn-small btn-ghost', text: 'Reverse DNS', attrs: { href: 'reverse.html#q=' + encodeURIComponent(res.value) + '&k=ip&go=1' } })
      ]));
    } else {
      out.appendChild(LU.kv([['Name', s.name], ['AS number', s.range], ['Organization', s.organization], ['Country', s.country], ['Type', s.type], ['Handle', s.handle],
        ['Registered', s.registered], ['Last changed', s.updated], ['Abuse contact', contactsNode(s.abuse)]]));
    }
    out.appendChild(LU.raw('Raw registry response', res.raw));
    out.appendChild(SK.el('p', { className: 'kit-note', text: 'Data is read from the registry through RDAP, the web-based successor to WHOIS, by way of the rdap.org lookup redirector.' }));
  }

  function initWhois() {
    if (!SK.$('who-in')) return;
    var out = SK.$('who-out');
    LU.start({ input: 'who-in', button: 'who-run', out: 'who-out', run: function (raw) {
      SK.clear(out);
      var v = (window.SKRoute ? window.SKRoute.refang(raw) : String(raw)).trim().split(/\s+/)[0] || '';
      var kind, value;
      if (/^AS\s?\d{1,10}$/i.test(v) && NL.parseAsn(v) !== null) { kind = 'asn'; value = 'AS' + NL.parseAsn(v); }
      else {
        var t = LU.parseTarget(raw, ['domain', 'ip']);
        if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
        kind = t.kind; value = t.value;
      }
      LU.working(out, 'Asking the registry about ' + value + '…');
      return NL.whoisLookup(kind, value).then(function (res) { renderWhois(out, res); }, function (e) {
        SK.clear(out);
        if (/^No registration found/.test(e.userMessage || '')) {
          out.appendChild(LU.callout('warn', [e.userMessage + ' It may be unregistered or expired.', 'If you expected a result, some registries are not in the public RDAP directory.']));
        } else {
          out.appendChild(LU.callout('bad', [NL.friendlyError(e), kind === 'domain' ? 'Some registries do not allow lookups from a web page. ICANN\'s lookup tool covers them:' : 'The registry may be down or rate limiting.']));
        }
        if (kind === 'domain') out.appendChild(SK.el('p', {}, [LU.link(icannLink(value), 'Look up ' + value + ' on ICANN Lookup')]));
      });
    } });
  }

  /* ---------------------------------------------------------------- abuse contacts */

  var REPORT_LINKS = [
    ['Google Safe Browsing: report a phishing page', 'https://safebrowsing.google.com/safebrowsing/report_phish/'],
    ['Microsoft: report an unsafe site', 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site'],
    ['Netcraft: report a phishing or malicious URL', 'https://report.netcraft.com/report'],
    ['APWG: forward phishing emails to reportphishing@apwg.org', 'mailto:reportphishing@apwg.org']
  ];

  function renderAbuse(out, r) {
    SK.clear(out);
    var any = false;
    if (r.registrar) {
      out.appendChild(SK.el('h3', { text: 'Registrar (for the domain name)' }));
      if (r.registrar.error) out.appendChild(LU.callout('warn', ['Could not read the registry: ' + r.registrar.error]));
      else {
        out.appendChild(LU.kv([['Registrar', r.registrar.registrar ? r.registrar.registrar + (r.registrar.registrarId ? '  (IANA ID ' + r.registrar.registrarId + ')' : '') : ''], ['Abuse contact', contactsNode(r.registrar.abuse)]]));
        if (!r.registrar.abuse.length) out.appendChild(SK.el('p', { className: 'kit-note', text: 'The registry did not list an abuse contact. Look up the registrar by name and use its abuse form.' }));
        else any = true;
      }
    }
    r.networks.forEach(function (n) {
      out.appendChild(SK.el('h3', { text: 'Network owner for ' + n.ip }));
      var contacts = [];
      if (n.ripe && n.ripe.contacts) n.ripe.contacts.forEach(function (e) { contacts.push({ email: e }); });
      if (n.rdap && n.rdap.abuse) n.rdap.abuse.forEach(function (c) { contacts.push(c); });
      var node = contactsNode(contacts);
      if (node) any = true;
      out.appendChild(LU.kv([['Organization', n.rdap && n.rdap.organization], ['Network name', n.rdap && n.rdap.name], ['Address range', n.rdap && n.rdap.range], ['Abuse contact', node]]));
      if (!node) out.appendChild(SK.el('p', { className: 'kit-note', text: 'No abuse contact found.' + (n.ripe && n.ripe.error ? ' (' + n.ripe.error + ')' : '') }));
    });
    if (r.noAddress) out.appendChild(LU.callout('', ['This name has no public address records, so there is no hosting provider to report to. Use the registrar contact above.']));
    if (any) out.appendChild(LU.callout('good', ['Report to both: the registrar can suspend the domain name, and the network owner can take the server offline.']));
    out.appendChild(SK.el('details', { className: 'kit-details' }, [
      SK.el('summary', { text: 'How to write a useful abuse report' }),
      SK.el('ul', {}, [
        'Say what it is (phishing, malware, scam) and give the full URL or IP address, defanged if you paste it into mail.',
        'Include the date and time with the time zone, and a screenshot or the relevant log lines.',
        'Do not attach malware. Describe it and give a hash instead.',
        'Send one clear report per issue. Ask for the content to be suspended, not for a reply.',
        'If a brand is impersonated, tell that brand as well: most have a phishing report address.'
      ].map(function (t) { return SK.el('li', { text: t }); })),
      SK.el('p', { text: 'Other places to report phishing:' }),
      SK.el('ul', {}, REPORT_LINKS.map(function (l) { return SK.el('li', {}, [LU.link(l[1], l[0])]); }))
    ]));
    out.appendChild(SK.el('p', { className: 'kit-note', text: 'Contacts come from the registry (RDAP) and from RIPEstat. A contact existing does not mean it will answer.' }));
  }

  function initAbuse() {
    if (!SK.$('ab-in')) return;
    var out = SK.$('ab-out');
    LU.start({ input: 'ab-in', button: 'ab-run', out: 'ab-out', run: function (raw) {
      SK.clear(out);
      var t = LU.parseTarget(raw, ['domain', 'ip']);
      if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
      LU.working(out, 'Finding abuse contacts for ' + t.value + '…');
      return NL.abuseLookup(t).then(function (r) { renderAbuse(out, r); });
    } });
  }

  /* ---------------------------------------------------------------- ASN */

  function renderAsn(out, r) {
    SK.clear(out);
    if (r.asn === null) {
      out.appendChild(LU.callout('warn', ['No announced route was found for ' + r.ip + (r.errors.origin ? ' (' + r.errors.origin + ')' : '') + '. It may be unrouted address space.']));
      return;
    }
    var info = r.info || {}, ov = r.overview || {}, rd = r.rdap || {};
    var holder = ov.holder || (info.name || '');
    out.appendChild(LU.callout('good', [SK.el('p', {}, [SK.el('strong', { text: 'AS' + r.asn }), document.createTextNode(holder ? ' ' + holder : '') ])]));
    out.appendChild(LU.kv([
      ['Address looked up', r.ip], ['Route that covers it', r.origin ? r.origin.prefix : ''], ['Other origin AS numbers', r.origin && r.origin.asns.length > 1 ? r.origin.asns.slice(1).map(function (a) { return 'AS' + a; }) : ''],
      ['AS name', info.name || rd.name], ['Organization', rd.organization], ['Country', info.country || rd.country], ['Registry', info.registry], ['Allocated', info.allocated || rd.registered],
      ['Currently announced', ov.announced === undefined ? '' : (ov.announced ? 'Yes' : 'No')], ['Abuse contact', contactsNode(rd.abuse || [])]
    ]));
    // The prefix list can be hundreds of KB, so it loads only when asked for.
    var pfx = SK.el('div'), pfxBtn = SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Show announced prefixes', attrs: { type: 'button' } });
    pfxBtn.addEventListener('click', function () {
      pfxBtn.disabled = true;
      LU.working(pfx, 'Loading the list of announced prefixes…');
      NL.asnPrefixes(r.asn).then(function (p) {
        SK.clear(pfx);
        pfx.appendChild(SK.el('p', { className: 'kit-note', text: p.count + ' prefixes announced' + (p.count > p.sample.length ? ' (first ' + p.sample.length + ' shown)' : '') + '.' }));
        pfx.appendChild(SK.el('div', { className: 'kit-out', text: p.sample.join('\n') || '(none)' }));
      }, function (e) { SK.clear(pfx); pfx.appendChild(LU.callout('warn', [NL.friendlyError(e)])); pfxBtn.disabled = false; });
    });
    out.appendChild(SK.el('div', { className: 'kit-row tight' }, [pfxBtn]));
    out.appendChild(pfx);
    var failed = Object.keys(r.errors);
    if (failed.length) out.appendChild(LU.callout('warn', ['Some sources could not be read: ' + failed.map(function (k) { return k + ' (' + r.errors[k] + ')'; }).join('; ') + '.']));
    out.appendChild(SK.el('div', { className: 'kit-row tight' }, [
      SK.el('a', { className: 'btn btn-small btn-ghost', text: 'WHOIS for AS' + r.asn, attrs: { href: 'whois.html#q=AS' + r.asn + '&k=asn&go=1' } })
    ]));
    out.appendChild(SK.el('p', { className: 'kit-note', text: 'Sources: Team Cymru IP-to-ASN mapping (DNS), registry data (RDAP), and RIPEstat. An AS number identifies a network that routes traffic, which is often a hosting provider or ISP rather than the end owner.' }));
  }

  function initAsn() {
    if (!SK.$('asn-in')) return;
    var out = SK.$('asn-out');
    LU.start({ input: 'asn-in', button: 'asn-run', out: 'asn-out', run: function (raw) {
      SK.clear(out);
      var v = (window.SKRoute ? window.SKRoute.refang(raw) : String(raw)).trim().split(/\s+/)[0] || '';
      var input;
      if (/^(AS\s?)?\d{1,10}$/i.test(v) && NL.parseAsn(v) !== null) input = 'AS' + NL.parseAsn(v);
      else {
        var t = LU.parseTarget(raw, ['domain', 'ip']);
        if (t.error) { out.appendChild(LU.callout('warn', [t.error])); return; }
        if (t.kind === 'domain') {
          out.appendChild(LU.callout('warn', ['That is a domain name. Find its address with ', SK.el('a', { text: 'DNS records', attrs: { href: 'dns.html#q=' + encodeURIComponent(t.value) + '&k=domain&go=1' } }), ', then look up the address here.']));
          return;
        }
        input = t.value;
      }
      LU.working(out, 'Looking up ' + input + '…');
      return NL.asnLookup(input).then(function (r) { renderAsn(out, r); });
    } });
  }

  function init() { initWhois(); initAbuse(); initAsn(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
