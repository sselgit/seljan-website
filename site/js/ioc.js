// Defang, refang and indicator extraction (SK.ioc) plus the page wiring. Runs locally.
(function () {
  var SK = window.SK = window.SK || {};
  var I = SK.ioc = {};

  // Words that look like domains but are almost always file names.
  var FILE_EXT = {};
  ('exe dll txt doc docx xls xlsx ppt pptx pdf js vbs ps1 bat cmd png jpg jpeg gif html htm css json xml log tmp dat bin sys msi lnk iso img py sh rtf csv ini cfg conf yml yaml md db bak old tar gz rar')
    .split(' ').forEach(function (e) { FILE_EXT[e] = true; });

  var URL_SRC = '\\b(?:https?|ftp):\\/\\/[^\\s<>"\'\\)\\]]+';
  var EMAIL_SRC = '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,24}\\b';
  var IP_SRC = '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b';
  var DOMAIN_SRC = '\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}\\b';

  I.refang = function (s) {
    return String(s)
      .replace(/\bhxxp(s?)(?=:|\[:\]|\(:\))/gi, 'http$1')
      .replace(/\bfxp(?=:|\[:\])/gi, 'ftp')
      .replace(/\[\s*:\s*\/\/\s*\]|\[\s*\/\/\s*\]/g, '://')
      .replace(/\[\s*:\s*\]|\(\s*:\s*\)/g, ':')
      .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}/gi, '.')
      .replace(/\[\s*@\s*\]|\(\s*@\s*\)|\[\s*at\s*\]|\(\s*at\s*\)/gi, '@');
  };

  function validIPv4(s) { return SK.net ? SK.net.parseIPv4(s) !== null : /^(\d{1,3}\.){3}\d{1,3}$/.test(s); }
  function isFileName(domain) {
    var tld = domain.slice(domain.lastIndexOf('.') + 1).toLowerCase();
    return !!FILE_EXT[tld];
  }
  function dotsToBrackets(s) { return s.replace(/\./g, '[.]'); }

  function defangUrl(u) {
    var m = /^(https?|ftp)(:\/\/)([^\/?#]*)(.*)$/i.exec(u);
    if (!m) return u;
    var scheme = m[1].toLowerCase() === 'ftp' ? 'fxp' : m[1].replace(/^http/i, 'hxxp');
    var auth = m[3], at = auth.lastIndexOf('@'), cred = '', host = auth;
    if (at >= 0) { cred = auth.slice(0, at + 1); host = auth.slice(at + 1); }
    var port = '', pm = /^(.*?)(:\d+)$/.exec(host);
    if (pm) { host = pm[1]; port = pm[2]; }
    return scheme + m[2] + cred + dotsToBrackets(host) + port + m[4];
  }

  I.defang = function (text) {
    var re = new RegExp('(' + URL_SRC + ')|(' + EMAIL_SRC + ')|(' + IP_SRC + ')|(' + DOMAIN_SRC + ')', 'gi');
    return String(text).replace(re, function (m, url, email, ip, dom) {
      if (url) {
        var trail = /[.,;:!?]+$/.exec(url), tail = trail ? trail[0] : '';
        return defangUrl(tail ? url.slice(0, -tail.length) : url) + tail;
      }
      if (email) {
        var at = email.indexOf('@');
        return email.slice(0, at) + '[@]' + dotsToBrackets(email.slice(at + 1));
      }
      if (ip) return validIPv4(ip) ? dotsToBrackets(ip) : ip;
      if (dom) return isFileName(dom) ? dom : dotsToBrackets(dom);
      return m;
    });
  };

  function uniq(list) {
    var seen = {}, out = [];
    list.forEach(function (x) { if (!seen[x]) { seen[x] = true; out.push(x); } });
    return out;
  }

  // Pulls indicators out of free text (reports, emails, tickets). Defanged input is cleaned first.
  I.extract = function (text) {
    var t = I.refang(text);
    var res = { urls: [], ips: [], ipv6: [], domains: [], emails: [], md5: [], sha1: [], sha256: [], sha512: [], cves: [], attack: [] };

    (t.match(new RegExp(URL_SRC, 'gi')) || []).forEach(function (u) { res.urls.push(u.replace(/[.,;:!?]+$/, '')); });
    (t.match(new RegExp(EMAIL_SRC, 'g')) || []).forEach(function (e) { res.emails.push(e.toLowerCase()); });

    // Remove URLs and emails before looking for bare domains and addresses, then add their hosts back.
    var rest = t.replace(new RegExp(URL_SRC, 'gi'), ' ').replace(new RegExp(EMAIL_SRC, 'g'), ' ');
    var domains = [];
    res.urls.forEach(function (u) {
      var hm = /^[a-z]+:\/\/(?:[^\/?#@]*@)?(\[[^\]]+\]|[^\/?#:]+)/i.exec(u);
      if (!hm) return;
      var h = hm[1].toLowerCase();
      if (validIPv4(h)) res.ips.push(h);
      else if (h.indexOf('[') < 0) domains.push(h);
    });
    res.emails.forEach(function (e) { domains.push(e.slice(e.indexOf('@') + 1)); });

    (rest.match(new RegExp(IP_SRC, 'g')) || []).forEach(function (ip) { if (validIPv4(ip)) res.ips.push(ip); });
    (rest.match(new RegExp(DOMAIN_SRC, 'gi')) || []).forEach(function (d) {
      if (validIPv4(d) || isFileName(d)) return;
      domains.push(d.toLowerCase());
    });
    if (SK.net) {
      (rest.match(/[0-9A-Fa-f:.]{3,}/g) || []).forEach(function (c) {
        if ((c.match(/:/g) || []).length >= 2 && SK.net.parseIPv6(c) !== null) res.ipv6.push(SK.net.ipv6Compress(SK.net.parseIPv6(c)));
      });
    }

    function hashes(len, key) {
      (t.match(new RegExp('\\b[a-fA-F0-9]{' + len + '}\\b', 'g')) || []).forEach(function (h) { res[key].push(h.toLowerCase()); });
    }
    hashes(32, 'md5'); hashes(40, 'sha1'); hashes(64, 'sha256'); hashes(128, 'sha512');
    (t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).forEach(function (c) { res.cves.push(c.toUpperCase()); });
    (t.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []).forEach(function (c) { res.attack.push(c); });

    res.domains = domains;
    Object.keys(res).forEach(function (k) { res[k] = uniq(res[k]); });
    return res;
  };

  I.LABELS = {
    ips: 'IPv4 addresses', ipv6: 'IPv6 addresses', domains: 'Domains', urls: 'URLs', emails: 'Email addresses',
    md5: 'MD5 hashes', sha1: 'SHA-1 hashes', sha256: 'SHA-256 hashes', sha512: 'SHA-512 hashes',
    cves: 'CVE IDs', attack: 'ATT&CK technique IDs'
  };

  /* ---------- page wiring ---------- */

  function init() {
    var input = SK.$('ioc-in');
    if (!input) return;
    var lastExtract = null;

    function setOut(text) {
      var out = SK.$('ioc-out');
      out.textContent = text;
      out.classList.toggle('empty', !text);
      SK.$('ioc-copy').disabled = !text;
    }

    SK.$('ioc-defang').addEventListener('click', function () { setOut(I.defang(I.refang(input.value))); });
    SK.$('ioc-refang').addEventListener('click', function () { setOut(I.refang(input.value)); });
    SK.$('ioc-copy').addEventListener('click', function () { SK.copyText(SK.$('ioc-out').textContent); });
    SK.$('ioc-clear').addEventListener('click', function () {
      input.value = ''; setOut(''); SK.clear(SK.$('ioc-extract-out')); lastExtract = null;
    });
    SK.$('ioc-sample').addEventListener('click', function () {
      input.value = 'Phishing email from billing@invoice-update.example sent a link hxxps://login-portal[.]example/verify?id=42 .\n' +
        'The page loaded a script from 198.51.100.23 and 203.0.113.9:8080. Internal host 10.1.2.3 was also seen.\n' +
        'Attachment SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n' +
        'Related: CVE-2023-23397, technique T1566.001, and the dropper http://files.sample-cdn.example/a/b.php.';
      SK.$('ioc-extract').click();
    });

    SK.$('ioc-extract').addEventListener('click', function () {
      var box = SK.$('ioc-extract-out');
      SK.clear(box);
      var res = I.extract(input.value);
      lastExtract = res;
      var total = 0;
      Object.keys(res).forEach(function (k) { total += res[k].length; });
      if (!total) { box.appendChild(SK.el('div', { className: 'kit-callout warn' }, [SK.el('p', { text: 'No indicators found in that text.' })])); return; }
      box.appendChild(SK.el('p', { className: 'kit-note', text: total + ' unique indicators found. Defanged forms are shown so they are safe to paste into tickets and chats.' }));
      Object.keys(I.LABELS).forEach(function (key) {
        var list = res[key];
        if (!list.length) return;
        var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, [SK.el('th', { text: 'Indicator (defanged)' }), SK.el('th', { text: 'Note' })])]);
        list.forEach(function (v) {
          var note = '';
          if ((key === 'ips' || key === 'ipv6') && SK.net) {
            var c = SK.net.classify(v);
            if (c) note = c.routable ? 'Public address' : 'Not public: ' + c.label + '. Do not send to external lookups.';
          }
          t.appendChild(SK.el('tr', {}, [SK.el('td', { className: 'mono', text: I.defang(v) }), SK.el('td', { text: note })]));
        });
        var det = SK.el('details', { className: 'kit-details', attrs: { open: '' } }, [
          SK.el('summary', { text: I.LABELS[key] + ' (' + list.length + ')' }),
          SK.el('div', { className: 'kit-table-wrap' }, [t]),
          SK.copyButton('Copy defanged list', function () { return list.map(I.defang).join('\n'); }),
          SK.copyButton('Copy raw list', function () { return list.join('\n'); })
        ]);
        box.appendChild(det);
      });
      var all = SK.el('div', { className: 'kit-row' }, [
        SK.el('button', { className: 'btn btn-small', text: 'Download CSV', attrs: { type: 'button' }, on: { click: function () {
          var rows = ['type,indicator,defanged'];
          Object.keys(I.LABELS).forEach(function (k) {
            lastExtract[k].forEach(function (v) { rows.push(k + ',"' + v.replace(/"/g, '""') + '","' + I.defang(v).replace(/"/g, '""') + '"'); });
          });
          SK.download('indicators.csv', rows.join('\n'), 'text/csv');
        } } })
      ]);
      box.appendChild(all);
    });

    // Arriving from the search box: fill in and extract (this tool works offline).
    var hq = SK.hashQuery();
    if (hq.q) { input.value = hq.q; SK.$('ioc-extract').click(); SK.$('ioc-defang').click(); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
