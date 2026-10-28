// IP and CIDR helpers (SK.net) plus the network page wiring. Runs locally; no lookups.
(function () {
  var SK = window.SK = window.SK || {};
  var N = SK.net = {};

  /* ---------- IPv4 ---------- */

  // Strict dotted quad. Returns an unsigned 32-bit number or null.
  N.parseIPv4 = function (s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s).trim());
    if (!m) return null;
    var n = 0;
    for (var i = 1; i <= 4; i++) {
      var o = parseInt(m[i], 10);
      if (o > 255) return null;
      n = n * 256 + o;
    }
    return n;
  };

  N.ipv4ToStr = function (n) {
    return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
  };

  N.maskFromPrefix = function (p) { return p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0; };

  // "10.0.0.0/8" or a single address (treated as /32).
  N.parseCIDR4 = function (s) {
    var m = /^\s*([\d.]+)(?:\/(\d{1,2}))?\s*$/.exec(s);
    if (!m) return null;
    var ip = N.parseIPv4(m[1]);
    var p = m[2] === undefined ? 32 : parseInt(m[2], 10);
    if (ip === null || p > 32) return null;
    var mask = N.maskFromPrefix(p);
    return { ip: ip, prefix: p, mask: mask, network: (ip & mask) >>> 0, broadcast: ((ip & mask) | (~mask >>> 0)) >>> 0 };
  };

  N.cidrInfo = function (s) {
    var c = N.parseCIDR4(s);
    if (!c) return null;
    var size = Math.pow(2, 32 - c.prefix);
    var hosts = c.prefix >= 31 ? size : size - 2;
    return {
      cidr: N.ipv4ToStr(c.network) + '/' + c.prefix,
      network: N.ipv4ToStr(c.network),
      broadcast: c.prefix >= 31 ? '(none)' : N.ipv4ToStr(c.broadcast),
      mask: N.ipv4ToStr(c.mask),
      wildcard: N.ipv4ToStr((~c.mask) >>> 0),
      first: N.ipv4ToStr(c.prefix >= 31 ? c.network : c.network + 1),
      last: N.ipv4ToStr(c.prefix >= 31 ? c.broadcast : c.broadcast - 1),
      total: size,
      hosts: hosts,
      inputHadHostBits: c.network !== c.ip
    };
  };

  N.inCIDR4 = function (ip, cidr) {
    var a = typeof ip === 'number' ? ip : N.parseIPv4(ip), c = N.parseCIDR4(cidr);
    if (a === null || !c) return null;
    return ((a & c.mask) >>> 0) === c.network;
  };

  var V4_RANGES = [
    ['0.0.0.0/8', 'This network', 'RFC 1122', 'reserved'],
    ['10.0.0.0/8', 'Private network', 'RFC 1918', 'private'],
    ['100.64.0.0/10', 'Carrier-grade NAT (shared address space)', 'RFC 6598', 'private'],
    ['127.0.0.0/8', 'Loopback (this device)', 'RFC 1122', 'loopback'],
    ['169.254.0.0/16', 'Link-local (self-assigned, no DHCP)', 'RFC 3927', 'linklocal'],
    ['172.16.0.0/12', 'Private network', 'RFC 1918', 'private'],
    ['192.0.0.0/24', 'IETF protocol assignments', 'RFC 6890', 'reserved'],
    ['192.0.2.0/24', 'Documentation (TEST-NET-1)', 'RFC 5737', 'documentation'],
    ['192.88.99.0/24', '6to4 relay anycast (deprecated)', 'RFC 7526', 'reserved'],
    ['192.168.0.0/16', 'Private network', 'RFC 1918', 'private'],
    ['198.18.0.0/15', 'Network benchmark testing', 'RFC 2544', 'reserved'],
    ['198.51.100.0/24', 'Documentation (TEST-NET-2)', 'RFC 5737', 'documentation'],
    ['203.0.113.0/24', 'Documentation (TEST-NET-3)', 'RFC 5737', 'documentation'],
    ['224.0.0.0/4', 'Multicast', 'RFC 5771', 'multicast'],
    ['255.255.255.255/32', 'Limited broadcast', 'RFC 919', 'reserved'],
    ['240.0.0.0/4', 'Reserved for future use', 'RFC 1112', 'reserved']
  ];

  N.classifyIPv4 = function (s) {
    var ip = N.parseIPv4(s);
    if (ip === null) return null;
    for (var i = 0; i < V4_RANGES.length; i++) {
      if (N.inCIDR4(ip, V4_RANGES[i][0])) {
        return { ip: N.ipv4ToStr(ip), label: V4_RANGES[i][1], rfc: V4_RANGES[i][2], scope: V4_RANGES[i][3], range: V4_RANGES[i][0], routable: false };
      }
    }
    return { ip: N.ipv4ToStr(ip), label: 'Public (globally routable)', rfc: '', scope: 'public', range: '', routable: true };
  };

  // Start and end address to the smallest list of CIDR blocks.
  N.rangeToCIDRs = function (startStr, endStr) {
    var s = N.parseIPv4(startStr), e = N.parseIPv4(endStr);
    if (s === null || e === null || s > e) return null;
    var out = [];
    while (s <= e) {
      // Grow the block while it stays aligned on s and does not run past the end.
      var prefix = 32;
      while (prefix > 0) {
        var size = Math.pow(2, 32 - (prefix - 1));
        if (s % size !== 0 || s + size - 1 > e) break;
        prefix--;
      }
      out.push(N.ipv4ToStr(s) + '/' + prefix);
      s += Math.pow(2, 32 - prefix);
    }
    return out;
  };

  N.splitCIDR = function (cidr, newPrefix, limit) {
    var c = N.parseCIDR4(cidr);
    if (!c || newPrefix <= c.prefix || newPrefix > 32) return null;
    var count = Math.pow(2, newPrefix - c.prefix), step = Math.pow(2, 32 - newPrefix), out = [];
    for (var i = 0; i < Math.min(count, limit || 256); i++) out.push(N.ipv4ToStr(c.network + i * step) + '/' + newPrefix);
    return { blocks: out, total: count };
  };

  /* ---------- IPv6 ---------- */

  // Returns a BigInt or null.
  N.parseIPv6 = function (str) {
    var s = String(str).trim().replace(/^\[|\]$/g, '').split('%')[0];
    if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0) return null;
    var v4 = null, m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m) {
      v4 = N.parseIPv4(m[2]);
      if (v4 === null) return null;
      s = m[1] + ((v4 >>> 16) & 0xffff).toString(16) + ':' + (v4 & 0xffff).toString(16);
    }
    var dbl = s.split('::');
    if (dbl.length > 2) return null;
    function groups(part) { return part === '' ? [] : part.split(':'); }
    var head = groups(dbl[0]), tail = dbl.length === 2 ? groups(dbl[1]) : [];
    var all;
    if (dbl.length === 2) {
      var missing = 8 - head.length - tail.length;
      if (missing < 1) return null;
      var zeros = [];
      for (var z = 0; z < missing; z++) zeros.push('0');
      all = head.concat(zeros, tail);
    } else {
      all = head;
    }
    if (all.length !== 8) return null;
    var n = 0n;
    for (var i = 0; i < 8; i++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return null;
      n = (n << 16n) | BigInt(parseInt(all[i], 16));
    }
    return n;
  };

  N.ipv6Expand = function (n) {
    var parts = [];
    for (var i = 7; i >= 0; i--) parts.push(SK.pad(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16), 4));
    return parts.join(':');
  };

  // RFC 5952 style compression: longest run of zero groups becomes "::".
  N.ipv6Compress = function (n) {
    var g = [];
    for (var i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16));
    var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (var j = 0; j < 8; j++) {
      if (g[j] === '0') {
        if (curStart < 0) { curStart = j; curLen = 0; }
        curLen++;
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else { curStart = -1; curLen = 0; }
    }
    if (bestLen < 2) return g.join(':');
    var left = g.slice(0, bestStart).join(':'), right = g.slice(bestStart + bestLen).join(':');
    return left + '::' + right;
  };

  function in6(n, base, prefix) {
    var shift = BigInt(128 - prefix);
    return (n >> shift) === (base >> shift);
  }

  N.classifyIPv6 = function (s) {
    var n = N.parseIPv6(s);
    if (n === null) return null;
    var res = function (label, rfc, scope, routable) { return { ip: N.ipv6Compress(n), label: label, rfc: rfc, scope: scope, routable: routable }; };
    if (n === 0n) return res('Unspecified address', 'RFC 4291', 'reserved', false);
    if (n === 1n) return res('Loopback (this device)', 'RFC 4291', 'loopback', false);
    if (in6(n, 0xffffn << 32n, 96)) return res('IPv4-mapped IPv6 address', 'RFC 4291', 'reserved', false);
    if (in6(n, 0x0064ff9bn << 96n, 96)) return res('NAT64 translation prefix', 'RFC 6052', 'reserved', false);
    if (in6(n, 0xfe80n << 112n, 10)) return res('Link-local', 'RFC 4291', 'linklocal', false);
    if (in6(n, 0xfc00n << 112n, 7)) return res('Unique local (private)', 'RFC 4193', 'private', false);
    if (in6(n, 0xff00n << 112n, 8)) return res('Multicast', 'RFC 4291', 'multicast', false);
    if (in6(n, 0x20010db8n << 96n, 32)) return res('Documentation', 'RFC 3849', 'documentation', false);
    if (in6(n, 0x2002n << 112n, 16)) return res('6to4 tunnel address', 'RFC 3056', 'public', true);
    if (in6(n, 0x20010000n << 96n, 32)) return res('Teredo tunnel address', 'RFC 4380', 'public', true);
    if (in6(n, 0x2000n << 112n, 3)) return res('Global unicast (public)', 'RFC 4291', 'public', true);
    return res('Reserved or unallocated', 'RFC 4291', 'reserved', false);
  };

  N.classify = function (s) { return N.classifyIPv4(s) || N.classifyIPv6(s); };

  /* ---------- page wiring ---------- */

  function init() {
    if (!SK.$('net-cidr')) return;

    function kv(rows) {
      var t = SK.el('table', { className: 'kit-table' });
      rows.forEach(function (r) {
        t.appendChild(SK.el('tr', {}, [SK.el('th', { text: r[0] }), SK.el('td', { className: 'mono', text: String(r[1]) })]));
      });
      return SK.el('div', { className: 'kit-table-wrap' }, [t]);
    }
    function show(id, node) { var b = SK.$(id); SK.clear(b); b.appendChild(node); }
    function msg(text, kind) { return SK.el('div', { className: 'kit-callout ' + (kind || 'warn') }, [SK.el('p', { text: text })]); }

    // 1. CIDR calculator
    SK.$('net-cidr-run').addEventListener('click', function () {
      var v = SK.$('net-cidr').value.trim();
      var info = N.cidrInfo(v);
      if (!info) { show('net-cidr-out', msg('Enter an IPv4 address or range such as 10.20.30.0/24.')); return; }
      var rows = [['CIDR (network form)', info.cidr], ['Network address', info.network], ['Broadcast address', info.broadcast],
        ['Subnet mask', info.mask], ['Wildcard mask', info.wildcard], ['First usable', info.first], ['Last usable', info.last],
        ['Total addresses', info.total.toLocaleString()], ['Usable hosts', info.hosts.toLocaleString()]];
      var box = SK.el('div', {}, [kv(rows)]);
      if (info.inputHadHostBits) box.insertBefore(msg('The address you entered has host bits set, so it was rounded down to the network address.', 'warn'), box.firstChild);
      var cls = N.classifyIPv4(info.network);
      if (cls) box.appendChild(SK.el('p', { className: 'kit-note', text: 'Network starts in: ' + cls.label + (cls.rfc ? ' (' + cls.rfc + ')' : '') }));
      show('net-cidr-out', box);
    });

    // 2. Is this IP in these ranges?
    SK.$('net-in-run').addEventListener('click', function () {
      var ips = SK.$('net-in-ips').value.split(/[\s,;]+/).filter(Boolean);
      var ranges = SK.$('net-in-ranges').value.split(/[\s,;]+/).filter(Boolean);
      if (!ips.length || !ranges.length) { show('net-in-out', msg('Enter at least one address and one range.')); return; }
      var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, [SK.el('th', { text: 'Address' }), SK.el('th', { text: 'Matching range(s)' })])]);
      ips.forEach(function (ip) {
        var is6 = ip.indexOf(':') >= 0, matches = [], bad = false;
        ranges.forEach(function (r) {
          if (is6) {
            var m = /^(.+)\/(\d{1,3})$/.exec(r), a = N.parseIPv6(ip), b = m ? N.parseIPv6(m[1]) : N.parseIPv6(r);
            if (a === null) { bad = true; return; }
            if (b !== null && in6(a, b, m ? parseInt(m[2], 10) : 128)) matches.push(r);
          } else {
            var res = N.inCIDR4(ip, r);
            if (res === null && N.parseIPv4(ip) === null) bad = true;
            else if (res) matches.push(r);
          }
        });
        t.appendChild(SK.el('tr', {}, [SK.el('td', { className: 'mono', text: ip }), SK.el('td', { className: 'mono', text: bad ? 'Not a valid address' : (matches.length ? matches.join(', ') : 'No match') })]));
      });
      show('net-in-out', SK.el('div', { className: 'kit-table-wrap' }, [t]));
    });

    // 3. Classify a list
    SK.$('net-cls-run').addEventListener('click', function () {
      var list = SK.$('net-cls-in').value.split(/[\s,;]+/).filter(Boolean);
      if (!list.length) { show('net-cls-out', msg('Paste one or more IP addresses.')); return; }
      var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, [SK.el('th', { text: 'Address' }), SK.el('th', { text: 'Type' }), SK.el('th', { text: 'Worth an external lookup?' })])]);
      list.forEach(function (raw) {
        var c = N.classify(raw);
        var cells;
        if (!c) cells = [raw, 'Not a valid IP address', ''];
        else cells = [c.ip, c.label + (c.rfc ? ' (' + c.rfc + ')' : ''), c.routable ? 'Yes, it is public' : 'No, it is not a public address'];
        t.appendChild(SK.el('tr', {}, [SK.el('td', { className: 'mono', text: cells[0] }), SK.el('td', { text: cells[1] }), SK.el('td', { text: cells[2] })]));
      });
      show('net-cls-out', SK.el('div', { className: 'kit-table-wrap' }, [t]));
    });

    // 4. Range to CIDR
    SK.$('net-range-run').addEventListener('click', function () {
      var list = N.rangeToCIDRs(SK.$('net-range-a').value.trim(), SK.$('net-range-b').value.trim());
      if (!list) { show('net-range-out', msg('Enter a valid start address and an end address that is not lower than the start.')); return; }
      var box = SK.el('div', {}, [SK.el('div', { className: 'kit-out', text: list.join('\n') }), SK.copyButton('Copy list', function () { return list.join('\n'); })]);
      show('net-range-out', box);
    });

    // 5. Split a subnet
    SK.$('net-split-run').addEventListener('click', function () {
      var res = N.splitCIDR(SK.$('net-split-cidr').value.trim(), parseInt(SK.$('net-split-prefix').value, 10), 256);
      if (!res) { show('net-split-out', msg('Enter a valid network and a longer prefix (for example 10.0.0.0/16 into /24).')); return; }
      var note = res.total > res.blocks.length ? '\n... and ' + (res.total - res.blocks.length) + ' more' : '';
      show('net-split-out', SK.el('div', {}, [SK.el('p', { className: 'kit-note', text: res.total + ' subnets' }), SK.el('div', { className: 'kit-out', text: res.blocks.join('\n') + note }), SK.copyButton('Copy list', function () { return res.blocks.join('\n'); })]));
    });

    // 6. IPv6 helper
    SK.$('net-v6-run').addEventListener('click', function () {
      var n = N.parseIPv6(SK.$('net-v6').value);
      if (n === null) { show('net-v6-out', msg('Enter a valid IPv6 address.')); return; }
      var c = N.classifyIPv6(SK.$('net-v6').value);
      show('net-v6-out', kv([['Compressed', N.ipv6Compress(n)], ['Expanded', N.ipv6Expand(n)], ['Type', c.label + ' (' + c.rfc + ')']]));
    });

    // Arriving from the search box: fill in the matching section and run it (these tools work offline).
    var hq = SK.hashQuery();
    if (hq.q) {
      if (hq.k === 'cidr') { SK.$('net-cidr').value = hq.q; SK.$('net-cidr-run').click(); }
      else {
        SK.$('net-cls-in').value = hq.q; SK.$('net-cls-run').click();
        if (hq.q.indexOf(':') >= 0) { SK.$('net-v6').value = hq.q; SK.$('net-v6-run').click(); }
        else { SK.$('net-cidr').value = hq.q; SK.$('net-cidr-run').click(); }
      }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
