// Capture builder (SK.pcapBuild): makes small PCAP and PCAPNG files from scratch. It builds the example captures
// on the Snort/Suricata tuner page and the synthetic traffic in the tests. Packets use zero checksums, which the
// reader ignores.
(function () {
  var SK = window.SK = window.SK || {};
  var PB = SK.pcapBuild = {};
  var enc = new TextEncoder();

  function bytesOf(x) { return typeof x === 'string' ? enc.encode(x) : (x || new Uint8Array(0)); }
  function u16(n) { return [(n >> 8) & 255, n & 255]; }
  function u32(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]; }
  function ip4(s) { return s.split('.').map(Number); }
  function ip6(s) {
    var n = SK.net.parseIPv6(s), out = [];
    for (var i = 15; i >= 0; i--) out.push(Number((n >> BigInt(i * 8)) & 255n));
    return out;
  }
  function join(parts) {
    var total = parts.reduce(function (a, p) { return a + p.length; }, 0), out = new Uint8Array(total), o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }
  var MAC = [0, 1, 2, 3, 4, 5];

  // Layer 3 and 4 for one packet. o: { src, dst, sport, dport, seq, ack, flags, payload, proto, v6, ttl }
  PB.l3 = function (o) {
    var payload = bytesOf(o.payload), v6 = !!o.v6, l4;
    if (o.proto === 'udp') l4 = join([new Uint8Array([].concat(u16(o.sport), u16(o.dport), u16(8 + payload.length), [0, 0])), payload]);
    else if (o.proto === 'icmp') l4 = join([new Uint8Array([o.type || 8, o.code || 0, 0, 0]), payload]);
    else l4 = join([new Uint8Array([].concat(u16(o.sport), u16(o.dport), u32(o.seq || 0), u32(o.ack || 0), [0x50, o.flags === undefined ? 0x18 : o.flags], u16(65535), [0, 0, 0, 0])), payload]);
    var proto = o.proto === 'udp' ? 17 : o.proto === 'icmp' ? (v6 ? 58 : 1) : 6;
    if (v6) return join([new Uint8Array([].concat([0x60, 0, 0, 0], u16(l4.length), [proto, o.ttl || 64], ip6(o.src), ip6(o.dst))), l4]);
    return join([new Uint8Array([].concat([0x45, 0], u16(20 + l4.length), [0, 1, 0x40, 0, o.ttl || 64, proto, 0, 0], ip4(o.src), ip4(o.dst))), l4]);
  };

  // A full link-layer frame. link: 'eth' (default), 'vlan', 'raw', 'sll'
  PB.frame = function (o) {
    var l3 = PB.l3(o), link = o.link || 'eth', et = o.v6 ? 0x86dd : 0x0800;
    if (link === 'raw') return l3;
    if (link === 'sll') return join([new Uint8Array([].concat([0, 0], [0, 1], [0, 6], MAC, [0, 0], u16(et))), l3]);
    if (link === 'vlan') return join([new Uint8Array([].concat(MAC, MAC, [0x81, 0], [0, 5], u16(et))), l3]);
    return join([new Uint8Array([].concat(MAC, MAC, u16(et))), l3]);
  };

  var LINKTYPE = { eth: 1, vlan: 1, raw: 101, sll: 113 };

  // Classic capture. packets: [{ ts (ms), frame }]. opts: { big, nano, link }
  PB.pcap = function (packets, opts) {
    opts = opts || {};
    var big = !!opts.big, link = LINKTYPE[opts.link || 'eth'];
    function w32(n) { return big ? u32(n) : u32(n).reverse(); }
    function w16(n) { return big ? u16(n) : u16(n).reverse(); }
    var magic = opts.nano ? 0xa1b23c4d : 0xa1b2c3d4;
    var parts = [new Uint8Array([].concat(w32(magic), w16(2), w16(4), w32(0), w32(0), w32(65535), w32(link)))];
    packets.forEach(function (p) {
      var sec = Math.floor(p.ts / 1000), frac = opts.nano ? Math.round((p.ts - sec * 1000) * 1e6) : Math.round((p.ts - sec * 1000) * 1000);
      parts.push(new Uint8Array([].concat(w32(sec), w32(frac), w32(p.frame.length), w32(p.frame.length))), p.frame);
    });
    return join(parts);
  };

  function pad4(a) { var n = (4 - (a.length % 4)) % 4; return n ? join([a, new Uint8Array(n)]) : a; }

  // PCAPNG with one interface (optionally with a nanosecond timestamp resolution option).
  PB.pcapng = function (packets, opts) {
    opts = opts || {};
    function block(type, body) { var padded = pad4(body), len = 12 + padded.length; return join([new Uint8Array([].concat(u32(type).reverse(), u32(len).reverse())), padded, new Uint8Array(u32(len).reverse())]); }
    var shb = block(0x0a0d0d0a, new Uint8Array([].concat(u32(0x1a2b3c4d).reverse(), [1, 0, 0, 0], [255, 255, 255, 255, 255, 255, 255, 255])));
    var idbBody = [].concat([1, 0, 0, 0], u32(65535).reverse());
    if (opts.nano) idbBody = idbBody.concat([9, 0, 1, 0, 9, 0, 0, 0], [0, 0, 0, 0]);
    var idb = block(1, new Uint8Array(idbBody));
    var parts = [shb, idb];
    packets.forEach(function (p) {
      var units = opts.nano ? Math.round(p.ts * 1e6) : Math.round(p.ts * 1000);
      var hi = Math.floor(units / 4294967296), lo = units % 4294967296;
      var body = join([new Uint8Array([].concat(u32(0).reverse(), u32(hi).reverse(), u32(lo).reverse(), u32(p.frame.length).reverse(), u32(p.frame.length).reverse())), p.frame]);
      parts.push(block(6, body));
    });
    return join(parts);
  };

  // A complete TCP session: handshake, request, response and close. Returns frames with timestamps.
  // o: { client, server, cport, sport, request, response, t0, split (request chunk size), isn }
  PB.tcpSession = function (o) {
    var t = o.t0 || 1700000000000, isnC = o.isn === undefined ? 1000 : o.isn, isnS = 5000, pk = [];
    var c = { src: o.client, dst: o.server, sport: o.cport || 40000, dport: o.sport || 80 }, s = { src: o.server, dst: o.client, sport: c.dport, dport: c.sport };
    function add(base, extra) { pk.push({ ts: t, frame: PB.frame(Object.assign({ proto: 'tcp', v6: o.v6, link: o.link }, base, extra)) }); t += 1; }
    var req = bytesOf(o.request), res = bytesOf(o.response);
    var cseq = isnC, sseq = isnS;
    if (!o.noHandshake) {
      add(c, { seq: cseq, flags: 0x02, payload: '' }); cseq++;
      add(s, { seq: sseq, ack: cseq, flags: 0x12, payload: '' }); sseq++;
      add(c, { seq: cseq, ack: sseq, flags: 0x10, payload: '' });
    }
    var size = o.split || req.length || 1;
    for (var i = 0; i < req.length; i += size) {
      var chunk = req.subarray(i, i + size);
      add(c, { seq: cseq, ack: sseq, flags: 0x18, payload: chunk }); cseq += chunk.length;
    }
    if (res.length) {
      add(s, { seq: sseq, ack: cseq, flags: 0x18, payload: res }); sseq += res.length;
      add(c, { seq: cseq, ack: sseq, flags: 0x10, payload: '' });
    }
    if (!o.noClose) { add(c, { seq: cseq, ack: sseq, flags: 0x11, payload: '' }); add(s, { seq: sseq, ack: cseq + 1, flags: 0x11, payload: '' }); }
    return pk;
  };

  PB.udp = function (o) { return { ts: o.ts || 1700000000000, frame: PB.frame(Object.assign({ proto: 'udp' }, o)) }; };

  PB.http = function (method, uri, headers, body) {
    var h = [method + ' ' + uri + ' HTTP/1.1', 'Host: ' + ((headers && headers.Host) || 'example.test')];
    Object.keys(headers || {}).forEach(function (k) { if (k !== 'Host') h.push(k + ': ' + headers[k]); });
    if (body !== undefined && !(headers && headers['Content-Length'])) h.push('Content-Length: ' + body.length);
    return h.join('\r\n') + '\r\n\r\n' + (body || '');
  };
  PB.httpResponse = function (code, body, headers) {
    var h = ['HTTP/1.1 ' + code + ' ' + (code === 200 ? 'OK' : 'Status'), 'Content-Length: ' + (body || '').length];
    Object.keys(headers || {}).forEach(function (k) { h.push(k + ': ' + headers[k]); });
    return h.join('\r\n') + '\r\n\r\n' + (body || '');
  };
  PB.merge = function () { return Array.prototype.concat.apply([], arguments).sort(function (a, b) { return a.ts - b.ts; }); };
})();
