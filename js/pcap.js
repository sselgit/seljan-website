// Capture file reader (SK.pcap): classic PCAP and PCAPNG, Ethernet and common link types, IPv4 and IPv6,
// TCP, UDP and ICMP, and TCP stream reassembly. Everything is read from a local file in the browser.
(function () {
  var SK = window.SK = window.SK || {};
  var P = SK.pcap = {};

  var MAX_PACKETS = 400000;
  var MAX_STREAM = 2 * 1024 * 1024;

  function fail(msg) { var e = new Error(msg); e.userMessage = msg; return e; }

  /* ================================================================ file formats */

  // Returns { format, linktype, packets: [{ ts (ms), data, origLen, link }], warnings }.
  P.parse = function (bytes) {
    var b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (b.length < 12) throw fail('That file is too small to be a capture.');
    if (b[0] === 0x1f && b[1] === 0x8b) throw fail('That file is compressed. Use P.parseAsync or decompress it first.');
    if (b[0] === 0x0a && b[1] === 0x0d && b[2] === 0x0d && b[3] === 0x0a) return parsePcapng(b);
    var magic = (b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0;
    if (magic === 0xd4c3b2a1) return parseClassic(b, true, false);
    if (magic === 0xa1b2c3d4) return parseClassic(b, false, false);
    if (magic === 0x4d3cb2a1) return parseClassic(b, true, true);
    if (magic === 0xa1b23c4d) return parseClassic(b, false, true);
    throw fail('That does not look like a PCAP or PCAPNG file. Save the capture as .pcap or .pcapng (for example with tcpdump or Wireshark).');
  };

  // Same as parse, but also accepts gzip-compressed captures (browsers can decompress them natively).
  P.parseAsync = function (bytes) {
    var b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (!(b[0] === 0x1f && b[1] === 0x8b)) return Promise.resolve().then(function () { return P.parse(b); });
    if (typeof DecompressionStream === 'undefined') return Promise.reject(fail('This browser cannot decompress .gz files. Decompress the capture first.'));
    var stream = new Blob([b]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(stream).arrayBuffer().then(function (buf) { return P.parse(new Uint8Array(buf)); });
  };

  function parseClassic(b, little, nano) {
    var dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    var u32 = function (o) { return dv.getUint32(o, little); };
    var linktype = u32(20) & 0xffff, off = 24, packets = [], warnings = [];
    while (off + 16 <= b.length) {
      var sec = u32(off), frac = u32(off + 4), incl = u32(off + 8), orig = u32(off + 12);
      off += 16;
      if (incl > 262144 * 4 || off + incl > b.length) {
        warnings.push(off + incl > b.length && incl <= 262144 * 4 ? 'The file ends in the middle of a packet; the last packet was dropped.' : 'A packet record looked corrupt; reading stopped there.');
        break;
      }
      packets.push({ ts: sec * 1000 + (nano ? frac / 1e6 : frac / 1000), data: b.subarray(off, off + incl), origLen: orig, link: linktype });
      off += incl;
      if (packets.length >= MAX_PACKETS) { warnings.push('Only the first ' + MAX_PACKETS + ' packets were read.'); break; }
    }
    return { format: 'pcap', linktype: linktype, packets: packets, warnings: warnings };
  }

  function parsePcapng(b) {
    var dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    var little = true, off = 0, ifaces = [], packets = [], warnings = [];
    while (off + 12 <= b.length) {
      var type = dv.getUint32(off, little);
      if (off === 0) {
        // Section header: the byte-order magic tells us how to read the rest.
        little = dv.getUint32(8, true) === 0x1a2b3c4d;
        if (!little && dv.getUint32(8, false) !== 0x1a2b3c4d) throw fail('That PCAPNG file has an unreadable header.');
        type = dv.getUint32(off, little);
      }
      var len = dv.getUint32(off + 4, little);
      if (len < 12 || off + len > b.length) { warnings.push('The file ends in the middle of a block; reading stopped there.'); break; }
      var body = off + 8;
      if (type === 0x0a0d0d0a) {
        ifaces = [];
        little = dv.getUint32(body, true) === 0x1a2b3c4d;
      } else if (type === 1) {
        var iface = { link: dv.getUint16(body, little), tsres: 1e-6 };
        for (var o = body + 8; o + 4 <= off + len - 4;) {
          var code = dv.getUint16(o, little), olen = dv.getUint16(o + 2, little);
          if (code === 0) break;
          if (code === 9 && olen >= 1) {
            var v = b[o + 4];
            iface.tsres = v & 0x80 ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v);
          }
          o += 4 + ((olen + 3) & ~3);
        }
        ifaces.push(iface);
      } else if (type === 6) {
        var ifc = ifaces[dv.getUint32(body, little)] || { link: 1, tsres: 1e-6 };
        var th = dv.getUint32(body + 4, little), tl = dv.getUint32(body + 8, little);
        var cap = dv.getUint32(body + 12, little), orig = dv.getUint32(body + 16, little);
        if (body + 20 + cap <= b.length) {
          packets.push({ ts: (th * 4294967296 + tl) * ifc.tsres * 1000, data: b.subarray(body + 20, body + 20 + cap), origLen: orig, link: ifc.link });
        }
      } else if (type === 3) {
        var origS = dv.getUint32(body, little), capS = Math.min(origS, len - 16);
        packets.push({ ts: 0, data: b.subarray(body + 4, body + 4 + capS), origLen: origS, link: (ifaces[0] || { link: 1 }).link });
      }
      off += (len + 3) & ~3;
      if (packets.length >= MAX_PACKETS) { warnings.push('Only the first ' + MAX_PACKETS + ' packets were read.'); break; }
    }
    return { format: 'pcapng', linktype: ifaces[0] ? ifaces[0].link : 1, packets: packets, warnings: warnings };
  }

  /* ================================================================ packet decoding */

  function ipv4Str(b, o) { return b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3]; }
  function ipv6Str(b, o) {
    var v = 0n;
    for (var i = 0; i < 16; i++) v = (v << 8n) | BigInt(b[o + i]);
    return SK.net ? SK.net.ipv6Compress(v) : v.toString(16);
  }

  // Locate the IP header: returns { off, version } or null.
  function ipStart(pkt) {
    var d = pkt.data, off = 0, i = 0, et;
    switch (pkt.link) {
      case 1: {
        if (d.length < 14) return null;
        off = 14; et = (d[12] << 8) | d[13];
        while ((et === 0x8100 || et === 0x88a8 || et === 0x9100) && off + 4 <= d.length) { et = (d[off + 2] << 8) | d[off + 3]; off += 4; i++; if (i > 3) break; }
        if (et === 0x0800) return { off: off, version: 4 };
        if (et === 0x86dd) return { off: off, version: 6 };
        return null;
      }
      case 113: off = 16; break;
      case 276: off = 20; break;
      case 0: case 108: off = 4; break;
      case 101: case 228: case 229: off = 0; break;
      default: return null;
    }
    if (off >= d.length) return null;
    var v = d[off] >> 4;
    return v === 4 || v === 6 ? { off: off, version: v } : null;
  }

  // Returns a decoded packet or null for anything that is not IPv4/IPv6.
  P.decode = function (pkt, index) {
    var d = pkt.data, s = ipStart(pkt);
    if (!s) return null;
    var o = s.off, out = { index: index, ts: pkt.ts, ipv: s.version, len: pkt.origLen };
    var proto, payloadOff, payloadEnd;
    if (s.version === 4) {
      if (d.length < o + 20) return null;
      var ihl = (d[o] & 15) * 4, total = (d[o + 2] << 8) | d[o + 3], flagsFrag = (d[o + 6] << 8) | d[o + 7];
      if (ihl < 20 || d.length < o + ihl) return null;
      out.ttl = d[o + 8]; proto = d[o + 9];
      out.src = ipv4Str(d, o + 12); out.dst = ipv4Str(d, o + 16);
      if ((flagsFrag & 0x1fff) !== 0) { out.fragment = true; return null; }
      payloadOff = o + ihl;
      payloadEnd = Math.min(d.length, total >= ihl ? o + total : d.length);
    } else {
      if (d.length < o + 40) return null;
      var next = d[o + 6], p = o + 40;
      out.ttl = d[o + 7];
      out.src = ipv6Str(d, o + 8); out.dst = ipv6Str(d, o + 24);
      var plen = (d[o + 4] << 8) | d[o + 5];
      payloadEnd = Math.min(d.length, plen ? o + 40 + plen : d.length);
      for (var hops = 0; hops < 8; hops++) {
        if (next === 0 || next === 43 || next === 60) { if (p + 2 > d.length) return null; var nn = d[p]; p += (d[p + 1] + 1) * 8; next = nn; }
        else if (next === 44) { if (p + 8 > d.length) return null; if (((d[p + 2] << 8 | d[p + 3]) & 0xfff8) !== 0) return null; var nf = d[p]; p += 8; next = nf; }
        else if (next === 51) { if (p + 2 > d.length) return null; var na = d[p]; p += (d[p + 1] + 2) * 4; next = na; }
        else break;
      }
      proto = next; payloadOff = p;
    }
    if (payloadOff > payloadEnd) return null;
    out.proto = proto;
    var t = payloadOff;
    if (proto === 6) {
      if (payloadEnd < t + 20) return null;
      var doff = (d[t + 12] >> 4) * 4;
      if (doff < 20 || t + doff > payloadEnd) return null;
      var fl = d[t + 13];
      out.sport = (d[t] << 8) | d[t + 1]; out.dport = (d[t + 2] << 8) | d[t + 3];
      out.tcp = { seq: ((d[t + 4] << 24) | (d[t + 5] << 16) | (d[t + 6] << 8) | d[t + 7]) >>> 0, ack: ((d[t + 8] << 24) | (d[t + 9] << 16) | (d[t + 10] << 8) | d[t + 11]) >>> 0,
        flags: fl, syn: !!(fl & 2), ack_: !!(fl & 16), fin: !!(fl & 1), rst: !!(fl & 4), psh: !!(fl & 8), win: (d[t + 14] << 8) | d[t + 15] };
      out.payload = d.subarray(t + doff, payloadEnd);
    } else if (proto === 17) {
      if (payloadEnd < t + 8) return null;
      out.sport = (d[t] << 8) | d[t + 1]; out.dport = (d[t + 2] << 8) | d[t + 3];
      out.payload = d.subarray(t + 8, payloadEnd);
    } else if (proto === 1 || proto === 58) {
      if (payloadEnd < t + 4) return null;
      out.icmp = { type: d[t], code: d[t + 1] };
      out.sport = 0; out.dport = 0;
      out.payload = d.subarray(t + 4, payloadEnd);
    } else {
      out.sport = 0; out.dport = 0;
      out.payload = d.subarray(payloadOff, payloadEnd);
    }
    return out;
  };

  /* ================================================================ sessions and TCP reassembly */

  function concat(chunks, total) {
    var out = new Uint8Array(total), o = 0;
    chunks.forEach(function (c) { out.set(c, o); o += c.length; });
    return out;
  }

  function reassemble(segs) {
    // segs: [{ seq, data, ts, pkt, syn }] in arrival order.
    var base = null, i;
    for (i = 0; i < segs.length; i++) if (segs[i].syn) { base = (segs[i].seq + 1) >>> 0; break; }
    if (base === null && segs.length) base = segs[0].seq;
    var items = segs.filter(function (s) { return s.data.length; }).map(function (s, n) {
      var rel = (s.seq - base) | 0;     // signed 32-bit distance, so wrap-around works
      return { rel: rel, data: s.data, ts: s.ts, pkt: s.pkt, n: n };
    });
    items.sort(function (a, b) { return a.rel - b.rel || a.n - b.n; });
    var chunks = [], list = [], pos = null, total = 0, gaps = 0, truncated = false, dup = 0;
    items.forEach(function (it) {
      if (pos === null) pos = it.rel;
      if (it.rel + it.data.length <= pos) { dup++; return; }                    // pure retransmission
      var skip = pos > it.rel ? pos - it.rel : 0;
      if (it.rel > pos) { gaps++; pos = it.rel; }                                 // missing data: continue after the hole
      var chunk = skip ? it.data.subarray(skip) : it.data;
      if (total + chunk.length > MAX_STREAM) { chunk = chunk.subarray(0, Math.max(0, MAX_STREAM - total)); truncated = true; }
      if (chunk.length) { list.push({ start: total, len: chunk.length, ts: it.ts, pkt: it.pkt }); chunks.push(chunk); total += chunk.length; pos += chunk.length; }
    });
    return { data: concat(chunks, total), segs: list, gaps: gaps, truncated: truncated, retransmits: dup };
  }

  function key(a, ap, b, bp) { return a < b || (a === b && ap <= bp) ? a + '|' + ap + '|' + b + '|' + bp : b + '|' + bp + '|' + a + '|' + ap; }

  // Groups decoded packets into sessions (TCP, UDP, ICMP) with reassembled TCP streams.
  P.buildSessions = function (decoded) {
    var map = {}, order = [];
    decoded.forEach(function (p) {
      if (!p) return;
      var kind = p.proto === 6 ? 'tcp' : p.proto === 17 ? 'udp' : (p.proto === 1 || p.proto === 58) ? 'icmp' : 'other';
      var k = kind + '|' + key(p.src, p.sport, p.dst, p.dport);
      var s = map[k];
      if (!s) {
        s = map[k] = { id: order.length + 1, proto: kind, ipv: p.ipv, start: p.ts, end: p.ts, packets: 0, bytes: 0, first: p, synFrom: null, synAckFrom: null, finSeen: false, rstSeen: false,
          pk: { a: [], b: [] }, datagrams: [], pktCount: { a: 0, b: 0 } };
        order.push(s);
      }
      s.end = p.ts; s.packets++; s.bytes += p.len;
      var side = (p.src === s.first.src && p.sport === s.first.sport) ? 'a' : 'b';
      s.pktCount[side]++;
      if (kind === 'tcp') {
        if (p.tcp.syn && !p.tcp.ack_ && s.synFrom === null) s.synFrom = side;
        if (p.tcp.syn && p.tcp.ack_ && s.synAckFrom === null) s.synAckFrom = side;
        if (p.tcp.fin) s.finSeen = true;
        if (p.tcp.rst) s.rstSeen = true;
        s.pk[side].push({ seq: p.tcp.seq, data: p.payload, ts: p.ts, pkt: p.index, syn: p.tcp.syn });
      } else if (p.payload.length || kind === 'icmp') {
        s.datagrams.push({ side: side, ts: p.ts, data: p.payload, pkt: p.index, icmp: p.icmp || null, ttl: p.ttl });
      }
    });
    var stats = { tcp: 0, udp: 0, icmp: 0, other: 0, gaps: 0, truncated: 0 };
    var sessions = order.map(function (s) {
      var f = s.first, clientSide = 'a';
      if (s.proto === 'tcp') {
        if (s.synFrom) clientSide = s.synFrom;
        else if (s.synAckFrom) clientSide = s.synAckFrom === 'a' ? 'b' : 'a';
        else if (f.sport < 1024 && f.dport >= 1024) clientSide = 'b';       // mid-stream capture: the low port is usually the server
      } else if (s.proto === 'udp' && f.sport < 1024 && f.dport >= 1024 && s.datagrams.length && s.pktCount.b === 0) clientSide = 'b';
      var serverSide = clientSide === 'a' ? 'b' : 'a';
      var A = { ip: f.src, port: f.sport }, B = { ip: f.dst, port: f.dport };
      var client = clientSide === 'a' ? A : B, server = clientSide === 'a' ? B : A;
      var sess = { id: s.id, proto: s.proto, ipv: s.ipv, client: client, server: server, start: s.start, end: s.end, packets: s.packets, bytes: s.bytes,
        synSeen: !!s.synFrom, synAckSeen: !!s.synAckFrom, finSeen: s.finSeen, rstSeen: s.rstSeen, dirs: {}, datagrams: [], pktCount: { toServer: s.pktCount[clientSide], toClient: s.pktCount[serverSide] } };
      if (s.proto === 'tcp') {
        sess.dirs.toServer = reassemble(s.pk[clientSide]);
        sess.dirs.toClient = reassemble(s.pk[serverSide]);
        sess.established = !!s.synAckFrom || (sess.dirs.toServer.data.length > 0 && sess.dirs.toClient.data.length > 0);
        stats.gaps += sess.dirs.toServer.gaps + sess.dirs.toClient.gaps;
        stats.truncated += (sess.dirs.toServer.truncated ? 1 : 0) + (sess.dirs.toClient.truncated ? 1 : 0);
      } else {
        sess.datagrams = s.datagrams.map(function (g) { return { dir: g.side === clientSide ? 'toServer' : 'toClient', ts: g.ts, data: g.data, pkt: g.pkt, icmp: g.icmp }; });
        sess.established = s.pktCount.a > 0 && s.pktCount.b > 0;
      }
      stats[s.proto]++;
      return sess;
    });
    return { sessions: sessions, stats: stats };
  };

  // Convenience: file bytes to sessions.
  P.read = function (bytes) {
    return P.parseAsync(bytes).then(function (cap) {
      var decoded = cap.packets.map(function (p, i) { return P.decode(p, i); });
      var built = P.buildSessions(decoded);
      var skipped = decoded.filter(function (x) { return !x; }).length;
      var times = cap.packets.map(function (p) { return p.ts; }).filter(Boolean);
      return { format: cap.format, linktype: cap.linktype, packetCount: cap.packets.length, skipped: skipped, sessions: built.sessions, stats: built.stats, warnings: cap.warnings,
        start: times.length ? Math.min.apply(null, times) : 0, end: times.length ? Math.max.apply(null, times) : 0 };
    });
  };
})();
