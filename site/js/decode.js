// Decoder toolkit: core logic (SK.decode) plus the page wiring. Everything runs locally.
(function () {
  var SK = window.SK = window.SK || {};
  var D = SK.decode = {};
  var enc = new TextEncoder();

  /* ---------- byte and text helpers ---------- */

  D.strToBytes = function (s) { return enc.encode(s); };

  function bytesFromLatin1(bin) {
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 255;
    return out;
  }

  // Share of bytes that are printable ASCII or common whitespace.
  D.printableRatio = function (bytes) {
    if (!bytes.length) return 0;
    var n = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) n++;
    }
    return n / bytes.length;
  };

  function textPrintableRatio(text) {
    if (!text.length) return 0;
    var n = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c > 159) n++;
    }
    return n / text.length;
  }

  // PowerShell -EncodedCommand and many Windows blobs are UTF-16LE: every other byte is zero.
  D.looksUtf16le = function (bytes) {
    if (bytes.length < 4 || bytes.length % 2) return false;
    var zeros = 0, pairs = bytes.length / 2;
    for (var i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    return zeros / pairs > 0.8;
  };

  D.bytesToText = function (bytes) {
    if (D.looksUtf16le(bytes)) return { text: new TextDecoder('utf-16le').decode(bytes), enc: 'UTF-16LE' };
    try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), enc: 'UTF-8' }; } catch (e) { /* fall through */ }
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return { text: s, enc: 'Latin-1' };
  };

  // Make control characters visible so odd bytes do not break the display.
  D.displayText = function (text) {
    return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, function (c) {
      return '·';
    });
  };

  /* ---------- individual decoders (return bytes or null) ---------- */

  D.fromBase64 = function (s) {
    var t = s.replace(/\s+/g, '');
    if (t.length < 8 || !/^[A-Za-z0-9+\/_-]+={0,2}$/.test(t)) return null;
    t = t.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
    if (t.length % 4 === 1) return null;
    while (t.length % 4) t += '=';
    var bin;
    try { bin = atob(t); } catch (e) { return null; }
    return bytesFromLatin1(bin);
  };

  D.fromHex = function (s) {
    var t = s.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[\s:,\-]/g, '');
    if (t.length < 2 || t.length % 2 || !/^[0-9a-fA-F]+$/.test(t)) return null;
    var out = new Uint8Array(t.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
    return out;
  };

  // Percent-decoding done by hand so invalid UTF-8 never throws. "+" becomes a space (form encoding).
  D.fromUrl = function (s) {
    if (!/%[0-9a-fA-F]{2}/.test(s)) return null;
    var t = s.replace(/\+/g, ' ');
    var out = [], i = 0;
    while (i < t.length) {
      if (t.charAt(i) === '%' && /^[0-9a-fA-F]{2}$/.test(t.substr(i + 1, 2))) {
        out.push(parseInt(t.substr(i + 1, 2), 16));
        i += 3;
      } else {
        var chunk = String.fromCodePoint(t.codePointAt(i));
        var b = enc.encode(chunk);
        for (var k = 0; k < b.length; k++) out.push(b[k]);
        i += chunk.length;
      }
    }
    return new Uint8Array(out);
  };

  var NAMED = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' };
  D.fromHtmlEntities = function (s) {
    var found = false;
    var t = s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, function (m, body) {
      var r = null;
      if (body.charAt(0) === '#') {
        var cp = body.charAt(1).toLowerCase() === 'x' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
        if (cp > 0 && cp <= 0x10ffff) r = String.fromCodePoint(cp);
      } else if (Object.prototype.hasOwnProperty.call(NAMED, body.toLowerCase())) {
        r = NAMED[body.toLowerCase()];
      }
      if (r === null) return m;
      found = true;
      return r;
    });
    return found ? enc.encode(t) : null;
  };

  D.fromBinary = function (s) {
    var t = s.replace(/\s+/g, '');
    if (t.length < 8 || t.length % 8 || !/^[01]+$/.test(t)) return null;
    var out = new Uint8Array(t.length / 8);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 8, 8), 2);
    return out;
  };

  D.fromDecimalList = function (s) {
    if (!/^\s*\d{1,3}([\s,;]+\d{1,3})+\s*$/.test(s)) return null;
    var parts = s.trim().split(/[\s,;]+/), out = new Uint8Array(parts.length);
    for (var i = 0; i < parts.length; i++) {
      var n = parseInt(parts[i], 10);
      if (n > 255) return null;
      out[i] = n;
    }
    return out;
  };

  // String.fromCharCode(72,101,...) and PowerShell [char]72+[char]101
  D.fromCharCodes = function (s) {
    var nums = [];
    var m = s.match(/fromCharCode\s*\(([^)]*)\)/i);
    if (m) {
      nums = m[1].split(',').map(function (x) { return parseInt(x.trim(), 10); });
    } else {
      var re = /\[char\]\s*(?:0x([0-9a-f]+)|(\d+))/gi, r;
      while ((r = re.exec(s))) nums.push(r[1] ? parseInt(r[1], 16) : parseInt(r[2], 10));
    }
    nums = nums.filter(function (n) { return n >= 0 && n <= 0x10ffff; });
    if (nums.length < 2) return null;
    return enc.encode(nums.map(function (n) { return String.fromCodePoint(n); }).join(''));
  };

  // A, \u{1F600}, \x41
  D.fromEscapes = function (s) {
    var found = false;
    var t = s.replace(/\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g, function (m, a, b, c) {
      found = true;
      var cp = parseInt(a || b || c, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    });
    return found ? enc.encode(t) : null;
  };

  var COMMON_WORDS = ('the and for are but not you all any can had her was one our out day get has him his how man new now old see two way who boy did its let put say she too use ' +
    'that with have this will your from they know want been good much some time very when come here just like long make many over such take than them well were ' +
    'hello world http https www com net org exe cmd powershell invoke function script password admin login user file system windows error open run set download ' +
    'echo write host start process command install update config server client data text name value true false null return string print import').split(' ');
  var COMMON_SET = {};
  COMMON_WORDS.forEach(function (w) { COMMON_SET[w] = true; });

  // True when the text contains enough ordinary words that it is probably a real message.
  D.looksLikeWords = function (text) {
    var words = String(text).toLowerCase().match(/[a-z]{3,}/g) || [];
    if (!words.length) return false;
    var hits = words.filter(function (w) { return COMMON_SET[w]; }).length;
    return hits >= 2 || (hits >= 1 && hits / words.length >= 0.25);
  };

  D.rot = function (s, n) {
    return s.replace(/[a-zA-Z]/g, function (c) {
      var base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + n) % 26 + base);
    });
  };

  D.reverse = function (s) { return Array.from(s).reverse().join(''); };

  /* ---------- run every decoder ---------- */

  var DECODERS = [
    { id: 'base64', name: 'Base64 / Base64url', fn: D.fromBase64 },
    { id: 'hex', name: 'Hex', fn: D.fromHex },
    { id: 'url', name: 'URL (percent) encoding', fn: D.fromUrl },
    { id: 'charcodes', name: 'Character codes (fromCharCode, [char])', fn: D.fromCharCodes },
    { id: 'escapes', name: 'Escape sequences (\\u0041, \\x41)', fn: D.fromEscapes },
    { id: 'html', name: 'HTML entities', fn: D.fromHtmlEntities },
    { id: 'binary', name: 'Binary (8-bit groups)', fn: D.fromBinary },
    { id: 'decimal', name: 'Decimal byte list', fn: D.fromDecimalList }
  ];

  function describe(bytes) {
    var view = D.bytesToText(bytes);
    var ratio = view.enc === 'UTF-16LE' || view.enc === 'UTF-8' ? textPrintableRatio(view.text) : D.printableRatio(bytes);
    return { bytes: bytes, text: view.text, enc: view.enc, score: ratio };
  }

  // Returns every decoding that applies. Text-based tricks (ROT13, reverse) are added last.
  D.tryAll = function (input) {
    var out = [];
    DECODERS.forEach(function (d) {
      var bytes = null;
      try { bytes = d.fn(input); } catch (e) { bytes = null; }
      if (!bytes || !bytes.length) return;
      var r = describe(bytes);
      r.id = d.id;
      r.name = d.name;
      out.push(r);
    });
    var rot13 = D.rot(input, 13);
    if (rot13 !== input) {
      var rr = describe(enc.encode(rot13)); rr.id = 'rot13'; rr.name = 'ROT13'; out.push(rr);
    }
    var rev = D.reverse(input);
    if (rev !== input) {
      var rv = describe(enc.encode(rev)); rv.id = 'reverse'; rv.name = 'Reversed text'; out.push(rv);
    }
    return out;
  };

  /* ---------- compression ---------- */

  D.isCompressed = function (bytes) {
    if (bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return 'gzip';
    if (bytes.length > 2 && bytes[0] === 0x78 && (bytes[1] === 0x01 || bytes[1] === 0x9c || bytes[1] === 0xda)) return 'deflate';
    return null;
  };

  D.inflate = async function (bytes, format) {
    if (typeof DecompressionStream === 'undefined') return null;
    try {
      var ds = new DecompressionStream(format);
      var stream = new Blob([bytes]).stream().pipeThrough(ds);
      var buf = await new Response(stream).arrayBuffer();
      return new Uint8Array(buf);
    } catch (e) {
      return null;
    }
  };

  /* ---------- auto-decode layers ---------- */

  var PEEL_ORDER = ['base64', 'hex', 'url', 'charcodes', 'escapes', 'html', 'binary', 'decimal'];

  // Repeatedly applies the most convincing decoding. Stops when the result no longer looks like text.
  D.peel = async function (input, maxDepth) {
    var steps = [], cur = input, lastBytes = null;
    for (var depth = 0; depth < (maxDepth || 8); depth++) {
      var cands = D.tryAll(cur).filter(function (c) {
        return PEEL_ORDER.indexOf(c.id) >= 0 && c.text !== cur && c.bytes.length >= 2;
      });
      var good = cands.filter(function (c) { return c.score >= 0.9; });
      var pick = null;
      for (var i = 0; i < PEEL_ORDER.length && !pick; i++) {
        pick = good.filter(function (c) { return c.id === PEEL_ORDER[i]; })[0] || null;
      }
      if (!pick) {
        // Possibly compressed data after Base64.
        var bin = cands.filter(function (c) { return c.id === 'base64' || c.id === 'hex'; })[0];
        if (bin && D.isCompressed(bin.bytes)) {
          var fmt = D.isCompressed(bin.bytes);
          var inflated = await D.inflate(bin.bytes, fmt);
          if (inflated) {
            steps.push({ method: bin.name + ' then ' + fmt + ' decompress', text: D.bytesToText(inflated).text, bytes: inflated, score: describe(inflated).score });
            lastBytes = inflated;
            cur = D.bytesToText(inflated).text;
            if (D.printableRatio(inflated) < 0.9) break;
            continue;
          }
        }
        if (bin) lastBytes = bin.bytes;
        break;
      }
      var label = pick.name + (pick.enc === 'UTF-16LE' ? ' (text is UTF-16LE)' : '');
      steps.push({ method: label, text: pick.text, bytes: pick.bytes, score: pick.score });
      lastBytes = pick.bytes;
      cur = pick.text;
    }
    return { steps: steps, final: cur, finalBytes: lastBytes };
  };

  /* ---------- XOR ---------- */

  function englishScore(bytes) {
    var score = 0;
    for (var i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b === 32) score += 2;
      else if ((b >= 97 && b <= 122)) score += 2;
      else if ((b >= 65 && b <= 90)) score += 1.5;
      else if (b >= 48 && b <= 57) score += 1;
      else if (b === 10 || b === 13 || b === 9 || (b >= 33 && b <= 126)) score += 0.5;
      else score -= 3;
    }
    return score / (bytes.length || 1);
  }

  D.xorWithKey = function (bytes, key) {
    var out = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
    return out;
  };

  // Try every single-byte key. A crib (text you expect to see, like "http" or "MZ") narrows the list.
  D.xorBrute = function (bytes, crib, top) {
    var results = [];
    var cribLower = crib ? crib.toLowerCase() : '';
    for (var k = 1; k < 256; k++) {
      var out = D.xorWithKey(bytes, [k]);
      var ratio = D.printableRatio(out);
      var text = D.bytesToText(out).text;
      var hasCrib = cribLower ? text.toLowerCase().indexOf(cribLower) >= 0 : false;
      if (cribLower && !hasCrib) continue;
      if (!cribLower && ratio < 0.85) continue;
      results.push({ key: k, score: englishScore(out) + (hasCrib ? 5 : 0), ratio: ratio, text: text, bytes: out });
    }
    results.sort(function (a, b) { return b.score - a.score; });
    return results.slice(0, top || 8);
  };

  /* ---------- hexdump, strings, magic numbers ---------- */

  D.hexdump = function (bytes, maxBytes) {
    var limit = Math.min(bytes.length, maxBytes || 2048), lines = [];
    for (var off = 0; off < limit; off += 16) {
      var hex = '', asc = '';
      for (var i = 0; i < 16; i++) {
        if (off + i < limit) {
          var b = bytes[off + i];
          hex += SK.pad(b.toString(16), 2) + ' ';
          asc += b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
        } else {
          hex += '   ';
        }
        if (i === 7) hex += ' ';
      }
      lines.push(SK.pad(off.toString(16), 8) + '  ' + hex + ' |' + asc + '|');
    }
    if (limit < bytes.length) lines.push('... ' + (bytes.length - limit) + ' more bytes not shown');
    return lines.join('\n');
  };

  // ASCII and UTF-16LE strings of at least minLen characters.
  D.strings = function (bytes, minLen) {
    minLen = minLen || 5;
    var found = [], cur = '', i;
    for (i = 0; i < bytes.length; i++) {
      var b = bytes[i];
      if (b >= 32 && b < 127) cur += String.fromCharCode(b);
      else { if (cur.length >= minLen) found.push(cur); cur = ''; }
    }
    if (cur.length >= minLen) found.push(cur);
    cur = '';
    for (i = 0; i + 1 < bytes.length; i += 2) {
      if (bytes[i] >= 32 && bytes[i] < 127 && bytes[i + 1] === 0) cur += String.fromCharCode(bytes[i]);
      else { if (cur.length >= minLen) found.push(cur); cur = ''; }
    }
    if (cur.length >= minLen) found.push(cur);
    var seen = {};
    return found.filter(function (s) { if (seen[s]) return false; seen[s] = true; return true; });
  };

  function ascii(s) { return Array.from(s).map(function (c) { return c.charCodeAt(0); }); }
  var MAGIC = [
    { name: 'Windows executable or DLL (PE, "MZ")', off: 0, sig: [0x4d, 0x5a], note: 'Check for a valid PE header; renamed executables are a common trick.' },
    { name: 'Linux/Unix executable (ELF)', off: 0, sig: [0x7f, 0x45, 0x4c, 0x46] },
    { name: 'PDF document', off: 0, sig: ascii('%PDF-'), note: 'PDFs can hold links, scripts and embedded files.' },
    { name: 'ZIP archive (also DOCX, XLSX, PPTX, JAR, APK)', off: 0, sig: [0x50, 0x4b, 0x03, 0x04], note: 'Modern Office files are ZIP containers. Rename to .zip to look inside.' },
    { name: 'Empty ZIP archive', off: 0, sig: [0x50, 0x4b, 0x05, 0x06] },
    { name: 'Legacy Office / OLE2 (DOC, XLS, PPT, MSI)', off: 0, sig: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], note: 'Old Office format; macros are possible.' },
    { name: 'RTF document', off: 0, sig: ascii('{\\rtf'), note: 'RTF is known for exploit delivery; check for embedded objects.' },
    { name: 'OneNote file', off: 0, sig: [0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d, 0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3], note: 'Can hide embedded files and scripts behind a button.' },
    { name: 'Windows shortcut (LNK)', off: 0, sig: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], note: 'Shortcuts can run commands; inspect the target and arguments.' },
    { name: 'Gzip', off: 0, sig: [0x1f, 0x8b] },
    { name: 'Zlib (deflate)', off: 0, sig: [0x78, 0x9c] },
    { name: 'Zlib (deflate, best compression)', off: 0, sig: [0x78, 0xda] },
    { name: 'Zlib (deflate, no compression)', off: 0, sig: [0x78, 0x01] },
    { name: 'Bzip2', off: 0, sig: ascii('BZh') },
    { name: '7-Zip archive', off: 0, sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
    { name: 'RAR archive', off: 0, sig: ascii('Rar!') .concat([0x1a, 0x07]) },
    { name: 'TAR archive', off: 257, sig: ascii('ustar') },
    { name: 'Windows cabinet (CAB)', off: 0, sig: ascii('MSCF') },
    { name: 'ISO disk image', off: 0x8001, sig: ascii('CD001'), note: 'ISO files mount as drives and are used to deliver malware around download warnings.' },
    { name: 'PNG image', off: 0, sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
    { name: 'JPEG image', off: 0, sig: [0xff, 0xd8, 0xff] },
    { name: 'GIF image', off: 0, sig: ascii('GIF8') },
    { name: 'BMP image', off: 0, sig: ascii('BM') },
    { name: 'WebP image', off: 8, sig: ascii('WEBP') },
    { name: 'Java class or Mach-O universal binary', off: 0, sig: [0xca, 0xfe, 0xba, 0xbe] },
    { name: 'Mach-O executable (macOS)', off: 0, sig: [0xcf, 0xfa, 0xed, 0xfe] },
    { name: 'Mach-O executable (macOS, 32-bit)', off: 0, sig: [0xce, 0xfa, 0xed, 0xfe] },
    { name: 'Android Dalvik executable (DEX)', off: 0, sig: ascii('dex\n') },
    { name: 'SQLite database', off: 0, sig: ascii('SQLite format 3') },
    { name: 'Windows event log (EVTX)', off: 0, sig: ascii('ElfFile') },
    { name: 'Windows registry hive', off: 0, sig: ascii('regf') },
    { name: 'Packet capture (PCAP)', off: 0, sig: [0xd4, 0xc3, 0xb2, 0xa1] },
    { name: 'Packet capture (PCAP, big-endian)', off: 0, sig: [0xa1, 0xb2, 0xc3, 0xd4] },
    { name: 'Packet capture (PCAPNG)', off: 0, sig: [0x0a, 0x0d, 0x0d, 0x0a] },
    { name: 'PEM text (certificate or key)', off: 0, sig: ascii('-----BEGIN') },
    { name: 'XML text', off: 0, sig: ascii('<?xml') },
    { name: 'Script with shebang line', off: 0, sig: ascii('#!') },
    { name: 'HTML text', off: 0, sig: ascii('<html'), ci: true },
    { name: 'HTML text (doctype)', off: 0, sig: ascii('<!doctype html'), ci: true }
  ];

  D.magic = function (bytes) {
    var hits = [];
    MAGIC.forEach(function (m) {
      if (bytes.length < m.off + m.sig.length) return;
      for (var i = 0; i < m.sig.length; i++) {
        var a = bytes[m.off + i], b = m.sig[i];
        if (m.ci) { a = String.fromCharCode(a).toLowerCase().charCodeAt(0); b = String.fromCharCode(b).toLowerCase().charCodeAt(0); }
        if (a !== b) return;
      }
      hits.push({ name: m.name, note: m.note || '' });
    });
    // PE detail: confirm the PE signature the header points to.
    if (bytes.length > 0x44 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
      var e = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
      if (e > 0 && e + 4 < bytes.length && bytes[e] === 0x50 && bytes[e + 1] === 0x45 && bytes[e + 2] === 0 && bytes[e + 3] === 0) {
        hits.push({ name: 'Valid PE header found', note: 'The "PE" signature is where the header says it should be.' });
      }
    }
    return hits;
  };

  /* ---------- page wiring ---------- */

  function init() {
    var input = SK.$('dec-input');
    if (!input) return;
    var workBytes = null; // set when a file is loaded

    function card(title, kind, bodyText, extra) {
      var head = SK.el('h4', {}, [title]);
      var kids = [head];
      if (bodyText != null) kids.push(SK.el('div', { className: 'kit-out', text: bodyText }));
      if (extra) kids.push(extra);
      return SK.el('div', { className: 'kit-result ' + (kind || '') }, kids);
    }

    function useAsInput(text) {
      input.value = text;
      input.focus();
      SK.toast('Moved to the input box');
    }

    function actionRow(text, bytes) {
      var row = SK.el('div', { className: 'kit-row tight' });
      row.appendChild(SK.copyButton('Copy', function () { return text; }));
      row.appendChild(SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Use as input', attrs: { type: 'button' }, on: { click: function () { useAsInput(text); } } }));
      if (bytes) {
        row.appendChild(SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Inspect bytes', attrs: { type: 'button' }, on: { click: function () { inspectBytes(bytes); } } }));
      }
      return row;
    }

    function runAll() {
      var box = SK.$('dec-results');
      SK.clear(box);
      var text = input.value;
      if (!text.trim()) {
        box.appendChild(card('Nothing to decode', 'warn', 'Paste some text first.'));
        return;
      }
      var res = D.tryAll(text.trim());
      // Hide ROT13/reverse junk unless it looks like words.
      res.sort(function (a, b) { return b.score - a.score; });
      var shown = 0;
      res.forEach(function (r) {
        var readable = r.score >= 0.9;
        // ROT13 and reversal always produce printable characters, so only show them when they yield real words.
        if ((r.id === 'rot13' || r.id === 'reverse') && !D.looksLikeWords(r.text)) return;
        shown++;
        var kind = readable ? 'good' : 'dim';
        var title = SK.el('h4', {}, [r.name, SK.el('span', { className: 'chip2 ' + (readable ? 'good' : ''), text: readable ? 'readable ' + Math.round(r.score * 100) + '%' : 'binary or noise ' + Math.round(r.score * 100) + '%' })]);
        var note = r.enc === 'UTF-16LE' ? 'Text is UTF-16LE. If this came from PowerShell -EncodedCommand, that is expected.' : '';
        var body = SK.el('div', { className: 'kit-out', text: D.displayText(r.text.length > 4000 ? r.text.slice(0, 4000) + '\n... (truncated)' : r.text) });
        var kids = [title, body];
        if (note) kids.push(SK.el('p', { className: 'kit-note', text: note }));
        var mg = D.magic(r.bytes);
        if (mg.length) kids.push(SK.el('p', { className: 'kit-note', text: 'File type guess: ' + mg.map(function (m) { return m.name; }).join('; ') }));
        kids.push(actionRow(r.text, r.bytes));
        box.appendChild(SK.el('div', { className: 'kit-result ' + kind }, kids));
      });
      var rot = SK.el('details', { className: 'kit-details' }, [
        SK.el('summary', { text: 'Caesar shifts (ROT1 to ROT25)' })
      ]);
      var lines = [];
      for (var n = 1; n < 26; n++) lines.push('ROT' + n + ': ' + D.rot(text.trim(), n).slice(0, 200));
      rot.appendChild(SK.el('div', { className: 'kit-out', text: lines.join('\n') }));
      box.appendChild(rot);
      if (!shown) box.insertBefore(card('No standard encoding detected', 'warn', 'Nothing matched Base64, hex, URL, escapes, HTML entities, binary or decimal. Try the Caesar shifts below, the XOR tool, or check whether the data is compressed.'), box.firstChild);
    }

    async function runPeel() {
      var out = SK.$('dec-peel-out');
      SK.clear(out);
      var text = input.value.trim();
      if (!text) { out.appendChild(card('Nothing to decode', 'warn', 'Paste some text first.')); return; }
      var r = await D.peel(text, 8);
      if (!r.steps.length) {
        out.appendChild(card('No layers found', 'warn', 'No convincing encoding layer was detected. Try the full decode list or the XOR tool.'));
        return;
      }
      r.steps.forEach(function (s, i) {
        var readable = (s.score !== undefined ? s.score : D.printableRatio(s.bytes)) >= 0.9;
        var shown = readable ? s.text : '(binary data, ' + s.bytes.length + ' bytes. Use "Inspect bytes".)';
        out.appendChild(SK.el('div', { className: 'kit-result good' }, [
          SK.el('h4', {}, ['Layer ' + (i + 1) + ': ', s.method]),
          SK.el('div', { className: 'kit-out', text: D.displayText(shown.length > 3000 ? shown.slice(0, 3000) + '\n... (truncated)' : shown) }),
          actionRow(s.text, s.bytes)
        ]));
      });
      var finalBytes = r.finalBytes;
      var mg = finalBytes ? D.magic(finalBytes) : [];
      if (mg.length) out.appendChild(SK.el('p', { className: 'kit-note', text: 'Final data looks like: ' + mg.map(function (m) { return m.name; }).join('; ') }));
    }

    function inspectBytes(bytes) {
      var box = SK.$('dec-inspect');
      SK.clear(box);
      var mg = D.magic(bytes);
      var kids = [SK.el('h3', { text: 'Byte inspector (' + bytes.length + ' bytes)' })];
      kids.push(SK.el('p', { className: 'kit-note', text: mg.length ? 'File type guess: ' + mg.map(function (m) { return m.name + (m.note ? ' (' + m.note + ')' : ''); }).join('; ') : 'No known file signature at the start.' }));
      kids.push(SK.el('div', { className: 'kit-out', text: D.hexdump(bytes, 1024) }));
      var strs = D.strings(bytes, 5).slice(0, 80);
      kids.push(SK.el('h3', { text: 'Readable strings' }));
      kids.push(SK.el('div', { className: 'kit-out', text: strs.length ? strs.join('\n') : 'None found.' }));
      kids.forEach(function (k) { box.appendChild(k); });
      box.hidden = false;
      box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function xorInputBytes() {
      if (workBytes) return workBytes;
      var mode = SK.$('xor-mode').value, raw = input.value;
      if (mode === 'hex') return D.fromHex(raw);
      if (mode === 'base64') return D.fromBase64(raw);
      return enc.encode(raw);
    }

    function runXor() {
      var out = SK.$('xor-out');
      SK.clear(out);
      var bytes = xorInputBytes();
      if (!bytes || !bytes.length) { out.appendChild(card('No input', 'warn', 'Put data in the input box above (or load a file) and choose how it is written.')); return; }
      var keyText = SK.$('xor-key').value.trim();
      if (keyText) {
        var key = D.fromHex(keyText) || enc.encode(keyText);
        var res = D.xorWithKey(bytes, key);
        var t = D.bytesToText(res);
        out.appendChild(card('XOR with your key (' + key.length + ' byte' + (key.length > 1 ? 's' : '') + ')', 'good', D.displayText(t.text.slice(0, 3000)), actionRow(t.text, res)));
        return;
      }
      var hits = D.xorBrute(bytes, SK.$('xor-crib').value.trim(), 8);
      if (!hits.length) { out.appendChild(card('No single-byte key produced readable output', 'warn', 'The key may be longer than one byte, or the data may be encoded another way first.')); return; }
      hits.forEach(function (h) {
        out.appendChild(SK.el('div', { className: 'kit-result good' }, [
          SK.el('h4', {}, ['Key 0x' + SK.pad(h.key.toString(16), 2) + ' (' + h.key + ')', SK.el('span', { className: 'chip2 good', text: Math.round(h.ratio * 100) + '% readable' })]),
          SK.el('div', { className: 'kit-out', text: D.displayText(h.text.slice(0, 600)) }),
          actionRow(h.text, h.bytes)
        ]));
      });
    }

    SK.$('dec-run').addEventListener('click', runAll);
    SK.$('dec-peel').addEventListener('click', runPeel);
    SK.$('xor-run').addEventListener('click', runXor);
    SK.$('dec-clear').addEventListener('click', function () {
      input.value = ''; workBytes = null;
      ['dec-results', 'dec-peel-out', 'xor-out'].forEach(function (id) { SK.clear(SK.$(id)); });
      SK.$('dec-inspect').hidden = true;
      SK.$('dec-file-name').textContent = '';
    });
    SK.$('dec-sample').addEventListener('click', function () {
      // A harmless example: Base64 of a short PowerShell-style string, UTF-16LE encoded, shown as a classic -enc blob.
      input.value = 'VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABlAGwAbABvACAAZgByAG8AbQAgAHMAZQBsAGoAYQBuAC4AbgBlAHQAJwA=';
      runAll(); runPeel();
    });
    SK.$('dec-file').addEventListener('change', async function (e) {
      var f = e.target.files[0];
      if (!f) return;
      if (f.size > 20 * 1024 * 1024) { SK.toast('That file is over 20 MB. Please use a smaller sample.'); return; }
      var buf = await SK.readFile(f);
      workBytes = new Uint8Array(buf);
      SK.$('dec-file-name').textContent = f.name + ' (' + workBytes.length + ' bytes, read locally)';
      inspectBytes(workBytes);
    });

    // Arriving from the search box: fill in and run (this tool works offline).
    var hq = SK.hashQuery();
    if (hq.q) { input.value = hq.q; runAll(); runPeel(); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
