// Hash identifier, local hashing and file-type check (SK.hash) plus the page wiring. Files never leave the browser.
(function () {
  var SK = window.SK = window.SK || {};
  var H = SK.hash = {};

  /* ---------- MD5 (WebCrypto does not offer it) ---------- */

  var MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  var MD5_K = (function () {
    var k = new Uint32Array(64);
    for (var i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    return k;
  })();

  function toHexLE(w) {
    var s = '';
    for (var i = 0; i < 4; i++) s += SK.pad(((w >>> (i * 8)) & 255).toString(16), 2);
    return s;
  }

  H.md5 = function (bytes) {
    var len = bytes.length;
    var padLen = Math.floor((len + 8) / 64) * 64 + 64;
    var buf = new Uint8Array(padLen);
    buf.set(bytes);
    buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, (len * 8) >>> 0, true);
    dv.setUint32(padLen - 4, Math.floor(len / 536870912), true);
    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    var M = new Uint32Array(16);
    for (var off = 0; off < padLen; off += 64) {
      for (var j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
      var A = a0, B = b0, C = c0, D = d0;
      for (var i = 0; i < 64; i++) {
        var F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + MD5_K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + (((F << MD5_S[i]) | (F >>> (32 - MD5_S[i]))) >>> 0)) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    return toHexLE(a0) + toHexLE(b0) + toHexLE(c0) + toHexLE(d0);
  };

  H.crc32 = function (bytes) {
    var table = H._crcTable;
    if (!table) {
      table = H._crcTable = new Uint32Array(256);
      for (var n = 0; n < 256; n++) {
        var c = n;
        for (var k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        table[n] = c >>> 0;
      }
    }
    var crc = 0xffffffff;
    for (var i = 0; i < bytes.length; i++) crc = table[(crc ^ bytes[i]) & 255] ^ (crc >>> 8);
    return SK.pad(((crc ^ 0xffffffff) >>> 0).toString(16), 8);
  };

  function bufToHex(buf) {
    var b = new Uint8Array(buf), s = '';
    for (var i = 0; i < b.length; i++) s += SK.pad(b[i].toString(16), 2);
    return s;
  }

  // Returns { md5, sha1, sha256, sha512, crc32 } as hex strings.
  H.digestAll = async function (bytes) {
    var out = { md5: H.md5(bytes), crc32: H.crc32(bytes) };
    var subtle = window.crypto && window.crypto.subtle;
    if (subtle) {
      out.sha1 = bufToHex(await subtle.digest('SHA-1', bytes));
      out.sha256 = bufToHex(await subtle.digest('SHA-256', bytes));
      out.sha512 = bufToHex(await subtle.digest('SHA-512', bytes));
    }
    return out;
  };

  /* ---------- identify a hash string ---------- */

  var HEX_LENGTHS = {
    8: [['CRC-32 or Adler-32', 'checksum', 'A checksum for catching errors, not for security.']],
    16: [['MySQL 3.x password hash', 'password', 'Very old and weak.'], ['Half of an MD5 or a 64-bit hash', 'other', '']],
    32: [['MD5', 'file', 'Common for file hashes in threat reports. Collisions are easy to create, so do not rely on it alone.'],
      ['NTLM (Windows password hash)', 'password', 'Same length as MD5. Context decides: a 32-character value from a memory dump or SAM file is NTLM.'],
      ['MD4 or LM', 'password', 'Legacy Windows hashes.']],
    40: [['SHA-1', 'file', 'Still common for file hashes. Considered weak against deliberate collisions.'], ['RIPEMD-160', 'other', '']],
    56: [['SHA-224 or SHA3-224', 'file', '']],
    64: [['SHA-256', 'file', 'The usual choice for file hashes and for lookups on VirusTotal and similar services.'],
      ['SHA3-256, BLAKE2s or Keccak-256', 'other', '']],
    96: [['SHA-384 or SHA3-384', 'file', '']],
    128: [['SHA-512 or SHA3-512', 'file', ''], ['Whirlpool or BLAKE2b-512', 'other', '']]
  };

  H.identify = function (input) {
    var s = String(input).trim(), out = [], m;
    if (!s) return out;
    function add(name, kind, note) { out.push({ name: name, kind: kind, note: note || '' }); }
    if (/^\$2[abxy]?\$\d{2}\$[.\/A-Za-z0-9]{53}$/.test(s)) add('bcrypt', 'password', 'Slow, salted password hash. Good practice.');
    else if (/^\$argon2(id|i|d)\$/.test(s)) add('Argon2', 'password', 'Modern password hash. Good practice.');
    else if (/^\$y\$/.test(s)) add('yescrypt', 'password', 'Modern Linux password hash.');
    else if (/^\$6\$/.test(s)) add('SHA-512 crypt ($6$)', 'password', 'Salted Linux password hash from /etc/shadow.');
    else if (/^\$5\$/.test(s)) add('SHA-256 crypt ($5$)', 'password', 'Salted Linux password hash from /etc/shadow.');
    else if (/^\$1\$/.test(s)) add('MD5 crypt ($1$)', 'password', 'Old Linux password hash. Weak by today\'s standards.');
    else if (/^\$apr1\$/.test(s)) add('Apache MD5 (apr1)', 'password', 'Used in .htpasswd files.');
    else if (/^\$[PH]\$/.test(s)) add('phpass (WordPress and others)', 'password', 'Common in PHP web apps.');
    else if (/^\{S?SHA\}/i.test(s)) add('LDAP SHA / salted SHA', 'password', 'Directory service password format.');
    else if (/^\$krb5tgs\$/.test(s)) add('Kerberos service ticket (TGS-REP)', 'ticket', 'Seen in Kerberoasting investigations. Treat as sensitive.');
    else if (/^\$krb5asrep\$/.test(s)) add('Kerberos AS-REP', 'ticket', 'Seen in AS-REP roasting investigations. Treat as sensitive.');
    else if ((m = /^([^:\s]+)::([^:\s]*):([0-9a-fA-F]{16}):([0-9a-fA-F]{32}):([0-9a-fA-F]+)$/.exec(s))) add('NetNTLMv2 challenge and response', 'ticket', 'Captured from network authentication (for example by Responder-style poisoning). Treat as sensitive.');
    else if (/^[0-9a-fA-F]+$/.test(s) && HEX_LENGTHS[s.length]) {
      HEX_LENGTHS[s.length].forEach(function (h) { add(h[0], h[1], h[2]); });
    } else if (/^[0-9a-fA-F]+$/.test(s)) {
      add('Hex string of ' + s.length + ' characters', 'other', 'This length does not match a common hash.');
    } else {
      add('No known hash format', 'other', 'Not a plain hex digest and not a recognised password-hash prefix.');
    }
    return out;
  };

  /* ---------- file type vs extension ---------- */

  var EXT_EXPECT = {
    exe: 'PE', dll: 'PE', sys: 'PE', scr: 'PE', pdf: 'PDF',
    docx: 'ZIP', xlsx: 'ZIP', pptx: 'ZIP', jar: 'ZIP', apk: 'ZIP', zip: 'ZIP',
    doc: 'OLE2', xls: 'OLE2', ppt: 'OLE2', msi: 'OLE2',
    png: 'PNG', jpg: 'JPEG', jpeg: 'JPEG', gif: 'GIF', rtf: 'RTF', lnk: 'LNK', one: 'OneNote',
    gz: 'Gzip', '7z': '7-Zip', rar: 'RAR', iso: 'ISO'
  };

  H.extensionCheck = function (fileName, magicHits) {
    var m = /\.([A-Za-z0-9]+)$/.exec(fileName || '');
    if (!m) return null;
    var ext = m[1].toLowerCase(), expect = EXT_EXPECT[ext];
    if (!expect) return null;
    var names = magicHits.map(function (h) { return h.name; }).join(' | ');
    if (!names) return { ok: false, text: 'The extension is .' + ext + ', but no known file signature was found at the start of the file.' };
    var ok = names.toLowerCase().indexOf(expect.toLowerCase()) >= 0;
    return ok ? { ok: true, text: 'The extension .' + ext + ' matches the file contents.' }
      : { ok: false, text: 'The extension is .' + ext + ', but the contents look like: ' + names + '. A mismatch can mean a renamed file; look closer.' };
  };

  /* ---------- page wiring ---------- */

  function init() {
    if (!SK.$('hash-id-in')) return;

    function callout(text, kind) { return SK.el('div', { className: 'kit-callout ' + (kind || 'warn') }, [SK.el('p', { text: text })]); }

    // Identify
    SK.$('hash-id-run').addEventListener('click', function () {
      var box = SK.$('hash-id-out');
      SK.clear(box);
      var res = H.identify(SK.$('hash-id-in').value);
      if (!res.length) { box.appendChild(callout('Paste a hash first.')); return; }
      var results = SK.el('div', { className: 'kit-results' });
      res.forEach(function (r) {
        results.appendChild(SK.el('div', { className: 'kit-result' }, [
          SK.el('h4', {}, [r.name, SK.el('span', { className: 'chip2', text: r.kind })]),
          r.note ? SK.el('p', { className: 'kit-note', text: r.note }) : null
        ]));
      });
      box.appendChild(results);
      box.appendChild(SK.el('p', { className: 'kit-note', text: 'Length and format only narrow it down. Where the hash came from tells you the rest.' }));
    });

    // Compute for text or file
    var currentFile = null;
    function showDigests(bytes, label, fileName) {
      var box = SK.$('hash-out');
      SK.clear(box);
      H.digestAll(bytes).then(function (d) {
        var expected = SK.$('hash-expect').value.trim().toLowerCase();
        var t = SK.el('table', { className: 'kit-table' });
        var matched = false;
        [['MD5', 'md5'], ['SHA-1', 'sha1'], ['SHA-256', 'sha256'], ['SHA-512', 'sha512'], ['CRC-32', 'crc32']].forEach(function (p) {
          if (!d[p[1]]) return;
          var isMatch = expected && d[p[1]] === expected;
          if (isMatch) matched = p[0];
          t.appendChild(SK.el('tr', {}, [SK.el('th', { text: p[0] }), SK.el('td', { className: 'mono', text: d[p[1]] }),
            SK.el('td', {}, [SK.copyButton('Copy', function () { return d[p[1]]; })])].concat(isMatch ? [] : [])));
        });
        box.appendChild(SK.el('p', { className: 'kit-note', text: label + ' (' + bytes.length.toLocaleString() + ' bytes)' }));
        box.appendChild(SK.el('div', { className: 'kit-table-wrap' }, [t]));
        if (expected) box.appendChild(callout(matched ? 'Match: the expected hash equals the ' + matched + ' of this ' + (fileName ? 'file' : 'text') + '.' : 'No match: the expected hash does not equal any hash computed here.', matched ? 'good' : 'bad'));
        if (fileName) {
          var mg = SK.decode ? SK.decode.magic(bytes.subarray(0, 40000)) : [];
          var ec = H.extensionCheck(fileName, mg);
          box.appendChild(SK.el('h3', { text: 'File type check' }));
          box.appendChild(SK.el('p', { text: mg.length ? 'Looks like: ' + mg.map(function (m) { return m.name; }).join('; ') : 'No known file signature at the start of the file.' }));
          mg.forEach(function (m) { if (m.note) box.appendChild(SK.el('p', { className: 'kit-note', text: m.note })); });
          if (ec) box.appendChild(callout(ec.text, ec.ok ? 'good' : 'warn'));
        }
      });
    }

    SK.$('hash-text-run').addEventListener('click', function () {
      currentFile = null;
      SK.$('hash-file-name').textContent = '';
      showDigests(new TextEncoder().encode(SK.$('hash-text').value), 'Text hashed as UTF-8', null);
    });
    SK.$('hash-file').addEventListener('change', async function (e) {
      var f = e.target.files[0];
      if (!f) return;
      if (f.size > 256 * 1024 * 1024) { SK.toast('That file is over 256 MB. Hash it with a local command-line tool instead.'); return; }
      currentFile = f;
      SK.$('hash-file-name').textContent = f.name + ' (read locally, never uploaded)';
      var buf = await SK.readFile(f);
      showDigests(new Uint8Array(buf), 'File ' + f.name, f.name);
    });
    SK.$('hash-expect').addEventListener('input', function () {
      if (SK.$('hash-out').firstChild) {
        if (currentFile) { SK.readFile(currentFile).then(function (b) { showDigests(new Uint8Array(b), 'File ' + currentFile.name, currentFile.name); }); }
        else SK.$('hash-text-run').click();
      }
    });

    // Arriving from the search box: identify a hash, or hash the text (these tools work offline).
    var hq = SK.hashQuery();
    if (hq.q) {
      if (hq.k === 'hash') { SK.$('hash-id-in').value = hq.q; SK.$('hash-id-run').click(); }
      else { SK.$('hash-text').value = hq.q; SK.$('hash-text-run').click(); }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
