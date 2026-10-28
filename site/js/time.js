// Timestamp converter (SK.time) plus the page wiring. Runs locally.
(function () {
  var SK = window.SK = window.SK || {};
  var T = SK.time = {};

  var FT_EPOCH_MS = 11644473600000;     // 1601-01-01 to 1970-01-01
  var NET_EPOCH_MS = 62135596800000;    // 0001-01-01 to 1970-01-01
  var COCOA_EPOCH_MS = 978307200000;    // 1970-01-01 to 2001-01-01
  var MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

  /* ---------- time zones ---------- */

  // Offset of a zone from UTC, in minutes, at a given instant.
  T.zoneOffsetMinutes = function (ms, tz) {
    if (!tz || tz === 'UTC') return 0;
    var parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).formatToParts(new Date(ms));
    var v = {};
    parts.forEach(function (p) { v[p.type] = parseInt(p.value, 10); });
    var asUtc = Date.UTC(v.year, v.month - 1, v.day, v.hour % 24, v.minute, v.second);
    return Math.round((asUtc - Math.floor(ms / 1000) * 1000) / 60000);
  };

  // Wall-clock time in a zone to a UTC instant.
  T.zonedToUtc = function (y, mo, d, h, mi, s, ms, tz) {
    var guess = Date.UTC(y, mo - 1, d, h, mi, s, ms || 0);
    if (!tz || tz === 'UTC') return guess;
    var off1 = T.zoneOffsetMinutes(guess, tz);
    var utc = guess - off1 * 60000;
    var off2 = T.zoneOffsetMinutes(utc, tz);
    if (off2 !== off1) utc = guess - off2 * 60000;
    return utc;
  };

  T.formatIn = function (ms, tz) {
    var d = new Date(ms);
    if (isNaN(d.getTime())) return 'invalid date';
    var parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz || 'UTC', hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short', timeZoneName: 'short'
    }).formatToParts(d);
    var v = {};
    parts.forEach(function (p) { v[p.type] = p.value; });
    return v.weekday + ' ' + v.year + '-' + v.month + '-' + v.day + ' ' + v.hour + ':' + v.minute + ':' + v.second + ' ' + (v.timeZoneName || '');
  };

  /* ---------- numeric interpretations ---------- */

  function plausible(ms) {
    if (!isFinite(ms)) return false;
    var y = new Date(ms).getUTCFullYear();
    return y >= 1996 && y <= 2100;
  }

  // Every way a number could be a timestamp, most plausible first.
  T.interpretNumber = function (str) {
    var s = String(str).trim();
    if (!/^-?\d+(\.\d+)?$/.test(s)) return [];
    var n = Number(s), isInt = /^-?\d+$/.test(s), big = isInt ? BigInt(s) : null;
    var list = [
      { id: 'unix_s', name: 'Unix time, seconds', ms: n * 1000 },
      { id: 'unix_ms', name: 'Unix time, milliseconds', ms: n },
      { id: 'unix_us', name: 'Unix time, microseconds', ms: n / 1000 },
      { id: 'unix_ns', name: 'Unix time, nanoseconds', ms: n / 1e6 }
    ];
    if (isInt) {
      list.push({ id: 'filetime', name: 'Windows FILETIME (100 ns since 1601)', ms: Number(big / 10000n) - FT_EPOCH_MS });
      list.push({ id: 'webkit', name: 'Chrome / WebKit time (microseconds since 1601)', ms: Number(big / 1000n) - FT_EPOCH_MS });
      list.push({ id: 'dotnet', name: '.NET ticks (100 ns since year 1)', ms: Number(big / 10000n) - NET_EPOCH_MS });
    }
    list.push({ id: 'cocoa', name: 'Apple Cocoa time (seconds since 2001)', ms: n * 1000 + COCOA_EPOCH_MS });
    list.push({ id: 'excel', name: 'Excel date serial (days since 1900)', ms: (n - 25569) * 86400000 });
    list.forEach(function (x) { x.plausible = plausible(x.ms); });
    list = list.filter(function (x) { return isFinite(x.ms) && Math.abs(x.ms) < 8.64e15; });
    list.sort(function (a, b) { return (b.plausible ? 1 : 0) - (a.plausible ? 1 : 0); });
    return list;
  };

  /* ---------- text dates ---------- */

  function tzToOffset(z) {
    if (!z) return null;
    if (/^(z|utc|gmt)$/i.test(z)) return 0;
    var m = /^([+-])(\d{2}):?(\d{2})$/.exec(z);
    if (!m) return null;
    return (m[1] === '-' ? -1 : 1) * (parseInt(m[2], 10) * 60 + parseInt(m[3], 10));
  }

  // Returns { ms, format, assumed } or null. "assumed" means no zone was in the text.
  T.parseText = function (str, assumeTz, nowMs) {
    var s = String(str).trim(), m;
    assumeTz = assumeTz || 'UTC';
    // ISO 8601 and "2026-10-27 13:55:36"
    m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i.exec(s);
    if (m) {
      var frac = m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0;
      var off = tzToOffset(m[8]);
      var y = +m[1], mo = +m[2], d = +m[3], h = +(m[4] || 0), mi = +(m[5] || 0), sec = +(m[6] || 0);
      var ms = off === null ? T.zonedToUtc(y, mo, d, h, mi, sec, frac, assumeTz) : Date.UTC(y, mo - 1, d, h, mi, sec, frac) - off * 60000;
      return { ms: ms, format: 'ISO 8601', assumed: off === null };
    }
    // Apache / CLF: 27/Oct/2026:13:55:36 -0400
    m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/.exec(s);
    if (m && MONTHS.indexOf(m[2].toLowerCase()) >= 0) {
      var o2 = tzToOffset(m[7]), mon = MONTHS.indexOf(m[2].toLowerCase()) + 1;
      var ms2 = o2 === null ? T.zonedToUtc(+m[3], mon, +m[1], +m[4], +m[5], +m[6], 0, assumeTz) : Date.UTC(+m[3], mon - 1, +m[1], +m[4], +m[5], +m[6]) - o2 * 60000;
      return { ms: ms2, format: 'Apache / common log format', assumed: o2 === null };
    }
    // RFC 2822 with a weekday: Tue, 27 Oct 2026 13:55:36 +0000
    m = /^(?:[A-Za-z]{3},?\s+)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s*(Z|UTC|GMT|[+-]\d{4})?$/.exec(s);
    if (m && MONTHS.indexOf(m[2].toLowerCase()) >= 0) {
      var o3 = tzToOffset(m[7]), mon3 = MONTHS.indexOf(m[2].toLowerCase()) + 1;
      var ms3 = o3 === null ? T.zonedToUtc(+m[3], mon3, +m[1], +m[4], +m[5], +(m[6] || 0), 0, assumeTz) : Date.UTC(+m[3], mon3 - 1, +m[1], +m[4], +m[5], +(m[6] || 0)) - o3 * 60000;
      return { ms: ms3, format: 'Email / RFC 2822', assumed: o3 === null };
    }
    // Syslog without a year: Oct 27 13:55:36
    m = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(s);
    if (m && MONTHS.indexOf(m[1].toLowerCase()) >= 0) {
      var year = new Date(nowMs || Date.now()).getUTCFullYear();
      return { ms: T.zonedToUtc(year, MONTHS.indexOf(m[1].toLowerCase()) + 1, +m[2], +m[3], +m[4], +m[5], 0, assumeTz), format: 'Syslog (no year, current year assumed)', assumed: true };
    }
    return null;
  };

  /* ---------- formats out ---------- */

  T.allFormats = function (ms) {
    var secs = Math.floor(ms / 1000);
    var ft = (BigInt(Math.round(ms)) + BigInt(FT_EPOCH_MS)) * 10000n;
    var wk = (BigInt(Math.round(ms)) + BigInt(FT_EPOCH_MS)) * 1000n;
    var ticks = (BigInt(Math.round(ms)) + BigInt(NET_EPOCH_MS)) * 10000n;
    return [
      ['ISO 8601 (UTC)', new Date(ms).toISOString()],
      ['RFC 2822 (UTC)', new Date(ms).toUTCString()],
      ['Unix seconds', String(secs)],
      ['Unix milliseconds', String(Math.round(ms))],
      ['Windows FILETIME', ft.toString()],
      ['Chrome / WebKit microseconds', wk.toString()],
      ['.NET ticks', ticks.toString()],
      ['Apple Cocoa seconds', String(secs - COCOA_EPOCH_MS / 1000)],
      ['Excel date serial', (ms / 86400000 + 25569).toFixed(6)]
    ];
  };

  T.relative = function (ms, nowMs) {
    var diff = (nowMs === undefined ? Date.now() : nowMs) - ms, past = diff >= 0;
    diff = Math.abs(diff) / 1000;
    var units = [['year', 31557600], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
    var out = [];
    for (var i = 0; i < units.length && out.length < 2; i++) {
      var q = Math.floor(diff / units[i][1]);
      if (q > 0) { out.push(q + ' ' + units[i][0] + (q > 1 ? 's' : '')); diff -= q * units[i][1]; }
    }
    if (!out.length) return 'right now';
    return out.join(' ') + (past ? ' ago' : ' from now');
  };

  T.duration = function (aMs, bMs) {
    var d = Math.abs(bMs - aMs) / 1000, secs = Math.round(d);
    var days = Math.floor(secs / 86400), h = Math.floor(secs % 86400 / 3600), m = Math.floor(secs % 3600 / 60), s = secs % 60;
    return (days ? days + ' day' + (days > 1 ? 's' : '') + ' ' : '') + SK.pad(h) + ':' + SK.pad(m) + ':' + SK.pad(s) + ' (' + secs.toLocaleString() + ' seconds)';
  };

  /* ---------- page wiring ---------- */

  function zoneList() {
    var list = [];
    try { if (Intl.supportedValuesOf) list = Intl.supportedValuesOf('timeZone'); } catch (e) { list = []; }
    if (!list.length) list = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Berlin', 'Asia/Tokyo', 'Australia/Sydney'];
    return ['UTC'].concat(list.filter(function (z) { return z !== 'UTC'; }));
  }

  function init() {
    var input = SK.$('time-in');
    if (!input) return;
    var zones = zoneList(), local = 'UTC';
    try { local = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch (e) { local = 'UTC'; }
    ['time-assume', 'time-show'].forEach(function (id) {
      var sel = SK.$(id);
      zones.forEach(function (z) { sel.appendChild(SK.el('option', { text: z, attrs: { value: z } })); });
    });
    SK.$('time-assume').value = 'UTC';
    SK.$('time-show').value = zones.indexOf(local) >= 0 ? local : 'UTC';

    function interpret(str) {
      var assume = SK.$('time-assume').value, found = [];
      T.interpretNumber(str).forEach(function (x) { found.push({ name: x.name, ms: x.ms, plausible: x.plausible, note: '' }); });
      var txt = T.parseText(str, assume);
      if (txt) found.unshift({ name: txt.format, ms: txt.ms, plausible: true, note: txt.assumed ? 'No time zone in the text, so ' + assume + ' was assumed. Change the setting above if that is wrong.' : '' });
      if (!found.length && str.trim()) {
        var p = Date.parse(str);
        if (!isNaN(p)) found.push({ name: 'Browser date parser', ms: p, plausible: true, note: 'Parsed by the browser. If there was no zone in the text, your computer\'s zone was used.' });
      }
      return found;
    }

    function render() {
      var box = SK.$('time-out');
      SK.clear(box);
      var str = input.value.trim();
      if (!str) return;
      var found = interpret(str), show = SK.$('time-show').value;
      if (!found.length) {
        box.appendChild(SK.el('div', { className: 'kit-callout warn' }, [SK.el('p', { text: 'That does not look like a timestamp I know. Try a number (Unix, FILETIME, WebKit, ...) or text such as 2026-10-27 13:55:36 or 27/Oct/2026:13:55:36 -0400.' })]));
        return;
      }
      function makeCard(f) {
        var valid = isFinite(f.ms) && !isNaN(new Date(f.ms).getTime());
        var kind = f.plausible ? 'good' : 'dim';
        var kids = [SK.el('h4', {}, [f.name, SK.el('span', { className: 'chip2 ' + (f.plausible ? 'good' : ''), text: f.plausible ? 'plausible' : 'unlikely year' })])];
        if (valid) {
          kids.push(SK.el('div', { className: 'kit-out', text: 'UTC:   ' + new Date(f.ms).toISOString() + '\n' + show + ':   ' + T.formatIn(f.ms, show) + '\nRelative: ' + T.relative(f.ms) }));
          if (f.note) kids.push(SK.el('p', { className: 'kit-note', text: f.note }));
          kids.push(SK.el('div', { className: 'kit-row tight' }, [
            SK.copyButton('Copy ISO', function () { return new Date(f.ms).toISOString(); }),
            SK.el('button', { className: 'btn btn-small btn-ghost', text: 'Show in all formats', attrs: { type: 'button' }, on: { click: function () { showAll(f.ms); } } })
          ]));
        }
        return SK.el('div', { className: 'kit-result ' + kind }, kids);
      }
      var likely = found.filter(function (f) { return f.plausible; }), unlikely = found.filter(function (f) { return !f.plausible; });
      likely.forEach(function (f) { box.appendChild(makeCard(f)); });
      if (unlikely.length) {
        var more = SK.el('details', { className: 'kit-details', attrs: likely.length ? {} : { open: '' } }, [
          SK.el('summary', { text: (likely.length ? 'Other readings with unlikely years (' : 'Readings, all with unlikely years (') + unlikely.length + ')' })
        ]);
        unlikely.forEach(function (f) { more.appendChild(makeCard(f)); });
        box.appendChild(more);
      }
      if (found[0].plausible) showAll(found[0].ms);
    }

    function showAll(ms) {
      var t = SK.el('table', { className: 'kit-table' });
      T.allFormats(ms).forEach(function (r) {
        t.appendChild(SK.el('tr', {}, [SK.el('th', { text: r[0] }), SK.el('td', { className: 'mono', text: r[1] })]));
      });
      var box = SK.$('time-all');
      SK.clear(box);
      box.appendChild(SK.el('h3', { text: 'The same moment in every format' }));
      box.appendChild(SK.el('div', { className: 'kit-table-wrap' }, [t]));
      box.hidden = false;
    }

    input.addEventListener('input', render);
    SK.$('time-assume').addEventListener('change', render);
    SK.$('time-show').addEventListener('change', render);
    SK.$('time-now').addEventListener('click', function () { input.value = new Date().toISOString(); render(); });

    function diff() {
      var out = SK.$('diff-out');
      SK.clear(out);
      var a = interpret(SK.$('diff-a').value.trim())[0], b = interpret(SK.$('diff-b').value.trim())[0];
      if (!a || !b) { out.appendChild(SK.el('div', { className: 'kit-callout warn' }, [SK.el('p', { text: 'Enter two timestamps in any format above.' })])); return; }
      out.appendChild(SK.el('div', { className: 'kit-out', text: 'A: ' + new Date(a.ms).toISOString() + '\nB: ' + new Date(b.ms).toISOString() + '\n\nDifference: ' + T.duration(a.ms, b.ms) + (b.ms >= a.ms ? '  (B is later)' : '  (A is later)') }));
    }
    SK.$('diff-run').addEventListener('click', diff);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
