// MAC address vendor lookup. The IEEE list is a static file served with the site, so no lookup leaves the browser.
(function () {
  var SK = window.SK = window.SK || {};
  if (!SK.nl || !SK.lu) return;
  var NL = SK.nl, LU = SK.lu;
  var dbPromise = null;

  function loadDb() {
    if (!dbPromise) {
      dbPromise = NL.request('data/oui.json', { timeout: 30000 }).then(function (res) {
        if (!res.json || !res.json.v) throw new Error('The vendor list did not load.');
        return res.json;
      });
      dbPromise.then(null, function () { dbPromise = null; });
    }
    return dbPromise;
  }

  function init() {
    if (!SK.$('mac-in')) return;
    var out = SK.$('mac-out');
    LU.start({ multiline: true, offline: true, input: 'mac-in', button: 'mac-run', out: 'mac-out', run: function (raw) {
      SK.clear(out);
      var tokens = String(raw).split(/[\s,;]+/).filter(Boolean).slice(0, 200);
      if (!tokens.length) { out.appendChild(LU.callout('warn', ['Enter one or more MAC addresses.'])); return; }
      LU.working(out, 'Loading the vendor list…');
      return loadDb().then(function (db) {
        SK.clear(out);
        var rows = tokens.map(function (tk) {
          var m = NL.parseMac(tk);
          if (!m) return [tk, '', 'Not a valid MAC address', '', ''];
          var f = NL.macFlags(m.hex), hit = NL.lookupOui(db, m.hex), notes = [];
          if (f.broadcast) notes.push('Broadcast address (every device on the network).');
          else if (f.multicast) notes.push('Group (multicast) address, not a single device.');
          if (f.localAdmin && !f.broadcast) notes.push('Locally administered: usually a randomized private Wi-Fi address (phones and PCs) or a virtual machine or container. It has no vendor.');
          if (!m.full) notes.push('Prefix only.');
          var fmt = m.full ? NL.formatMac(m.hex) : null;
          var vendor = hit ? hit.vendor : (f.localAdmin || f.multicast ? '' : 'Not in the IEEE public list (unassigned or privately registered)');
          return [tk, fmt ? fmt.colon : m.hex, vendor, hit ? hit.registry : '', notes.join(' ') + (fmt ? ' Formats: ' + fmt.hyphen + ' | ' + fmt.dotted : '')];
        });
        out.appendChild(LU.table(['Input', 'Normalized', 'Vendor', 'Block', 'Notes'], rows, [0, 1]));
        out.appendChild(SK.el('p', { className: 'kit-note', text: 'Vendor data: ' + db.source + ', as of ' + db.updated + '. A vendor name tells you who registered the address block, not what the device is. Cloned and spoofed addresses look identical.' }));
      });
    } });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
