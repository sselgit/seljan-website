// Shows the MITRE ATT&CK suggestions from attack-map.js as a panel. Suggestions are keyword matches on the rule, to be reviewed.
(function () {
  var SK = window.SK = window.SK || {};

  // text: what to read (rule name, rule body, alert). opts: { classtype }. Returns an element, or null when nothing matched.
  SK.attackPanel = function (text, opts) {
    var list = SK.attack ? SK.attack.suggest(text, opts) : [];
    var box = SK.el('div', { className: 'kit-panel' }, [SK.el('h2', { text: 'MITRE ATT&CK techniques this rule probably maps to' })]);
    if (!list.length) {
      box.appendChild(SK.el('p', { className: 'sub', text: 'Nothing in the rule name or contents points clearly to a technique. Read what the rule detects and pick one yourself; the ATT&CK site lets you search by behavior.' }));
      return box;
    }
    box.appendChild(SK.el('p', { className: 'sub', text: 'Suggested from the words in the rule name, its contents and the alert. These are starting points for your rule metadata or tags. Confirm each against what the rule really detects before you use it.' }));
    var t = SK.el('table', { className: 'kit-table' }, [SK.el('tr', {}, ['Technique', 'Tactic', 'Why', 'Fit'].map(function (h) { return SK.el('th', { text: h }); }))]);
    list.forEach(function (s) {
      var link = SK.el('a', { text: s.id, attrs: { href: s.url, target: '_blank', rel: 'noopener noreferrer' } });
      t.appendChild(SK.el('tr', {}, [
        SK.el('td', {}, [link, ' ' + s.name + (s.oldId ? ' (before ATT&CK v20: ' + s.oldId + ')' : '')]),
        SK.el('td', { text: s.tactics.join(', ') }),
        SK.el('td', { text: s.why.join('; ') }),
        SK.el('td', {}, [SK.el('span', { className: 'chip2 ' + (s.confidence === 'good match' ? 'good' : (s.confidence === 'possible match' ? 'warn' : '')), text: s.confidence })])
      ]));
    });
    box.appendChild(SK.el('div', { className: 'kit-table-wrap' }, [t]));
    box.appendChild(SK.el('p', { className: 'kit-note', text: 'Technique names and IDs are from MITRE ATT&CK Enterprise v20. Links open attack.mitre.org in a new tab; nothing from this page is sent there.' }));
    return box;
  };
})();
