// Phishing triage guide (SK.triage): structured questions, a rough score, response steps and a ticket note.
// This is a thinking aid, not a verdict. Nothing is stored or sent.
(function () {
  var SK = window.SK = window.SK || {};
  var Tr = SK.triage = {};

  Tr.QUESTIONS = [
    { group: 'Sender', id: 's1', w: 2, text: 'The sender\'s address does not match who they claim to be (for example a "Microsoft" display name on a free-mail address, or a lookalike domain).' },
    { group: 'Sender', id: 's2', w: 2, text: 'The Reply-To address is different from the From address.' },
    { group: 'Sender', id: 's3', w: 2, text: 'Email authentication failed or is missing (SPF, DKIM or DMARC in the Authentication-Results header).', help: 'In the raw message headers look for "Authentication-Results". A pass does not prove an email is safe, but a fail on a message that claims to be from a big brand is a strong signal.' },
    { group: 'Sender', id: 's4', w: 1, text: 'You have never received mail from this sender before.' },
    { group: 'Content', id: 'c1', w: 1, text: 'It creates urgency or fear, or offers a reward ("your account will be closed", "act now").' },
    { group: 'Content', id: 'c2', w: 3, text: 'It asks for a password, a sign-in code, payment, gift cards, or a change to bank details.' },
    { group: 'Content', id: 'c3', w: 1, text: 'It is unexpected: it does not match anything the recipient asked for or a known business process.' },
    { group: 'Content', id: 'c4', w: 1, text: 'The greeting is generic or the wording or formatting looks off.' },
    { group: 'Links', id: 'l1', w: 3, text: 'A link\'s visible text does not match where it really goes (hover over it, or look at the HTML).' },
    { group: 'Links', id: 'l2', w: 3, text: 'A link goes to a lookalike domain (a typo, extra words, or an unusual ending).' },
    { group: 'Links', id: 'l3', w: 2, text: 'Links use a shortener or redirect, or the message pushes you to scan a QR code or open a shared file.' },
    { group: 'Attachments', id: 'a1', w: 3, text: 'The attachment is a risky type (HTML, ISO, IMG, LNK, ONE, JS, VBS, or a macro-enabled Office file), or it asks you to enable macros or enter a password.' },
    { group: 'Attachments', id: 'a2', w: 4, text: 'The attachment or link was flagged by a sandbox or a reputation service.' }
  ];

  Tr.IMPACT = [
    { id: 'i1', text: 'The recipient clicked a link.' },
    { id: 'i2', text: 'The recipient entered a password or sign-in code on a page.' },
    { id: 'i3', text: 'The recipient opened or ran an attachment.' },
    { id: 'i4', text: 'More than one person received the same message.' }
  ];

  // answers: { id: 'yes' | 'no' | 'unsure' }
  Tr.score = function (answers) {
    var total = 0;
    Tr.QUESTIONS.forEach(function (q) {
      var a = answers[q.id];
      if (a === 'yes') total += q.w;
      else if (a === 'unsure') total += q.w * 0.5;
    });
    var verdict, level;
    var forced = answers.a2 === 'yes' || (answers.c2 === 'yes' && (answers.s1 === 'yes' || answers.l2 === 'yes'));
    if (forced || total >= 8) { verdict = 'Likely phishing'; level = 'bad'; }
    else if (total >= 4) { verdict = 'Suspicious: investigate further'; level = 'warn'; }
    else { verdict = 'Low suspicion, but verify before trusting'; level = 'good'; }
    return { total: total, verdict: verdict, level: level, forced: forced };
  };

  Tr.actions = function (answers, result) {
    var out = [];
    var clicked = answers.i1 === 'yes', creds = answers.i2 === 'yes', opened = answers.i3 === 'yes', many = answers.i4 === 'yes';
    if (result.level === 'bad' || result.level === 'warn') {
      out.push('Do not interact with the message further. Keep the original (as an attachment, with headers) for evidence.');
      out.push('Report it through your mail system\'s phishing report function, or to your security team.');
      out.push('Block the sender address and the sending domain, and block any linked domains and URLs at the web filter or DNS.');
    }
    if (many || result.level === 'bad') out.push('Search all mailboxes for the same sender, subject and links, then remove matching messages.');
    if (clicked || creds || opened) {
      out.push('Treat the recipient\'s device and account as possibly affected until you have checked them.');
    }
    if (creds) {
      out.push('Reset the account password and revoke active sessions and tokens now. Check multi-factor methods for anything new.');
      out.push('Check the mailbox for new forwarding or inbox rules, and sign-in logs for unfamiliar places or devices.');
    }
    if (opened) {
      out.push('Isolate the device if you can, and run an endpoint scan. Look for new processes started from the attachment (for example a script or shell launched by an Office program).');
    }
    if (clicked && !creds && !opened) out.push('Check proxy or DNS logs for what the link loaded, and ask the recipient what appeared on screen.');
    if (result.level === 'good') {
      out.push('Confirm with the sender through a different channel (a phone number you already know) before acting on any request.');
      out.push('Record why you judged it low risk so a colleague can check your reasoning.');
    }
    out.push('Tell the person who reported it what you decided. Thank them: reporting is the behavior you want.');
    return out;
  };

  Tr.note = function (answers, result, actions, extra) {
    var lines = [];
    lines.push('Phishing triage note');
    lines.push('Generated (UTC): ' + new Date().toISOString());
    if (extra && extra.ref) lines.push('Reference: ' + extra.ref);
    lines.push('Assessment: ' + result.verdict + ' (score ' + result.total + ')');
    lines.push('', 'Signals observed:');
    var any = false;
    Tr.QUESTIONS.forEach(function (q) {
      var a = answers[q.id];
      if (a === 'yes' || a === 'unsure') { lines.push('- [' + (a === 'yes' ? 'yes' : 'unsure') + '] ' + q.text); any = true; }
    });
    if (!any) lines.push('- None selected');
    lines.push('', 'Impact:');
    var impact = false;
    Tr.IMPACT.forEach(function (q) {
      if (answers[q.id] === 'yes') { lines.push('- ' + q.text); impact = true; }
    });
    if (!impact) lines.push('- None reported');
    lines.push('', 'Recommended actions:');
    actions.forEach(function (a) { lines.push('- ' + a); });
    if (extra && extra.notes) lines.push('', 'Analyst notes:', extra.notes);
    lines.push('', 'This note is a structured guide, not a final verdict.');
    return lines.join('\n');
  };

  function init() {
    var host = SK.$('tri-questions');
    if (!host) return;
    var answers = {};

    function radioGroup(q) {
      var wrap = SK.el('fieldset', { className: 'kit-result'});
      wrap.appendChild(SK.el('legend', { className: 'kit-label', text: q.text }));
      if (q.help) wrap.appendChild(SK.el('p', { className: 'kit-note', text: q.help }));
      var row = SK.el('div', { className: 'kit-row tight' });
      [['yes', 'Yes'], ['no', 'No'], ['unsure', 'Not sure']].forEach(function (o) {
        var id = 'tri-' + q.id + '-' + o[0];
        var input = SK.el('input', { attrs: { type: 'radio', name: 'tri-' + q.id, id: id, value: o[0] } });
        input.addEventListener('change', function () { answers[q.id] = o[0]; update(); });
        row.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': id } }, [input, o[1]]));
      });
      wrap.appendChild(row);
      return wrap;
    }

    var lastGroup = '';
    Tr.QUESTIONS.forEach(function (q) {
      if (q.group !== lastGroup) { host.appendChild(SK.el('h3', { text: q.group })); lastGroup = q.group; }
      host.appendChild(radioGroup(q));
    });
    var imp = SK.$('tri-impact');
    Tr.IMPACT.forEach(function (q) {
      var input = SK.el('input', { attrs: { type: 'checkbox', id: 'tri-' + q.id } });
      input.addEventListener('change', function () { answers[q.id] = input.checked ? 'yes' : 'no'; update(); });
      imp.appendChild(SK.el('label', { className: 'kit-check', attrs: { 'for': 'tri-' + q.id } }, [input, q.text]));
    });

    function update() {
      var box = SK.$('tri-result');
      SK.clear(box);
      if (!Object.keys(answers).length) {
        box.appendChild(SK.el('div', { className: 'kit-callout' }, [SK.el('p', { text: 'Answer the questions above and the result will appear here.' })]));
        SK.$('tri-note').value = '';
        return;
      }
      var result = Tr.score(answers), actions = Tr.actions(answers, result);
      box.appendChild(SK.el('div', { className: 'kit-callout ' + result.level }, [
        SK.el('p', {}, [SK.el('strong', { text: result.verdict }), ' (score ' + result.total + ')']),
        result.forced ? SK.el('p', { text: 'A high-risk combination was selected, which sets this result on its own.' }) : null
      ]));
      var ul = SK.el('ul');
      actions.forEach(function (a) { ul.appendChild(SK.el('li', { text: a })); });
      box.appendChild(SK.el('h3', { text: 'Suggested next steps' }));
      box.appendChild(ul);
      SK.$('tri-note').value = Tr.note(answers, result, actions, { ref: SK.$('tri-ref').value.trim(), notes: SK.$('tri-extra').value.trim() });
    }
    SK.$('tri-ref').addEventListener('input', update);
    SK.$('tri-extra').addEventListener('input', update);
    SK.$('tri-copy').addEventListener('click', function () { SK.copyText(SK.$('tri-note').value); });
    SK.$('tri-reset').addEventListener('click', function () {
      answers = {};
      Array.prototype.forEach.call(document.querySelectorAll('#tri-questions input, #tri-impact input'), function (i) { i.checked = false; });
      SK.$('tri-ref').value = ''; SK.$('tri-extra').value = '';
      update();
    });
    update();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
