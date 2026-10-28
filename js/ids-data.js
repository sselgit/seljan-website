// Teaching content and example captures for the Snort/Suricata tuner. The example captures are built in the
// page when you press a button (nothing is downloaded), using the same capture builder the tests use.
(function () {
  var SK = window.SK = window.SK || {};

  var CHECKS = [
    'I searched our historical network data (or a longer capture) for this alert and know what normally causes it.',
    'I know which host, application or team owns the traffic that was matched, and they confirmed it is expected.',
    'I checked that an attacker could not keep the attack working by changing a few bytes, a port or a header (a tuned rule is easy to dodge if it is too narrow in the wrong place).',
    'I will test the new rule with the engine on both captures (it should stay quiet on the false positive and still alert on the real activity).',
    'The change has an owner and a review date.'
  ];

  var ABNORMAL = [
    ['Outbound connections at fixed intervals (every 60 seconds, for example) to one rare address', 'Regular timing is what malware check-ins look like (beaconing). People and browsers are not that regular.'],
    ['DNS queries with very long or random-looking names, or lots of TXT answers', 'Can be data being smuggled out through DNS (tunneling).'],
    ['A web server or database server starting outbound connections to the internet', 'Servers normally only answer. A new outbound connection from one may be a reverse shell or a download of a second stage.'],
    ['HTTP to an IP address with no host name, an odd User-Agent, or a request that looks like a command ("cmd=", "exec=")', 'Real sites use names. Tools and malware often skip them.'],
    ['Large uploads out of the network at night to a place nobody can explain', 'Possible data theft. Compare with backup and sync schedules first.'],
    ['SMB, RDP or WinRM from a workstation to many other workstations', 'Spreading from machine to machine (lateral movement) looks like this.'],
    ['One host trying many ports or many hosts quickly', 'Scanning. Expected from your own vulnerability scanner, concerning from anything else.'],
    ['Traffic on a well-known port that is not that protocol (TLS on port 53, SSH on port 80)', 'Hides traffic inside ports that are usually allowed.']
  ];

  var ROUTINE = [
    ['Your own vulnerability scanner or monitoring tool trips web-attack rules', 'Limit the rule by source address (suppress for the scanner), keep it for everyone else, and put an end date on it.'],
    ['A web application whose normal pages contain the attack-looking text', 'Move the content into the right HTTP buffer and anchor it (this tuner proposes that). Do not just delete the rule.'],
    ['A backup, update or sync service sends large or odd-looking transfers', 'Tie the exclusion to the exact server pair and port, not to the whole subnet.'],
    ['An internal tool sends a command word your rule treats as an exploit', 'Anchor the content (offset, depth, distance, within) so only the exploit layout matches.'],
    ['A rule that fires many times for one event (thousands of alerts, one host)', 'A rate limit keeps the first alert and drops repeats without blinding the rule.']
  ];

  var HISTORICAL = [
    'Search the last 30 to 90 days of alerts for this rule ID. Is it new, or has it always fired? Note the hosts and times.',
    'Pick a few alerts and open the full packet capture. Read the traffic as a person. What is the client asking for and why?',
    'Look at what else the same source and destination did around the same time (DNS, other alerts, firewall logs).',
    'Ask the owner of the server or application. If nobody can explain it, do not tune it, investigate it.',
    'If it is genuinely expected, choose the narrowest change that stops it: a buffer, an anchor and a window before a suppression, and a suppression before disabling the rule.',
    'Test on a real capture of the false positive (should be silent) and on a capture of the real attack (should still alert). Keep both captures with the change record.',
    'Set a review date. Applications change, and a tuned rule can quietly stop catching what it was written for.'
  ];

  // What the position words mean, with the engine differences that trip people up.
  var CHEATSHEET = [
    ['offset N', 'Start looking N bytes into the buffer. Counts from byte 0 of the buffer, not from the previous match.', 'All engines.'],
    ['depth N', 'Only look at N bytes, counting from the offset (or byte 0 if there is no offset). The match must end within them.', 'Snort 2 and 3 measure depth from the offset too. A depth smaller than the content can never match.'],
    ['distance N', 'Start N bytes after the end of the previous match. Negative numbers move backward. Snort and Suricata both allow this.', 'Needs an earlier content in the same buffer.'],
    ['within N', 'The match must end within N bytes of where distance starts. within must be at least as long as the content.', 'Sets the size of the window, together with distance.'],
    ['startswith', 'Short for offset 0 and depth the length of the content.', 'Suricata 5 and later. Snort 3 has no startswith keyword; use offset:0, depth:N.'],
    ['endswith', 'The match must end exactly at the end of the buffer.', 'Suricata only. Snort has no direct form; isdataat:!1,relative is the nearest.'],
    ['nocase', 'Ignore capital letters. Keeps the rule working if the attacker changes the case.', 'Removing it narrows the rule but lets "ADMIN" slip past. Rarely worth it.'],
    ['sticky buffer', 'Names which part of the traffic the next contents search (http.uri, http.header, file.data, and so on).', 'Suricata and Snort 3 use a name first, then contents. Snort 2 puts a modifier after the content (content:"x"; http_uri;).'],
    ['dsize', 'Size of one packet payload (not a stream). Handy for UDP and short messages.', 'Not useful for HTTP, which spans packets.']
  ];

  var EXAMPLES = [
    { id: 'http', title: 'Web rule that matches the wrong place',
      blurb: 'A rule for /admin also fires on a Referer header and a form field. Suricata. Shows the HTTP buffer recommendation.',
      engine: 'suricata',
      rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"EXAMPLE Admin panel probe"; flow:to_server,established; content:"/admin"; nocase; classtype:web-application-attack; sid:1000001; rev:1;)',
      alert: '10/28/2026-12:00:00.000000  [**] [1:1000001:1] EXAMPLE Admin panel probe [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.0.0.5:40001 -> 192.0.2.10:80',
      build: function (PB) {
        function web(client, cport, method, uri, headers, body, t0) { return PB.tcpSession({ client: client, server: '192.0.2.10', cport: cport, request: PB.http(method, uri, headers, body), response: PB.httpResponse(200, 'ok'), t0: t0 }); }
        return {
          fp: PB.pcap(PB.merge(
            web('10.0.0.5', 40001, 'GET', '/static/app.js', { Referer: 'http://example.test/admin/index' }, undefined, 1793188800000),
            web('10.0.0.6', 40002, 'POST', '/api/save', {}, 'path=/admin/settings', 1793188801000),
            web('10.0.0.7', 40003, 'GET', '/home', {}, undefined, 1793188802000))),
          tp: PB.pcap(web('203.0.113.9', 50001, 'GET', '/admin/login.php', {}, undefined, 1793188900000))
        };
      } },
    { id: 'udp', title: 'Command word anywhere in a UDP message',
      blurb: 'A rule for "CMD=" fires on messages that only mention it. Snort 3. Shows offset, depth and a payload size limit.',
      engine: 'snort3',
      rule: 'alert udp any any -> any 5000 (msg:"EXAMPLE Command string"; content:"CMD=",nocase; sid:1000002; rev:1;)',
      alert: '',
      build: function (PB) {
        function udp(src, sport, payload, ts) { return PB.udp({ src: src, dst: '192.0.2.9', sport: sport, dport: 5000, payload: payload, ts: ts }); }
        return {
          fp: PB.pcap([udp('10.0.0.5', 50001, 'status=ok;note CMD=none', 1793188800000), udp('10.0.0.6', 50002, 'heartbeat; a=1;CMD=zz.......', 1793188801000)]),
          tp: PB.pcap([udp('203.0.113.9', 51001, 'CMD=run', 1793188900000), udp('203.0.113.9', 51002, 'CMD=exec ls', 1793188901000)])
        };
      } },
    { id: 'beacon', title: 'Two strings that are too far apart',
      blurb: 'A beacon rule with two contents matches harmless traffic where they are 30 bytes apart. Shows distance and within.',
      engine: 'suricata',
      rule: 'alert tcp any any -> any 4444 (msg:"EXAMPLE Beacon"; flow:to_server,established; content:"BEACON"; content:"id="; sid:1000003; rev:1;)',
      alert: '',
      build: function (PB) {
        function raw(client, cport, payload, t0) { return PB.tcpSession({ client: client, server: '192.0.2.20', cport: cport, sport: 4444, request: payload, response: '', t0: t0 }); }
        return {
          fp: PB.pcap(raw('10.0.0.5', 41001, 'BEACON' + new Array(31).join(' ') + 'id=7', 1793188800000)),
          tp: PB.pcap(PB.merge(raw('203.0.113.9', 52001, 'BEACON id=42', 1793188900000), raw('203.0.113.9', 52002, 'BEACON id=43', 1793189000000)))
        };
      } }
  ];

  SK.idsData = { CHECKS: CHECKS, ABNORMAL: ABNORMAL, ROUTINE: ROUTINE, HISTORICAL: HISTORICAL, CHEATSHEET: CHEATSHEET, EXAMPLES: EXAMPLES };
})();
