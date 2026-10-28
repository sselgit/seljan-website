// Quick-reference tables for analysts. Static data, searchable in the page. No network.
(function () {
  var SK = window.SK = window.SK || {};

  var SECURITY = [
    ['4624', 'Successful logon', 'Check the logon type (see table below), source address and account. Type 3 and 10 from unusual hosts deserve a look.'],
    ['4625', 'Failed logon', 'Bursts against one account suggest guessing; one attempt across many accounts suggests spraying.'],
    ['4634 / 4647', 'Logoff / user-initiated logoff', 'Pair with 4624 to build session length.'],
    ['4648', 'Logon with explicit credentials', 'RunAs or a tool using someone else\'s credentials; common in lateral movement.'],
    ['4672', 'Special privileges assigned to a new logon', 'Admin-level logon. Expected for admins, suspicious for ordinary accounts.'],
    ['4688', 'A process was created', 'Needs command-line auditing turned on to be useful.'],
    ['4697', 'A service was installed (Security log)', 'Service creation is a common persistence and remote execution step.'],
    ['4698 / 4699 / 4700 / 4702', 'Scheduled task created / deleted / enabled / updated', 'Persistence and remote execution. Look at the action and the creating account.'],
    ['4719', 'System audit policy was changed', 'Attackers turn auditing down to hide.'],
    ['4720 / 4722 / 4725 / 4726', 'Account created / enabled / disabled / deleted', 'New accounts outside of change windows are worth checking.'],
    ['4723 / 4724', 'Password change / reset attempted', 'A reset by someone other than the owner or help desk is suspicious.'],
    ['4728 / 4732 / 4756', 'Member added to a security group (global / local / universal)', 'Watch privileged groups such as Domain Admins and Administrators.'],
    ['4740', 'Account locked out', 'Source of the lockout is in the event; helps find the guessing host.'],
    ['4768 / 4769 / 4771', 'Kerberos ticket requests / pre-authentication failure', 'Many 4769 events with RC4 encryption can point to Kerberoasting.'],
    ['4776', 'NTLM credential validation', 'Shows which host validated an NTLM logon; useful for pass-the-hash hunting.'],
    ['4798 / 4799', 'Local group membership enumerated', 'Reconnaissance of who is an admin.'],
    ['5140 / 5145', 'Network share accessed / share object checked', 'ADMIN$ and C$ access from workstations is a lateral movement sign.'],
    ['5156 / 5157', 'Filtering Platform allowed / blocked a connection', 'Very noisy; useful when scoped to one host.'],
    ['4946 / 4947 / 4948', 'Firewall rule added / modified / deleted', 'Unexpected rule changes can open a path in.'],
    ['1102', 'The audit log was cleared', 'Almost always worth an alert.'],
    ['4616', 'System time was changed', 'Can be used to confuse timelines.']
  ];

  var SYSTEM = [
    ['7045', 'New service installed (System log)', 'Check the service name, image path and account. Random names and odd paths are suspicious.'],
    ['7040', 'Service start type changed', 'Disabled security services are a red flag.'],
    ['104', 'The event log was cleared (System)', 'Same idea as 1102 for the System log.'],
    ['6005 / 6006 / 6008', 'Event log service started / stopped / unexpected shutdown', 'Useful for building reboot timelines.']
  ];

  var POWERSHELL = [
    ['4104', 'Script block logging', 'Records the actual script text, including de-obfuscated code. The most valuable PowerShell event.'],
    ['4103', 'Module logging', 'Records pipeline execution details.'],
    ['400 / 403', 'Engine started / stopped (classic log)', 'Shows host application and version; a version 2 downgrade is suspicious.'],
    ['800', 'Pipeline execution details (classic log)', 'Older logging source.']
  ];

  var SYSMON = [
    ['1', 'Process created', 'Image, command line, parent process and hashes.'],
    ['2', 'File creation time changed', 'Timestomping.'],
    ['3', 'Network connection', 'Which process connected where.'],
    ['5', 'Process terminated', ''],
    ['6', 'Driver loaded', 'Check signatures; vulnerable drivers are abused.'],
    ['7', 'Image (DLL) loaded', 'Noisy; useful for DLL side-loading.'],
    ['8', 'CreateRemoteThread', 'Process injection indicator.'],
    ['10', 'Process access', 'Reads of lsass.exe memory suggest credential theft.'],
    ['11', 'File created', 'Drops in user-writable folders.'],
    ['12 / 13 / 14', 'Registry object / value / rename', 'Run keys and other persistence locations.'],
    ['15', 'File stream created', 'Mark-of-the-web and alternate data streams.'],
    ['17 / 18', 'Named pipe created / connected', 'Used by some remote-execution and C2 tooling.'],
    ['19 / 20 / 21', 'WMI filter / consumer / binding', 'WMI persistence.'],
    ['22', 'DNS query', 'Which process asked for which domain.'],
    ['23 / 26', 'File deleted (archived / detected)', 'Evidence of clean-up.'],
    ['25', 'Process tampering', 'Hollowing or herpaderping indicators.']
  ];

  var LOGON = [
    ['2', 'Interactive', 'Keyboard at the machine.'],
    ['3', 'Network', 'File shares, remote commands. Most common for lateral movement.'],
    ['4', 'Batch', 'Scheduled task.'],
    ['5', 'Service', 'A service started under an account.'],
    ['7', 'Unlock', 'Workstation unlocked.'],
    ['8', 'NetworkCleartext', 'Password sent in the clear to the server (for example IIS basic auth). Worth noting.'],
    ['9', 'NewCredentials', 'RunAs /netonly; the new credentials are only used on the network.'],
    ['10', 'RemoteInteractive', 'Remote Desktop.'],
    ['11', 'CachedInteractive', 'Logon using cached credentials (laptop off the network).']
  ];

  var WATCH = [
    ['winword.exe, excel.exe, powerpnt.exe, outlook.exe', 'launching cmd, PowerShell, wscript, mshta or rundll32', 'Normal Office use almost never starts a shell. A document opening a script host is a classic phishing result.'],
    ['powershell.exe, pwsh.exe', '-EncodedCommand, -WindowStyle Hidden, download cradles (DownloadString, Invoke-WebRequest)', 'Admins use PowerShell all the time. Encoded, hidden, internet-fetching commands from user context are the concern.'],
    ['mshta.exe', 'any URL or script argument', 'Runs HTML applications; rarely needed in a normal workplace.'],
    ['regsvr32.exe', '/i:http..., scrobj.dll', 'Can load a remote script as a "scriptlet".'],
    ['rundll32.exe', 'javascript:, unusual DLL paths, no arguments', 'Many legitimate uses, so judge by the DLL path and parent process.'],
    ['certutil.exe', '-urlcache, -decode', 'Meant for certificates; also downloads and decodes files.'],
    ['bitsadmin.exe', '/transfer', 'Legitimate download tool that is also used to fetch payloads.'],
    ['wmic.exe', 'process call create, /node:', 'Remote execution and reconnaissance.'],
    ['schtasks.exe, sc.exe', '/create from user-writable paths', 'Persistence.'],
    ['msiexec.exe', '/i with a remote URL', 'Installs a package from the internet.'],
    ['vssadmin.exe, wbadmin.exe, bcdedit.exe', 'delete shadows, delete catalog, recoveryenabled no', 'Ransomware preparation: removing the ability to recover.'],
    ['wevtutil.exe', 'cl (clear log)', 'Clearing logs hides activity.']
  ];

  var ESTIMATIVE = [
    ['Almost no chance', 'Remote', '1-5%'],
    ['Very unlikely', 'Highly improbable', '5-20%'],
    ['Unlikely', 'Improbable', '20-45%'],
    ['Roughly even chance', 'Roughly even odds', '45-55%'],
    ['Likely', 'Probable', '55-80%'],
    ['Very likely', 'Highly probable', '80-95%'],
    ['Almost certain', 'Nearly certain', '95-99%']
  ];

  var HTTP = [
    ['200', 'OK', ''], ['301 / 302 / 307 / 308', 'Redirects', 'Long redirect chains are common in phishing and ad fraud.'],
    ['400', 'Bad request', 'Malformed input; scanners trigger many.'], ['401', 'Unauthorized', 'Authentication needed or failed. Many 401s from one source suggest guessing.'],
    ['403', 'Forbidden', 'Access refused.'], ['404', 'Not found', 'Bursts of 404s suggest scanning for files and paths.'],
    ['405', 'Method not allowed', ''], ['429', 'Too many requests', 'Rate limiting kicked in.'],
    ['500', 'Server error', 'A burst after odd input can mean someone is probing for flaws.'], ['502 / 503 / 504', 'Gateway or availability errors', '']
  ];

  var TABLES = [
    { id: 'security', title: 'Windows Security log events', cols: ['Event ID', 'Meaning', 'Why analysts care'], rows: SECURITY },
    { id: 'system', title: 'Windows System log events', cols: ['Event ID', 'Meaning', 'Why analysts care'], rows: SYSTEM },
    { id: 'ps', title: 'PowerShell logging events', cols: ['Event ID', 'Meaning', 'Why analysts care'], rows: POWERSHELL },
    { id: 'sysmon', title: 'Sysmon events', cols: ['Event ID', 'Meaning', 'Why analysts care'], rows: SYSMON },
    { id: 'logon', title: 'Windows logon types (inside event 4624 / 4625)', cols: ['Type', 'Name', 'Meaning'], rows: LOGON },
    { id: 'watch', title: 'Programs that deserve a second look', cols: ['Program', 'Concerning use', 'Why'], rows: WATCH },
    { id: 'est', title: 'Estimative language (ICD 203 probability scale)', cols: ['Term', 'Also written as', 'Rough probability'], rows: ESTIMATIVE },
    { id: 'http', title: 'HTTP status codes in web logs', cols: ['Code', 'Meaning', 'Why analysts care'], rows: HTTP }
  ];

  var NOTES = {
    watch: 'These programs are built into Windows and are used legitimately every day. The point is the combination: what started it, what arguments it has, and where it ran from. Always check how often it happens in your own environment first.',
    est: 'Words give analysts a shared meaning. Pick the term, not the number, in writing, and keep it separate from your confidence in the sources. The ranges here are the commonly published ICD 203 scale (U.S. Office of the Director of National Intelligence); confirm against the primary directive before citing it formally.',
    security: 'Event IDs are for Microsoft Windows. Check Microsoft\'s documentation for your Windows version before building detections on them.'
  };

  SK.reference = { tables: TABLES };

  function init() {
    var host = SK.$('ref-tables');
    if (!host) return;
    var query = SK.$('ref-search');

    function render() {
      var q = query.value.trim().toLowerCase(), shown = 0;
      SK.clear(host);
      TABLES.forEach(function (tb) {
        var rows = tb.rows.filter(function (r) { return !q || r.join(' ').toLowerCase().indexOf(q) >= 0; });
        if (!rows.length) return;
        shown += rows.length;
        var t = SK.el('table', { className: 'kit-table' });
        t.appendChild(SK.el('tr', {}, tb.cols.map(function (c) { return SK.el('th', { text: c }); })));
        rows.forEach(function (r) {
          t.appendChild(SK.el('tr', {}, r.map(function (c, i) { return SK.el('td', { className: i === 0 ? 'num mono' : '', text: c }); })));
        });
        var section = SK.el('section', { className: 'kit-panel', attrs: { id: 'ref-' + tb.id } }, [
          SK.el('h2', { text: tb.title }),
          NOTES[tb.id] ? SK.el('p', { className: 'sub', text: NOTES[tb.id] }) : null,
          SK.el('div', { className: 'kit-table-wrap' }, [t])
        ]);
        host.appendChild(section);
      });
      if (!shown) host.appendChild(SK.el('div', { className: 'kit-callout warn' }, [SK.el('p', { text: 'Nothing matches "' + q + '".' })]));
    }
    query.addEventListener('input', render);
    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
