// Teaching content and sample data for the rule tuner. Plain data, no logic.
(function () {
  var SK = window.SK = window.SK || {};

  // Each risk has a matching test in tuner-core.js (same id).
  var RISKS = [
    { id: 'office-child', sev: 'high', title: 'Office program started a shell or script host',
      why: 'Word, Excel, PowerPoint and Outlook rarely need to start a command shell or script engine. When they do, it is most often a malicious document or macro running.',
      mitre: ['T1566.001', 'T1204.002', 'T1059'] },
    { id: 'browser-child', sev: 'high', title: 'Web browser started a shell or script host',
      why: 'A browser launching cmd, PowerShell or a script host can mean a drive-by download or a pasted malicious command.',
      mitre: ['T1189', 'T1059'] },
    { id: 'encoded-command', sev: 'high', title: 'Encoded or obfuscated command line',
      why: 'Encoded PowerShell hides what it does. Some management tools use it, so check who started it, but unexplained encoded commands deserve investigation.',
      mitre: ['T1027', 'T1059.001'] },
    { id: 'download-cradle', sev: 'high', title: 'Command downloads content from the internet',
      why: 'Fetching and running remote content is a common way to bring in a second stage.',
      mitre: ['T1105', 'T1059.001'] },
    { id: 'invoke-expression', sev: 'medium', title: 'Text is run as code (Invoke-Expression / iex)',
      why: 'Running a string as code is often how obfuscated scripts execute their real payload.',
      mitre: ['T1059.001', 'T1027'] },
    { id: 'hidden-bypass', sev: 'medium', title: 'Hidden window with profile or execution policy bypass',
      why: 'Hiding the window and skipping safety settings together is typical of attacker scripts. Some admin tools do it too, so confirm the owner.',
      mitre: ['T1059.001', 'T1564.003'] },
    { id: 'writable-path', sev: 'high', title: 'Program or script runs from a folder any user can write to',
      why: 'Temp, Downloads, AppData, ProgramData and Public are places users and malware can drop files. Legitimate software normally installs elsewhere.',
      mitre: ['T1204.002', 'T1036'] },
    { id: 'lolbin-remote', sev: 'high', title: 'Built-in program asked to run remote or script content',
      why: 'mshta, regsvr32, rundll32 and msiexec can be pointed at a URL or script to run it. That bypasses simple allow-lists.',
      mitre: ['T1218.005', 'T1218.010', 'T1218.011'] },
    { id: 'credential-theft', sev: 'high', title: 'Credential theft pattern',
      why: 'Dumping LSASS memory or saving the SAM, SYSTEM or NTDS data is how attackers collect passwords. Do not exclude it.',
      mitre: ['T1003.001', 'T1003.002', 'T1003.003'] },
    { id: 'persistence', sev: 'medium', title: 'Persistence being created (scheduled task, Run key, service)',
      why: 'Software installers do this too, so compare against known installs. Unknown programs creating them are suspicious.',
      mitre: ['T1053.005', 'T1547.001', 'T1543.003'] },
    { id: 'recovery-tamper', sev: 'high', title: 'Backups or logs being destroyed',
      why: 'Deleting shadow copies, backups or event logs is a standard ransomware and clean-up step.',
      mitre: ['T1490', 'T1070.001'] },
    { id: 'remote-exec', sev: 'medium', title: 'Remote execution tooling',
      why: 'PsExec, WMI node execution and remote PowerShell are used by admins and by attackers moving between machines.',
      mitre: ['T1021.002', 'T1047', 'T1021.006', 'T1569.002'] },
    { id: 'svchost-oddity', sev: 'high', title: 'svchost.exe from an unexpected parent or folder',
      why: 'The real svchost.exe is started by services.exe and lives in System32. A lookalike elsewhere is likely malware.',
      mitre: ['T1036.005'] },
    { id: 'double-extension', sev: 'high', title: 'Document or image name with an executable extension',
      why: 'A name such as invoice.pdf.exe tries to look like a document.',
      mitre: ['T1036.007'] },
    { id: 'very-long-command', sev: 'medium', title: 'Very long command line',
      why: 'Commands over about 800 characters often carry embedded payloads or heavy obfuscation.',
      mitre: ['T1027'] }
  ];

  var ABNORMAL = [
    ['Excel, Word, PowerPoint or Outlook starts PowerShell, cmd, wscript, cscript or mshta', 'A document that runs a script is the classic phishing outcome. Investigate the document and the user, do not tune it out.'],
    ['A browser or PDF reader starts a shell', 'Can indicate a browser exploit or a user pasting a command from a fake web page.'],
    ['PowerShell with an encoded command (-enc) that nobody can explain', 'Ask the owning team. If there is no clear owner, treat it as suspicious.'],
    ['A script or program runs from Temp, Downloads, AppData or Public', 'Legitimate software rarely runs from there. Attackers drop files there because users can write to it.'],
    ['certutil, bitsadmin, curl or PowerShell downloading from the internet to a user folder', 'Normal admin work usually comes from known deployment tools and servers.'],
    ['mshta, regsvr32 or rundll32 given a URL or script', 'These are built-in programs that can run remote content.'],
    ['Anything touching LSASS memory, the SAM, or ntds.dit', 'Credential theft. Never tune this out without a very specific, documented reason.'],
    ['Shadow copies, backups or event logs being deleted', 'A common ransomware and cover-up step.'],
    ['A system process name in the wrong place (svchost.exe outside System32)', 'Name-matching on a lookalike file is a typical hiding method.']
  ];

  var ROUTINE = [
    ['A backup, inventory or patch agent starts PowerShell with a fixed script path from its own install folder', 'Check that the parent program, script path and arguments are the same every time and that the folder is only writable by administrators.'],
    ['A vulnerability scanner or monitoring server connects to many hosts on a schedule', 'Scope the exclusion to the scanner\'s address and the schedule, not to the whole service.'],
    ['An EDR or management agent touches many files or processes', 'Use the agent\'s signed path and publisher, and confirm with the vendor documentation.'],
    ['A developer build tool (for example msbuild) running on build servers', 'Limit the exclusion to the build servers. The same activity on an accounting laptop would be unusual.']
  ];

  var HISTORICAL = [
    'Search at least 30 days of history for the same activity (90 days is better). Note how often it happens, on which hosts, and for which users.',
    'Confirm that it happens on a regular pattern (a schedule, a deployment, a specific team). One-off events are not good candidates.',
    'Find the owner: which team or product causes it? Ask them, and check the vendor documentation.',
    'Check whether any occurrence differs: a new host, a new user, a different path or a different parent process. Look at those first.',
    'Check that the files involved sit in locations only administrators can change, and are signed by the expected publisher.'
  ];

  var FORMATS = [
    { id: 'yaral', label: 'YARA-L 2.0 (Google SecOps / Chronicle)' },
    { id: 'sigma', label: 'Sigma' },
    { id: 'splunk', label: 'Splunk search (SPL)' },
    { id: 'kql', label: 'Kusto (Microsoft Sentinel / Defender)' },
    { id: 'regex', label: 'Regular expression (pattern on a log line)' },
    { id: 'generic', label: 'Other (plain-language conditions)' }
  ];

  var SAMPLE = {
    format: 'sigma',
    alert: 'Alert: Suspicious PowerShell launched with a script file\nSeverity: Medium\nHost: WS-0142\nTriggered 14 times in 7 days across 3 hosts.',
    rule: 'title: PowerShell Started With Script File By Non-Interactive Parent\nstatus: experimental\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image|endswith: \'\\powershell.exe\'\n        CommandLine|contains: \' -File \'\n    condition: selection\nlevel: medium',
    logs: [
      '{"UtcTime":"2026-10-20 02:00:04","Computer":"SRV-APP01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\prebackup.ps1\\" -Job 1042","SourceIp":"10.20.30.41"}',
      '{"UtcTime":"2026-10-21 02:00:03","Computer":"SRV-APP01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\prebackup.ps1\\" -Job 1043","SourceIp":"10.20.30.41"}',
      '{"UtcTime":"2026-10-22 02:00:05","Computer":"SRV-APP01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\prebackup.ps1\\" -Job 1044","SourceIp":"10.20.30.41"}',
      '{"UtcTime":"2026-10-20 02:00:09","Computer":"SRV-DB01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\prebackup.ps1\\" -Job 1042","SourceIp":"10.20.30.42"}',
      '{"UtcTime":"2026-10-21 02:00:08","Computer":"SRV-DB01","User":"NT AUTHORITY\\\\SYSTEM","ParentImage":"C:\\\\Program Files\\\\NorthwindBackup\\\\nbagent.exe","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\"C:\\\\Program Files\\\\NorthwindBackup\\\\scripts\\\\prebackup.ps1\\" -Job 1043","SourceIp":"10.20.30.42"}',
      '{"UtcTime":"2026-10-22 13:41:17","Computer":"WS-0142","User":"CORP\\\\jsmith","ParentImage":"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\EXCEL.EXE","Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe","CommandLine":"powershell.exe -nop -w hidden -File C:\\\\Users\\\\jsmith\\\\AppData\\\\Local\\\\Temp\\\\update.ps1","SourceIp":"10.20.31.77"}'
    ].join('\n')
  };

  SK.tunerData = { RISKS: RISKS, ABNORMAL: ABNORMAL, ROUTINE: ROUTINE, HISTORICAL: HISTORICAL, FORMATS: FORMATS, SAMPLE: SAMPLE };
})();
