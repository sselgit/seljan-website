#!/usr/bin/env python3
"""Builds site/js/attack-map.js: keyword rules that suggest MITRE ATT&CK techniques for a detection rule.

Usage: python scripts/build_attack_map.py [path-to-enterprise-attack.json]

Technique names and tactics are read from MITRE's public STIX data
(https://github.com/mitre-attack/attack-stix-data), so every ID below is checked to exist and not be revoked.
The keyword rules are our own, hand-written and deliberately small. ATT&CK(R) is a registered trademark of
The MITRE Corporation; the data is used under MITRE's terms (https://attack.mitre.org/resources/terms-of-use/).
"""
import json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "site", "js", "attack-map.js")
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# (regex on the lower-cased rule name, rule text and alert text, [technique ids], short reason)
RULES = [
    # ---- execution and scripting
    (r"powershell|pwsh|invoke-expression|\biex\b", ["T1059.001"], "PowerShell"),
    (r"cmd\.exe|command shell|windows command", ["T1059.003"], "Windows command shell"),
    (r"wscript|cscript|vbscript|\.vbs\b", ["T1059.005"], "Visual Basic script host"),
    (r"jscript|javascript|\.js\b|node\.exe", ["T1059.007"], "JavaScript"),
    (r"/bin/(ba)?sh|unix shell|bash -i|reverse shell|netcat|\bnc -e", ["T1059.004"], "Unix shell"),
    (r"macro|winword|\bexcel\b|powerpnt|outlook.{0,20}(spawn|child|launch)|office.{0,20}(spawn|child|launch|start)", ["T1204.002", "T1566.001"], "Office document running code"),
    (r"encoded ?command|-enc\b|-encodedcommand|base64|obfuscat|char\(\d+\)|\bxor\b", ["T1027", "T1140"], "Encoded or obfuscated content"),
    (r"mshta", ["T1218.005"], "mshta"),
    (r"regsvr32", ["T1218.010"], "regsvr32"),
    (r"rundll32", ["T1218.011"], "rundll32"),
    (r"msiexec", ["T1218.007"], "msiexec"),
    (r"installutil", ["T1218.004"], "InstallUtil"),
    (r"bitsadmin|bits ?job", ["T1197"], "BITS jobs"),
    (r"certutil|invoke-webrequest|downloadstring|downloadfile|\bwget\b|\bcurl\b|download cradle|ingress tool|download.{0,20}(exe|payload|dll|script)", ["T1105"], "File or tool downloaded from elsewhere"),
    # ---- persistence and privilege
    (r"schtasks|scheduled task", ["T1053.005"], "Scheduled task"),
    (r"currentversion\\run|run key|startup folder|runonce", ["T1547.001"], "Registry run key or startup folder"),
    (r"sc(\.exe)? create|new service|service install|createservice", ["T1543.003"], "Windows service"),
    (r"wmi (event )?subscription|__eventfilter|commandlineeventconsumer", ["T1546.003"], "WMI event subscription"),
    (r"web ?shell|cmd\.php|c99|r57|china chopper", ["T1505.003"], "Web shell"),
    (r"uac bypass|fodhelper|eventvwr|computerdefaults", ["T1548.002"], "UAC bypass"),
    (r"process injection|createremotethread|writeprocessmemory|process hollowing|reflective", ["T1055"], "Process injection"),
    (r"dll (side[- ]?load|hijack|search order)", ["T1574.001"], "DLL side-loading"),
    (r"svchost|masquerad|lookalike|double extension|\.pdf\.exe|\.doc\.exe", ["T1036"], "Masquerading"),
    # ---- defense evasion
    (r"disable.{0,20}(defender|antivirus|av\b|security)|tamper|set-mppreference|stop.{0,10}(defender|sense)", ["T1685"], "Security tools disabled"),
    (r"clear.{0,12}(event ?)?log|wevtutil cl|wevtutil clear|log (deletion|clearing)", ["T1685.005"], "Event logs cleared"),
    # ---- credential access
    (r"lsass|mimikatz|procdump.{0,30}lsass|sekurlsa|comsvcs.{0,10}minidump", ["T1003.001"], "LSASS credential dumping"),
    (r"\bsam\b.{0,20}(hive|save|dump)|reg save.{0,20}(sam|system)", ["T1003.002"], "SAM credential dump"),
    (r"ntds|ntdsutil", ["T1003.003"], "NTDS.dit credential dump"),
    (r"dcsync|drsuapi|getncchanges", ["T1003.006"], "DCSync"),
    (r"kerberoast|tgs.{0,10}(rc4|0x17)", ["T1558.003"], "Kerberoasting"),
    (r"password spray|spraying", ["T1110.003"], "Password spraying"),
    (r"brute[- ]?force|failed logon|login attempts|too many (failed|auth)|ssh.{0,10}(scan|brute)", ["T1110"], "Repeated login attempts"),
    # ---- discovery
    (r"whoami", ["T1033"], "whoami"),
    (r"net (user|group|localgroup)|get-aduser|adfind", ["T1087"], "Account discovery"),
    (r"systeminfo|os discovery", ["T1082"], "System information discovery"),
    (r"ipconfig|ifconfig|route print|network config", ["T1016"], "Network configuration discovery"),
    (r"nltest|domain trust|dsquery.{0,10}trust", ["T1482"], "Domain trust discovery"),
    (r"arp -a|net view|ping sweep|host discovery|nbtscan", ["T1018"], "Remote system discovery"),
    (r"port ?scan|nmap|masscan|syn scan|portscan|service scan|network scan|scanning", ["T1046"], "Port or service scanning"),
    (r"admin (panel|page|console|login)|/admin|wp-login|phpmyadmin|/manager/html", ["T1595", "T1190"], "Probing for admin pages"),
    (r"vulnerability scan|nessus|openvas|nikto|sqlmap|acunetix|burp|wpscan|dirbuster|gobuster|ffuf", ["T1595.002"], "Vulnerability scanner"),
    # ---- lateral movement
    (r"psexec|admin\$|ipc\$|smb.{0,15}(admin|lateral|share)|\bsmb\b", ["T1021.002"], "SMB and admin shares"),
    (r"winrm|wsman|enter-pssession|invoke-command", ["T1021.006"], "Windows Remote Management"),
    (r"\brdp\b|remote desktop|ms-wbt-server|mstsc|3389", ["T1021.001"], "Remote Desktop"),
    (r"\bssh\b|port 22\b", ["T1021.004"], "SSH"),
    (r"wmic.{0,20}(/node|process call)|wmiexec|win32_process.{0,10}create", ["T1047"], "WMI execution"),
    # ---- command and control, exfiltration
    (r"beacon|command and control|\bc2\b|\bc&c\b|callback|cobalt ?strike|meterpreter|trojan|\brat\b|backdoor", ["T1071"], "Command-and-control traffic"),
    (r"\bhttps?\b|user-agent|\buri\b|get /|post /", ["T1071.001"], "Web protocol traffic"),
    (r"\bdns\b.{0,25}(tunnel|txt|long|exfil|beacon|c2)|dnscat|iodine|dns tunnel", ["T1071.004", "T1572"], "DNS used for command and control or tunneling"),
    (r"dga|domain generation|random.{0,10}domain|dynamic dns|ddns", ["T1568.002"], "Domain generation or dynamic DNS"),
    (r"icmp.{0,15}(tunnel|payload|exfil|data)", ["T1095"], "ICMP carrying data"),
    (r"tunnel|ngrok|chisel|frp\b|socks", ["T1572"], "Protocol tunneling"),
    (r"\btor\b|onion|proxy|anonymi[sz]er", ["T1090"], "Proxy or anonymizing network"),
    (r"\btls\b|\bssl\b|certificate|ja3|self-signed", ["T1573"], "Encrypted channel"),
    (r"exfil|data (theft|leak)|large (upload|outbound)|upload.{0,10}(archive|zip|rar)", ["T1041"], "Data leaving the network"),
    # ---- initial access and impact
    (r"sql ?injection|\bsqli\b|union.{0,5}select|information_schema|' ?or ?1=1|xp_cmdshell", ["T1190"], "SQL injection against a public service"),
    (r"directory traversal|path traversal|\.\./|\.\.%2f|\blfi\b|\brfi\b|file inclusion|log4j|jndi:|shellshock|\(\) ?\{|\brce\b|remote code|command injection|deserializ|exploit|cve-\d{4}-\d+", ["T1190"], "Exploit against a public-facing service"),
    (r"phish|spearphish|malicious (email|attachment)|credential harvest", ["T1566"], "Phishing"),
    (r"shadow ?cop|vssadmin|wbadmin|bcdedit|recoveryenabled|wmic shadowcopy|backup.{0,10}delet", ["T1490"], "Backups or recovery disabled"),
    (r"ransom|encrypt(ed)? files|\.locked\b|files? encrypted", ["T1486"], "Ransomware encryption"),
    (r"\bdos\b|denial of service|flood|amplification|ddos", ["T1498"], "Denial of service"),
]

# ATT&CK v20 renumbered some techniques (checked against the data: each old ID is revoked and points at the new one).
# Many teams still use the old IDs, so the page shows both.
LEGACY = {"T1685": "T1562.001", "T1685.005": "T1070.001", "T1574.001": "T1574.002"}

# Snort and Suricata classtype values with a clear ATT&CK link.
CLASSTYPES = {
    "web-application-attack": ["T1190"],
    "attempted-admin": ["T1190"],
    "attempted-user": ["T1190"],
    "shellcode-detect": ["T1059"],
    "trojan-activity": ["T1071"],
    "network-scan": ["T1046"],
    "attempted-recon": ["T1595"],
    "denial-of-service": ["T1498"],
    "attempted-dos": ["T1498"],
    "successful-recon-limited": ["T1595"],
    "web-application-activity": [],
}


def load(path):
    if path:
        return json.load(open(path, encoding="utf-8"))
    print("downloading", URL)
    with urllib.request.urlopen(URL, timeout=120) as r:
        return json.load(r)


def main():
    data = load(sys.argv[1] if len(sys.argv) > 1 else None)
    techs = {}
    version = ""
    for o in data["objects"]:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version", "")
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            for r in o["external_references"]:
                if r.get("source_name") == "mitre-attack":
                    techs[r["external_id"]] = (o["name"], [p["phase_name"].replace("-", " ") for p in o.get("kill_chain_phases", [])])
    used = set(i for _, ids, _ in RULES for i in ids) | set(i for v in CLASSTYPES.values() for i in v)
    missing = sorted(i for i in used if i not in techs)
    if missing:
        sys.exit("Not in the ATT&CK data (revoked or mistyped): " + ", ".join(missing))
    tech_json = {i: dict({"n": techs[i][0], "t": techs[i][1]}, **({"o": LEGACY[i]} if i in LEGACY else {})) for i in sorted(used)}
    rules_js = ",\n    ".join("[%s, %s, %s]" % (json.dumps("/" + p + "/i"[1:]) if False else "/" + p.replace("/", "\\/") + "/i", json.dumps(ids), json.dumps(why)) for p, ids, why in RULES)
    js = """// Suggests MITRE ATT&CK techniques for a detection rule from its name and contents. GENERATED by scripts/build_attack_map.py
// from MITRE's ATT&CK Enterprise data (v%(version)s); do not edit by hand. These are keyword suggestions to review, not a
// classification. ATT&CK(R) is a registered trademark of The MITRE Corporation (https://attack.mitre.org/resources/terms-of-use/).
(function () {
  var SK = window.SK = window.SK || {};
  var TECH = %(tech)s;
  var RULES = [
    %(rules)s
  ];
  var CLASSTYPES = %(classtypes)s;

  // text: rule name, rule body, alert text. opts.classtype: optional Snort/Suricata classtype.
  // Returns [{ id, name, tactics, url, confidence, why: [reasons] }], best first, at most opts.max (default 5).
  function suggest(text, opts) {
    opts = opts || {};
    var hay = String(text || '').toLowerCase(), found = {};
    function add(id, why, weight) {
      var f = found[id] = found[id] || { id: id, score: 0, why: [] };
      f.score += weight;
      if (f.why.indexOf(why) < 0) f.why.push(why);
    }
    RULES.forEach(function (r) {
      if (!r[0].test(hay)) return;
      // Generic web or encryption words alone say little, so they count less than a named tool or behavior.
      var weak = r[1].length === 1 && (r[1][0] === 'T1071.001' || r[1][0] === 'T1573' || r[1][0] === 'T1090' || r[1][0] === 'T1572');
      r[1].forEach(function (id) { add(id, r[2], weak ? 1 : 3); });
    });
    var ct = String(opts.classtype || '').toLowerCase();
    (CLASSTYPES[ct] || []).forEach(function (id) { add(id, 'classtype ' + ct, 2); });
    var list = Object.keys(found).map(function (id) { return found[id]; }).filter(function (f) { return TECH[f.id]; });
    // A sub-technique makes its parent redundant.
    list = list.filter(function (f) { return !list.some(function (g) { return g.id !== f.id && g.id.indexOf(f.id + '.') === 0; }); });
    list.sort(function (a, b) { return b.score - a.score || (a.id < b.id ? -1 : 1); });
    return list.slice(0, opts.max || 5).map(function (f) {
      var t = TECH[f.id];
      return { id: f.id, name: t.n, oldId: t.o || '', tactics: t.t, url: 'https://attack.mitre.org/techniques/' + f.id.replace('.', '/') + '/',
        confidence: f.score >= 6 ? 'good match' : (f.score >= 3 ? 'possible match' : 'weak hint'), why: f.why };
    });
  }

  SK.attack = { suggest: suggest, TECH: TECH };
})();
""" % {"version": version, "tech": json.dumps(tech_json, indent=2, sort_keys=True), "rules": rules_js, "classtypes": json.dumps(CLASSTYPES)}
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(js)
    print("wrote", OUT, len(tech_json), "techniques, ATT&CK", version)


main()
