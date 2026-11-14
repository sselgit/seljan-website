// ---------- Knowledge base ----------
// kw: words that signal this goal. hints: concept -> which commands -> shape with blanks.
const R=[
{t:"Find the processes using the most memory",kw:"process processes program programs memory ram heavy hog top using task",
 h:["Think of this in 3 stages: get all processes, put the biggest first, keep only the top few.","You will want three commands joined by pipes: one that gets processes, one that sorts, and one that selects the first rows. Memory in use is a property called WS (working set).","Shape: Get-Process | Sort-Object ____ -Descending | Select-Object -First ____"],
 a:"Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name,Id,WS",
 e:"Get-Process lists processes. Sort-Object WS -Descending puts the biggest memory users first. Select-Object -First 10 keeps 10 rows and shows only three columns.",
 must:["Get-Process","Sort-Object","Select-Object"],sh:"ps aux --sort=-%mem | head -n 10"},
{t:"List services that are stopped",kw:"service services stopped not running down status",
 h:["Services are background programs. Each one has a Status property.","Get the services, then filter them. The filtering command is Where-Object.","Shape: Get-Service | Where-Object Status -____ 'Stopped'"],
 a:"Get-Service | Where-Object Status -eq 'Stopped'",
 e:"Where-Object keeps only items that match the test. -eq means equals.",
 must:["Get-Service","Where-Object"],sh:"systemctl list-units --type=service --state=inactive"},
{t:"Restart a service",kw:"restart service bounce spooler reboot service start stop",
 h:["Restarting changes the system, so be careful and preview first.","The verb is Restart. The noun is Service. You must give the service name.","Shape: Restart-Service -Name ____ -WhatIf   (remove -WhatIf to really do it)"],
 a:"Restart-Service -Name Spooler -WhatIf",
 e:"-WhatIf shows what would happen without doing it. Spooler is the print service, used here as an example. Needs an admin PowerShell.",
 must:["Restart-Service"],sh:"sudo systemctl restart cups"},
{t:"Find big files on a drive",kw:"large big files size space disk huge find biggest megabytes gb mb",
 h:["You need to look through folders, test each file's size, then sort.","Get-ChildItem lists files (add -Recurse for subfolders and -File for files only). Size is the Length property. PowerShell understands 100MB.","Shape: Get-ChildItem ____ -Recurse -File | Where-Object Length -gt ____ | Sort-Object Length -Descending"],
 a:"Get-ChildItem C:\\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object Length -gt 100MB | Sort-Object Length -Descending | Select-Object -First 20 FullName,Length",
 e:"-ErrorAction SilentlyContinue hides 'access denied' noise. This can take a while on a whole drive, so try a smaller folder first.",
 must:["Get-ChildItem","Where-Object","Sort-Object"],sh:"find / -type f -size +100M 2>/dev/null | head -n 20"},
{t:"Check free disk space",kw:"disk space free drive storage capacity full volume",
 h:["Drives are exposed as 'volumes'.","Look for a Get command with Volume or PSDrive in the name.","Shape: Get-Volume   or   Get-PSDrive -PSProvider ____"],
 a:"Get-Volume | Select-Object DriveLetter,FileSystemLabel,@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}},@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}",
 e:"The @{n=..;e={..}} parts make calculated columns that turn bytes into gigabytes.",
 must:["Get-Volume"],alt:["Get-PSDrive","Get-CimInstance"],sh:"df -h"},
{t:"Test if a computer or website is reachable",kw:"ping test connection reachable network host online port connectivity",
 h:["Ping checks if a machine answers. PowerShell has its own version.","Test-Connection is the ping style. Test-NetConnection can also check a specific port.","Shape: Test-NetConnection -ComputerName ____ -Port ____"],
 a:"Test-NetConnection -ComputerName example.com -Port 443",
 e:"TcpTestSucceeded : True means the port accepted the connection. Use Test-Connection <host> for a plain ping.",
 must:["Test-NetConnection"],alt:["Test-Connection","ping"],sh:"ping -c 4 example.com   or   nc -zv example.com 443"},
{t:"Show my IP address and network settings",kw:"ip address network adapter dns gateway config ipconfig interface",
 h:["This is the PowerShell version of the old ipconfig.","The command name starts with Get-Net.","Shape: Get-NetIPConfiguration   (or Get-NetIPAddress)"],
 a:"Get-NetIPConfiguration",
 e:"Shows adapter, IP, gateway and DNS in one view. ipconfig /all also still works.",
 must:["Get-NetIPConfiguration"],alt:["Get-NetIPAddress","ipconfig"],sh:"ip addr   and   ip route"},
{t:"Find recent errors in the event log",kw:"event log errors error system application crash windows events recent",
 h:["Windows keeps logs. You want only errors from a recent time window.","Get-WinEvent reads logs. Use -FilterHashtable to filter fast at the source. Level 2 means Error.","Shape: Get-WinEvent -FilterHashtable @{LogName='____'; Level=2; StartTime=(Get-Date).AddDays(-____)}"],
 a:"Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-1)} | Select-Object TimeCreated,Id,ProviderName,Message -First 20",
 e:"Filtering inside -FilterHashtable is much faster than getting everything and using Where-Object. Run as admin to read the Security log.",
 must:["Get-WinEvent"],sh:"journalctl -p err --since yesterday"},
{t:"Find text inside files",kw:"search text string inside files grep find word log contains pattern",
 h:["This is like grep on Linux.","The command name has the word Select and String.","Shape: Select-String -Path ____ -Pattern '____'"],
 a:"Select-String -Path .\\*.log -Pattern 'error' -CaseSensitive:$false",
 e:"Add -Recurse via Get-ChildItem -Recurse *.log | Select-String error to search subfolders.",
 must:["Select-String"],sh:"grep -ri 'error' *.log"},
{t:"Stop a program that is frozen",kw:"kill stop end close frozen hung process terminate notepad",
 h:["Stopping a process can lose unsaved work. Preview first.","The verb is Stop, the noun is Process. Identify it by name or Id.","Shape: Stop-Process -Name ____ -WhatIf"],
 a:"Stop-Process -Name notepad -WhatIf",
 e:"Remove -WhatIf to actually stop it. Use Get-Process first to confirm the name.",
 must:["Stop-Process"],sh:"pkill notepad"},
{t:"Save results to a CSV file",kw:"export csv save file excel report output spreadsheet",
 h:["Any pipeline result can end in a file.","The command that writes CSV starts with Export.","Shape: <your command> | Export-Csv -Path ____ -NoTypeInformation"],
 a:"Get-Process | Select-Object Name,Id,WS | Export-Csv -Path .\\procs.csv -NoTypeInformation",
 e:"-NoTypeInformation removes a junk first line in older PowerShell versions. Open the file in Excel.",
 must:["Export-Csv"],sh:"ps aux > procs.txt"},
{t:"Show installed software",kw:"installed software programs apps list applications inventory",
 h:["Programs register themselves in a list the system can read.","Look at Get-Package, or the registry Uninstall keys for a fuller list.","Shape: Get-Package | Select-Object Name,Version"],
 a:"Get-Package | Select-Object Name,Version | Sort-Object Name",
 e:"Avoid Get-WmiObject Win32_Product for this, it is slow and can trigger repairs.",
 must:["Get-Package"],alt:["Uninstall"],sh:"dpkg -l   or   rpm -qa"},
{t:"How long has this computer been running (uptime)",kw:"uptime boot last restart rebooted running since",
 h:["The boot time is stored in system info. Subtract it from now.","Get-CimInstance reads system info. The class is Win32_OperatingSystem, property LastBootUpTime.","Shape: (Get-Date) - (Get-CimInstance ____).LastBootUpTime"],
 a:"(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
 e:"Subtracting two dates gives a time span with days, hours and minutes.",
 must:["Get-CimInstance","LastBootUpTime"],sh:"uptime"},
{t:"Look up a DNS name",kw:"dns lookup resolve nslookup domain name record mx",
 h:["It is the PowerShell version of nslookup.","The command starts with Resolve.","Shape: Resolve-DnsName ____ -Type ____"],
 a:"Resolve-DnsName example.com -Type A",
 e:"Try -Type MX for mail servers, or add -Server 8.8.8.8 to ask a specific DNS server.",
 must:["Resolve-DnsName"],alt:["nslookup"],sh:"dig example.com A"},
{t:"See who is an administrator on this PC",kw:"admin administrators group members local users who privileged",
 h:["Local groups have members you can list.","The noun is LocalGroupMember.","Shape: Get-LocalGroupMember -Group '____'"],
 a:"Get-LocalGroupMember -Group 'Administrators'",
 e:"Great for audits. Use Get-LocalUser to list all local accounts.",
 must:["Get-LocalGroupMember"],sh:"getent group sudo"},
{t:"List open listening ports",kw:"open ports listening netstat tcp connections services port",
 h:["Which programs are waiting for connections?","Get-NetTCPConnection replaces netstat. Filter by state.","Shape: Get-NetTCPConnection -State ____"],
 a:"Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort",
 e:"OwningProcess is a process Id. Look it up with Get-Process -Id <number>.",
 must:["Get-NetTCPConnection"],alt:["netstat"],sh:"ss -tlnp"},
{t:"Copy files or folders",kw:"copy files folder duplicate backup move",
 h:["Copying has a standard verb.","Copy-Item takes a source and a destination. Add -Recurse for folders.","Shape: Copy-Item -Path ____ -Destination ____ -Recurse"],
 a:"Copy-Item -Path C:\\Data -Destination D:\\Backup -Recurse -WhatIf",
 e:"Remove -WhatIf to run for real. For big or repeat copies, robocopy is more robust.",
 must:["Copy-Item"],alt:["robocopy"],sh:"cp -r /data /backup"},
{t:"Find commands or learn how a command works",kw:"help learn how command find which examples documentation what",
 h:["PowerShell documents itself.","Get-Command searches by name. Get-Help explains one command.","Shape: Get-Help ____ -Examples"],
 a:"Get-Help Get-Service -Examples",
 e:"Run Update-Help once as admin to download the full help files.",
 must:["Get-Help"],alt:["Get-Command"],sh:"man ls   or   ls --help"}
];

// ---------- Ask mode ----------
const $=id=>document.getElementById(id);
const stem=w=>w.toLowerCase().replace(/[^a-z0-9]/g,"").replace(/(ing|ed|es|s)$/,"");
const tok=s=>s.split(/\s+/).map(stem).filter(x=>x.length>1);
function score(r,words){const k=new Set(tok(r.kw+" "+r.t));let n=0;words.forEach(w=>{if(k.has(w))n++});return n}
function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}

$("sugg").append(...[0,1,3,7,16].map(i=>{const b=el("button",null,R[i].t);b.onclick=()=>{$("q").value=R[i].t;coach()};return b}));
$("go").onclick=coach;$("q").addEventListener("keydown",e=>{if(e.key==="Enter")coach()});

function coach(){
  const words=tok($("q").value);const out=$("lesson");out.replaceChildren();
  if(!words.length)return;
  const ranked=R.map(r=>({r,s:score(r,words)})).filter(x=>x.s>0).sort((a,b)=>b.s-a.s);
  if(!ranked.length){const c=el("div","card");c.append(el("p",null,"I don't have a guide for that yet. Try these general moves:"),
    el("div","hint","Run Get-Command *word* to search for commands with your keyword in the name."),
    el("div","hint","Run Get-Help <command> -Examples once you find a likely command."));out.append(c);return}
  lesson(ranked[0].r,out);
  if(ranked.length>1){const o=el("p","muted","Other possible matches:");const s=el("div","sugg");
    ranked.slice(1,4).forEach(x=>{const b=el("button",null,x.r.t);b.onclick=()=>{out.replaceChildren();lesson(x.r,out)};s.append(b)});out.append(o,s)}
}

function lesson(r,out){
  const c=el("div","card");c.append(el("div","tag","Goal"),el("h2",null,r.t));
  const hints=el("div");let shown=0;
  const next=el("button","ghost","Give me a hint");
  const show=el("button","ghost","Show the answer");show.style.marginLeft="8px";
  const ans=el("div");
  next.onclick=()=>{
    if(shown>=r.h.length)return;
    const d=el("div","hint");d.append(el("b",null,"Hint "+(shown+1)+" of "+r.h.length+": "));d.append(document.createTextNode(r.h[shown]));
    hints.append(d);shown++;
    next.textContent=shown>=r.h.length?"No more hints":"Another hint";next.disabled=shown>=r.h.length};
  show.onclick=()=>{ans.replaceChildren();ans.append(el("div","tag","Answer (PowerShell)"),el("pre",null,r.a),el("p",null,r.e));
    if(r.sh)ans.append(el("div","tag","Linux/macOS terminal equivalent"),el("pre",null,r.sh));show.disabled=true};
  c.append(hints,next,show,ans);
  // attempt checker
  const t=el("textarea");t.placeholder="Type your own attempt here, then check it...";
  const chk=el("button","primary","Check my attempt");chk.style.marginTop="8px";
  const fb=el("div");
  chk.onclick=()=>{
    fb.replaceChildren();const v=t.value.toLowerCase();if(!v.trim())return;
    const missing=r.must.filter(m=>!v.includes(m.toLowerCase()));
    const altOk=(r.alt||[]).some(a=>v.includes(a.toLowerCase()));
    const p=el("p");
    if(!missing.length){p.className="ok";p.textContent="Looks right. You used "+r.must.join(", ")+". Test it in PowerShell and compare the output with what you expected."}
    else if(altOk){p.className="ok";p.textContent="That is a valid alternative approach. Run it and check the result."}
    else{p.className="warn";p.textContent=(r.must.length-missing.length)+" of "+r.must.length+" key pieces found. You are still missing a piece. Try the next hint, or think about what step takes the result and narrows or orders it."}
    if(/remove-|stop-|restart-|set-/.test(v)&&!/-whatif/.test(v)){fb.append(el("p","warn","Safety: this command changes things. Add -WhatIf first to preview."))}
    fb.prepend(p)};
  const wrap=el("div");wrap.style.marginTop="16px";wrap.append(el("div","tag","Try it yourself"),t,chk,fb);c.append(wrap);out.append(c);
}

// ---------- Builder ----------
const SRC={
 "Get-Process":["Name","Id","CPU","WS","Handles","StartTime"],
 "Get-Service":["Name","DisplayName","Status","StartType"],
 "Get-ChildItem":["Name","Length","LastWriteTime","Extension","FullName"],
 "Get-LocalUser":["Name","Enabled","LastLogon","Description"],
 "Get-NetTCPConnection":["LocalPort","RemoteAddress","State","OwningProcess"],
 "Get-EventLog -LogName System -Newest 200":["EntryType","Source","EventID","TimeGenerated"]};
function fill(sel,arr,blank){sel.replaceChildren();if(blank)sel.append(new Option(blank,""));arr.forEach(x=>sel.append(new Option(x,x)))}
fill($("b-src"),Object.keys(SRC));
function props(){const p=SRC[$("b-src").value];fill($("b-fprop"),p);fill($("b-sprop"),p,"(no sort)")}
const PIECE={"Get-Process":"Get-Process lists running programs.","Get-Service":"Get-Service lists Windows services.","Get-ChildItem":"Get-ChildItem lists files and folders.","Get-LocalUser":"Get-LocalUser lists local accounts.","Get-NetTCPConnection":"Get-NetTCPConnection lists network connections.","Get-EventLog -LogName System -Newest 200":"Get-EventLog reads the System log. -Newest 200 limits it so it stays quick."};
function build(){
  const parts=[];const ex=[];const src=$("b-src").value;parts.push(src);ex.push(PIECE[src]||src);
  const fp=$("b-fprop").value,fo=$("b-fop").value,fv=$("b-fval").value.trim();
  if(fo&&fv){const q=/^(-?\d+(\.\d+)?(KB|MB|GB)?|\$\w+)$/i.test(fv)?fv:"'"+fv.replace(/'/g,"''")+"'";
    parts.push("Where-Object "+fp+" "+fo+" "+q);ex.push("Where-Object keeps only rows where "+fp+" "+fo+" "+q+".")}
  if($("b-sprop").value){const d=$("b-sdir").value;parts.push("Sort-Object "+$("b-sprop").value+d);ex.push("Sort-Object orders the rows by "+$("b-sprop").value+(d?" from biggest to smallest.":" from smallest to biggest."))}
  const n=parseInt($("b-n").value,10);
  const cols=$("b-cols").value.split(",").map(s=>s.trim()).filter(Boolean).join(",");
  if(n>0||cols){parts.push("Select-Object"+(n>0?" -First "+n:"")+(cols?" "+cols:""));ex.push("Select-Object trims the result"+(n>0?" to "+n+" rows":"")+(cols?" and keeps columns "+cols:"")+".")}
  if($("b-out").value){const o=$("b-out").value;parts.push(o);ex.push(o.split(" ")[0]+" controls how the result is shown or saved.")}
  $("b-cmd").textContent=parts.join(" |\n  ");
  const l=$("b-explain");l.replaceChildren();const ul=el("ol");ex.forEach(x=>ul.append(el("li",null,x)));l.append(ul)}
$("b-src").onchange=()=>{props();build()};
["b-fprop","b-fop","b-fval","b-sprop","b-sdir","b-n","b-cols","b-out"].forEach(i=>$(i).addEventListener("input",build));
props();build();

// ---------- Tabs ----------
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll(".tabs button").forEach(x=>x.setAttribute("aria-selected",x===b));
  ["ask","build","tips"].forEach(id=>$(id).hidden=id!==b.dataset.tab)});
