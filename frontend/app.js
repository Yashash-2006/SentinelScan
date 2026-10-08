const $=id=>document.getElementById(id); let currentId=null;
async function api(u,o={}){const r=await fetch(u,o),d=await r.json();if(!r.ok)throw Error(d.error||"Request failed");return d}
$("scanForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/scans",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:$("target").value.trim(),permission:$("permission").checked,delay:+$("delay").value,max_pages:+$("pages").value,timeout:+$("timeout").value})});currentId=d.id;$("progressCard").classList.remove("hidden");$("summary").classList.add("hidden");poll()}catch(x){alert(x.message)}});
async function poll(){const j=await api("/api/scans/"+currentId);$("stage").textContent=j.stage||j.status;$("pct").textContent=(j.progress||0)+"%";$("bar").style.width=(j.progress||0)+"%";if(j.status==="running")return setTimeout(poll,600);if(j.status==="failed")return $("stage").textContent="Scan failed: "+j.error;render(j.report);loadHistory()}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function render(r){$("progressCard").classList.add("hidden");$("summary").classList.remove("hidden");$("resultTarget").textContent=r.target;$("total").textContent=r.summary.total;$("high").textContent=r.summary.by_severity.High;$("medium").textContent=r.summary.by_severity.Medium;$("low").textContent=r.summary.by_severity.Low;$("download").onclick=()=>location.href="/api/scans/"+currentId+"/report";$("findings").innerHTML=r.findings.length?r.findings.map(f=>`<article class="finding"><div class="finding-head"><span class="badge ${f.severity}">${f.severity}</span><h3>${esc(f.title)}</h3></div><div class="finding-meta">${esc(f.owasp)} · ${esc(f.url)} · ${esc(f.check)}</div><code>${esc(f.evidence)}</code><div class="fix"><b>Remediation:</b> ${esc(f.remediation)}</div></article>`).join(""):'<div class="finding"><b>No findings detected.</b><p class="muted">This does not prove the target is secure; coverage is limited.</p></div>'}
async function loadHistory(){const a=await api("/api/scans");$("history").innerHTML=a.length?a.map(r=>`<div class="history-row"><div><b>${esc(r.target)}</b><br><span>${new Date(r.started).toLocaleString()}</span></div><span>${esc(r.status)}</span><b>${r.findings??0} findings</b></div>`).join(""):'<p class="muted">No scans yet.</p>'}loadHistory();

// Sidebar navigation
document.querySelectorAll(".nav-link").forEach(link=>{
  link.addEventListener("click",e=>{
    e.preventDefault();
    const id=link.dataset.section;
    document.querySelectorAll(".nav-link").forEach(x=>x.classList.remove("active"));
    link.classList.add("active");
    if(id==="overview"){
      window.scrollTo({top:0,behavior:"smooth"});
      return;
    }
    const el=document.querySelector('[data-section="'+id+'"]');
    if(el) el.scrollIntoView({behavior:"smooth",block:"start"});
  });
});

$("reportsDownload").addEventListener("click",()=>{
  if(currentId) location.href="/api/scans/"+currentId+"/report";
  else alert("Run a scan first.");
});
