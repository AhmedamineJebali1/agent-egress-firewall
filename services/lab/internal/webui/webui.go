// Package webui holds the firewall's live console. It is a single self
// contained page so the lab needs no asset pipeline and no CDN access.
package webui

// Dashboard is served at the admin root.
const Dashboard = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Egress Firewall</title>
<style>
  :root{
    --bg:#0f1115; --panel:#171a21; --line:#262b36; --fg:#e7eaf0; --muted:#8b93a7;
    --allow:#2ea043; --block:#e5484d; --accent:#4c8dff; --warn:#e2a03f;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{padding:18px 20px;border-bottom:1px solid var(--line);display:flex;
         gap:16px;align-items:center;flex-wrap:wrap}
  h1{font-size:16px;margin:0;letter-spacing:.3px}
  .pill{padding:3px 10px;border-radius:999px;border:1px solid var(--line);
        background:var(--panel);color:var(--muted);font-size:12px}
  .pill b{color:var(--fg)}
  main{padding:16px 20px;max-width:1400px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
  .card .n{font-size:26px;font-weight:600}
  .card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
  .modes{display:flex;gap:8px;flex-wrap:wrap}
  button{background:var(--panel);color:var(--fg);border:1px solid var(--line);
         border-radius:8px;padding:7px 14px;cursor:pointer;font:inherit}
  button:hover{border-color:var(--accent)}
  button.on{background:var(--accent);border-color:var(--accent);color:#fff}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);
        vertical-align:top;white-space:nowrap}
  th{color:var(--muted);font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
  td.wrap{white-space:normal;word-break:break-word;max-width:460px}
  .allow{color:var(--allow)} .block{color:var(--block)} .muted{color:var(--muted)}
  .tag{background:#222733;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:11px}
  .scroll{max-height:62vh;overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
  @media (prefers-color-scheme: light){
    :root:not([data-theme="dark"]){--bg:#f6f7f9;--panel:#fff;--line:#e2e5ea;--fg:#14171f;--muted:#656d7e}
  }
</style></head>
<body>
<header>
  <h1>EGRESS FIREWALL &mdash; live console</h1>
  <span class="pill">mode <b id="mode">?</b></span>
  <span class="pill">scenario <b id="scen">-</b></span>
  <span class="pill">canaries <b id="secrets">?</b></span>
  <div class="modes">
    <button data-m="off">off</button>
    <button data-m="allowlist">allowlist</button>
    <button data-m="full">full</button>
    <button id="reset" style="margin-left:10px">reset log</button>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n" id="c-total">0</div><div class="l">decisions</div></div>
    <div class="card"><div class="n allow" id="c-allow">0</div><div class="l">allowed</div></div>
    <div class="card"><div class="n block" id="c-block">0</div><div class="l">blocked</div></div>
    <div class="card"><div class="n" id="c-dlp">0</div><div class="l">dlp hits</div></div>
  </div>
  <div class="scroll">
  <table>
    <thead><tr><th>#</th><th>time</th><th>scenario</th><th>proto</th><th>destination</th>
    <th>request</th><th>action</th><th>reason</th><th>technique</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  </div>
</main>
<script>
async function tick(){
  try{
    const [s,e] = await Promise.all([
      fetch('status').then(r=>r.json()),
      fetch('events?limit=300').then(r=>r.json())
    ]);
    document.getElementById('mode').textContent = s.mode;
    document.getElementById('scen').textContent = s.scenario || '-';
    document.getElementById('secrets').textContent = s.secrets;
    document.querySelectorAll('button[data-m]').forEach(b=>
      b.classList.toggle('on', b.dataset.m===s.mode));

    const ev = e.events || [];
    let dlp=0, allow=0, block=0;
    for(const x of ev){
      if(x.action==='allow') allow++; else block++;
      if((x.reason||'').startsWith('dlp')) dlp++;
    }
    document.getElementById('c-total').textContent = ev.length;
    document.getElementById('c-allow').textContent = allow;
    document.getElementById('c-block').textContent = block;
    document.getElementById('c-dlp').textContent = dlp;

    const rows = ev.slice().reverse().map(x=>{
      const dest = x.host + (x.port && x.port!=='443' && x.port!=='80' ? ':'+x.port : '');
      const req = x.proto==='dns' ? (x.qtype||'') + ' ' + (x.host||'')
                                  : (x.method||'') + ' ' + (x.path||'');
      const cov = x.coverage ? ' ('+Math.round(x.coverage*100)+'%)' : '';
      return '<tr>'+
        '<td class="muted">'+x.seq+'</td>'+
        '<td class="muted">'+new Date(x.ts).toISOString().substr(11,12)+'</td>'+
        '<td><span class="tag">'+(x.scenario||'-')+'</span></td>'+
        '<td>'+x.proto+(x.inspected?' <span class="tag">tls-mitm</span>':'')+'</td>'+
        '<td>'+esc(dest)+'</td>'+
        '<td class="wrap">'+esc(req)+'</td>'+
        '<td class="'+x.action+'">'+x.action.toUpperCase()+'</td>'+
        '<td class="wrap">'+esc(x.reason)+cov+'</td>'+
        '<td class="wrap muted">'+esc(x.detail||x.technique||'')+'</td>'+
      '</tr>';
    }).join('');
    document.getElementById('rows').innerHTML = rows;
  }catch(err){ /* firewall restarting */ }
}
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
document.querySelectorAll('button[data-m]').forEach(b=>b.onclick=async()=>{
  await fetch('mode?m='+b.dataset.m,{method:'POST'}); tick();
});
document.getElementById('reset').onclick=async()=>{ await fetch('reset',{method:'POST'}); tick(); };
tick(); setInterval(tick, 1500);
</script>
</body></html>
`
