const ADMIN_API_PATH = "/plugins/aegis-admin/api";

const TAB_PATHS = {
  admission: "/plugins/aegis-admission/panel?embed=1",
  reports: "/plugins/aegis-admin/reports?embed=1",
  audit: "/plugins/aegis-admin/audit?embed=1",
  rules: "/plugins/aegis-admin/rules?embed=1",
  mcp: "/plugins/aegis-admin/mcp?embed=1",
};

export function renderSecurityCenterPage(token) {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis 安全中心</title><style>
:root{color-scheme:dark;--bg:#080d18;--panel:#11192a;--card:#151f34;--line:#2b3857;--text:#edf3ff;--muted:#9babc9;--blue:#70adff;--green:#38d995;--red:#ff657d;--amber:#f7c948}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:radial-gradient(circle at 15% 0,#172c50 0,transparent 34%),linear-gradient(145deg,#080d18,#0d1424 58%,#0b1120);color:var(--text);font:14px/1.55 system-ui,"Microsoft YaHei",sans-serif}button{font:inherit}.shell{max-width:1540px;margin:auto;padding:22px}.hero{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:16px}.brand{display:flex;align-items:center;gap:13px}.brand-mark{display:grid;place-items:center;width:46px;height:46px;border:1px solid #4c78b8;border-radius:14px;background:linear-gradient(145deg,#1f4677,#14233d);box-shadow:0 0 28px #4b9bff2b;font-size:23px}.eyebrow{color:var(--blue);font-size:11px;font-weight:900;letter-spacing:.12em}.hero h1{margin:1px 0;font-size:26px}.hero p{margin:0;color:var(--muted)}.release{border:1px solid #326549;background:#102d25;color:#9bf0c9;padding:7px 11px;border-radius:999px;white-space:nowrap}.nav{display:flex;gap:7px;padding:7px;border:1px solid var(--line);border-radius:14px;background:#0d1526;overflow:auto;position:sticky;top:0;z-index:3;box-shadow:0 10px 30px #0005}.nav-button{display:flex;align-items:center;gap:7px;border:0;border-radius:9px;padding:9px 13px;background:transparent;color:#aebbd4;cursor:pointer;white-space:nowrap;font-weight:750}.nav-button:hover{background:#18243a;color:#e8f0ff}.nav-button.active{background:linear-gradient(145deg,#2d68a7,#234d82);color:white;box-shadow:0 6px 16px #05080f88}.content{margin-top:15px}.overview{display:block}.overview.hidden{display:none}.overview-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:7px 1px 14px}.overview-head h2{margin:0;font-size:22px}.overview-head p{margin:3px 0 0;color:var(--muted)}.refresh{border:1px solid #3a5279;background:#17243a;color:#dce8ff;border-radius:9px;padding:8px 12px;cursor:pointer}.refresh:disabled{opacity:.5}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel{border:1px solid var(--line);border-radius:14px;background:linear-gradient(150deg,#162137,#111929);box-shadow:0 12px 28px #0003}.card{padding:17px}.card span{display:block;color:var(--muted);font-size:12px}.card strong{display:block;margin-top:5px;font-size:27px}.allow{color:var(--green)}.block{color:var(--red)}.valid{color:var(--green)}.invalid{color:var(--red)}.panel{margin-top:13px;padding:17px}.panel-head{display:flex;justify-content:space-between;gap:14px;margin-bottom:10px}.panel h3{margin:0}.status{color:var(--muted)}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #293650;text-align:left;vertical-align:top}th{color:#9baccb;font-size:11px}td code{color:#c7d6f2}.empty{text-align:center;color:var(--muted);padding:28px}.footnote{margin-top:11px;color:#7585a5;font-size:11px;text-align:right}@media(max-width:900px){.cards{grid-template-columns:1fr 1fr}.hero{align-items:flex-start;flex-direction:column}}@media(max-width:520px){.shell{padding:12px}.cards{grid-template-columns:1fr}.release{display:none}.nav-button{padding:8px 10px}}
</style></head><body><main class="shell">
<header class="hero"><div class="brand"><div class="brand-mark">⛨</div><div><div class="eyebrow">AEGIS CHAIN × OPENCLAW</div><h1>Aegis 安全中心</h1><p>统一管理安装准入、扫描报告、审计证据、安全规则和 MCP 配置。</p></div></div><div class="release">正式发布版 · 本地安全引擎</div></header>
<nav class="nav" aria-label="安全中心功能导航">
  <button class="nav-button" data-tab="overview">总览</button>
  <button class="nav-button" data-tab="admission">准入扫描</button>
  <button class="nav-button" data-tab="reports">扫描报告</button>
  <button class="nav-button" data-tab="audit">审计记录</button>
  <button class="nav-button" data-tab="rules">规则管理</button>
  <button class="nav-button" data-tab="mcp">MCP 准入</button>
</nav>
<section id="overview" class="content overview">
  <div class="overview-head"><div><h2>安全总览</h2><p>基于本机真实准入审计记录生成，刷新后即时更新。</p></div><button id="refresh" class="refresh">刷新数据</button></div>
  <div class="cards"><article class="card"><span>累计准入请求</span><strong id="metric-total">—</strong></article><article class="card"><span>允许安装</span><strong id="metric-allow" class="allow">—</strong></article><article class="card"><span>安全阻断</span><strong id="metric-block" class="block">—</strong></article><article class="card"><span>审计链完整性</span><strong id="metric-chain">验证中</strong></article></div>
  <article class="panel"><div class="panel-head"><h3>最近审计活动</h3><div id="overview-status" class="status">正在读取安全引擎……</div></div><div class="table-wrap"><table><thead><tr><th>序号 / 时间</th><th>目标</th><th>决策</th><th>处置原因</th><th>耗时</th></tr></thead><tbody id="recent-rows"><tr><td colspan="5" class="empty">正在加载……</td></tr></tbody></table></div></article>
  <div class="footnote">本页面只展示最小化安全元数据，不显示上传源码或凭据。</div>
</section>
</main><script>
const TOKEN=${JSON.stringify(token)},API=${JSON.stringify(ADMIN_API_PATH)},PATHS=${JSON.stringify(TAB_PATHS)},VALID_TABS=new Set(['overview',...Object.keys(PATHS)]);
const overview=document.getElementById('overview'),buttons=Array.from(document.querySelectorAll('[data-tab]'));
let loadedOverview=false;
function esc(value){return String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function formatTime(value){try{return new Date(value).toLocaleString('zh-CN')}catch{return value||'—'}}
async function call(operation,payload={}){const response=await fetch(API,{method:'POST',headers:{'Content-Type':'application/json','X-Aegis-Demo-Token':TOKEN},body:JSON.stringify({operation,...payload})});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error?.message||'读取失败');return result.data}
async function loadOverview(){const refresh=document.getElementById('refresh'),status=document.getElementById('overview-status');refresh.disabled=true;status.textContent='正在读取安全引擎……';try{const [summary,audits]=await Promise.all([call('overview'),call('list_audits',{limit:8})]);document.getElementById('metric-total').textContent=summary.recent_total;document.getElementById('metric-allow').textContent=summary.decision_counts.allow;document.getElementById('metric-block').textContent=summary.decision_counts.block;const chain=document.getElementById('metric-chain');chain.textContent=summary.audit_integrity.valid?'有效 · '+summary.audit_integrity.rows+' 条':'异常';chain.className=summary.audit_integrity.valid?'valid':'invalid';const rows=document.getElementById('recent-rows');rows.innerHTML=(audits.audits||[]).map(row=>'<tr><td><b>#'+esc(row.sequence)+'</b><br><small>'+esc(formatTime(row.created_at))+'</small></td><td>'+esc(row.target_type)+'<br><code>'+esc(row.target_name)+'</code></td><td class="'+(row.decision==='allow'?'allow':'block')+'"><b>'+esc(String(row.decision||'').toUpperCase())+'</b></td><td>'+esc(row.reason_code||'—')+'</td><td>'+esc(row.duration_ms)+' ms</td></tr>').join('')||'<tr><td colspan="5" class="empty">暂无审计记录</td></tr>';status.textContent='审计链 '+(summary.audit_integrity.valid?'有效':'异常')+' · 最近 '+summary.recent_total+' 条';loadedOverview=true}catch(error){status.textContent='读取失败：'+error.message;status.className='status invalid'}finally{refresh.disabled=false}}
function activate(tab,replace=true){if(!VALID_TABS.has(tab))tab='overview';if(tab!=='overview'){location.replace(PATHS[tab]);return}for(const button of buttons){button.classList.toggle('active',button.dataset.tab===tab);button.setAttribute('aria-current',button.dataset.tab===tab?'page':'false')}overview.classList.remove('hidden');if(!loadedOverview)loadOverview();if(replace){const url=new URL(location.href);url.searchParams.delete('tab');history.replaceState(null,'',url)}}
for(const button of buttons)button.addEventListener('click',()=>activate(button.dataset.tab));document.getElementById('refresh').addEventListener('click',loadOverview);window.addEventListener('popstate',()=>activate(new URL(location.href).searchParams.get('tab')||'overview',false));activate(new URL(location.href).searchParams.get('tab')||'overview',false);
</script></body></html>`;
}
