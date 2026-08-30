import { randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  renderAuditPage,
  renderMcpPage,
  renderReportHtml,
  renderReportsPage,
  renderRulesPage,
} from "./admin_pages.js";
import { renderAdmissionPage } from "./admission_page.js";
import { SESSION_TTL_MS, UploadError, UploadSessionStore } from "./upload_sessions.js";

const PANEL_PATH = "/plugins/aegis-admission/panel";
const API_PATH = "/plugins/aegis-admission/api/run";
const REPORTS_PATH = "/plugins/aegis-admin/reports";
const AUDIT_PATH = "/plugins/aegis-admin/audit";
const RULES_PATH = "/plugins/aegis-admin/rules";
const MCP_PATH = "/plugins/aegis-admin/mcp";
const ADMIN_API_PATH = "/plugins/aegis-admin/api";
const REPORT_PDF_PATH = "/plugins/aegis-admin/report.pdf";
const TOKEN_TTL_MS = 30 * 60 * 1000;
const MAX_BODY_BYTES = 4096;
const MAX_ADMIN_BODY_BYTES = 64 * 1024;
const tokens = new Map();
let running = false;

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(JSON.stringify(body));
}

function setSandboxCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", "null");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Aegis-Action, X-Aegis-Token, X-Aegis-Demo-Token, X-Aegis-Session, X-Aegis-Relative-Path");
  res.setHeader("Access-Control-Max-Age", "300");
  res.setHeader("Vary", "Origin");
}

function redactLogLine(value, projectRoot = "") {
  let text = String(value);
  const privateRoots = [
    [process.env.USERPROFILE, "<USER_HOME>"],
    [process.env.HOME, "<USER_HOME>"],
    [projectRoot, "<PROJECT_ROOT>"],
  ];
  for (const [root, replacement] of privateRoots) {
    if (!root) continue;
    text = text.replaceAll(root, replacement).replaceAll(root.replaceAll("\\", "/"), replacement);
  }
  return text
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[REDACTED]")
    .replace(/((?:token|password|api[_-]?key|secret)\s*[:=]\s*)[^\s,;]+/gi, "$1[REDACTED]");
}

function sendStreamEvent(res, event) {
  if (!res.destroyed && !res.writableEnded) res.write(`${JSON.stringify(event)}\n`);
}

function sendHtml(res, html) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.end(html);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function issueToken() {
  const token = randomBytes(32).toString("hex");
  const now = Date.now();
  for (const [key, expiresAt] of tokens) {
    if (expiresAt <= now) tokens.delete(key);
  }
  tokens.set(token, now + TOKEN_TTL_MS);
  return token;
}

function consumeToken(candidate) {
  if (typeof candidate !== "string" || candidate.length !== 64) return false;
  const expiresAt = tokens.get(candidate);
  if (!expiresAt || expiresAt <= Date.now()) {
    tokens.delete(candidate);
    return false;
  }
  const expected = Buffer.from(candidate, "utf8");
  const supplied = Buffer.from(candidate, "utf8");
  if (!timingSafeEqual(expected, supplied)) return false;
  return true;
}

async function readJsonBody(req, maxBytes = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function projectRootFromModule() {
  const pluginRoot = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(pluginRoot, "../../..");
}

function adminRuntime(projectRoot) {
  const candidates = process.platform === "win32"
    ? [
        path.join(projectRoot, ".runtime_mcp313", "Scripts", "python.exe"),
        path.join(projectRoot, ".runtime_mcp313", "python.exe"),
      ]
    : [path.join(projectRoot, ".runtime_mcp313", "bin", "python")];
  const runtime = candidates.find((candidate) => existsSync(candidate));
  if (!runtime) throw new Error("Aegis MCP administrator runtime is unavailable.");
  return runtime;
}

async function runAdminOperation(projectRoot, request) {
  const python = adminRuntime(projectRoot);
  const script = path.join(projectRoot, "demo_web", "tools", "openclaw_admin_cli.py");
  return await new Promise((resolve, reject) => {
    const child = spawn(python, [script], {
      cwd: projectRoot,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        PYTHONUTF8: "1",
        PYTHONIOENCODING: "utf-8",
        // The installer writes the install-policy configuration to these same
        // project-local paths. Do not inherit stale service-level variables.
        AEGIS_CUSTOM_RULES_PATH: path.join(projectRoot, "demo_web", "data", "openclaw-final", "custom_rules.json"),
        AEGIS_OPENCLAW_AUDIT_DB: path.join(projectRoot, "demo_web", "data", "openclaw-final", "admission_audit.db"),
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 4 * 1024 * 1024) child.kill();
    });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    // MCP admission invokes OpenClaw's official `mcp set` and `mcp show`
    // commands in sequence. Cold Windows/Node starts take longer than the
    // ordinary administration operations.
    const operationTimeoutMs = request?.operation === "admit_mcp" ? 90_000 : 30_000;
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Aegis administrator operation timed out after ${operationTimeoutMs / 1000}s.`));
    }, operationTimeoutMs);
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", () => {
      clearTimeout(timeout);
      try {
        const result = JSON.parse(stdout.trim());
        if (!result.ok) reject(new Error(result.error?.message || "Administrator operation failed."));
        else resolve(result);
      } catch (error) {
        reject(new Error(`Administrator operation returned invalid JSON: ${error.message}; ${stderr.slice(-300)}`));
      }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

function edgeExecutable() {
  const candidates = [
    path.join(process.env["ProgramFiles(x86)"] || "", "Microsoft", "Edge", "Application", "msedge.exe"),
    path.join(process.env.ProgramFiles || "", "Microsoft", "Edge", "Application", "msedge.exe"),
  ];
  return candidates.find((candidate) => candidate && path.isAbsolute(candidate) && existsSync(candidate));
}

async function renderPdf(html) {
  const edge = edgeExecutable();
  if (!edge) throw new Error("Microsoft Edge is required to export PDF on Windows.");
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), "aegis-report-"));
  const htmlPath = path.join(temporaryRoot, "report.html");
  const pdfPath = path.join(temporaryRoot, "report.pdf");
  writeFileSync(htmlPath, html, "utf8");
  try {
    await new Promise((resolve, reject) => {
      const child = spawn(edge, [
        "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
        `--user-data-dir=${path.join(temporaryRoot, "profile")}`,
        `--print-to-pdf=${pdfPath}`,
        pathToFileURL(htmlPath).href,
      ], { windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      const timeout = setTimeout(() => { child.kill(); reject(new Error("PDF rendering timed out.")); }, 30_000);
      child.once("error", (error) => { clearTimeout(timeout); reject(error); });
      child.once("close", (code) => {
        clearTimeout(timeout);
        if (code !== 0 || !existsSync(pdfPath)) reject(new Error(`PDF rendering failed (${code}): ${stderr.slice(-300)}`));
        else resolve();
      });
    });
    return readFileSync(pdfPath);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function readSampleText(projectRoot, caseId) {
  const sample = path.join(projectRoot, "datasets", "skilltrustbench_v1_0", "full", "cases", caseId, "SKILL.md");
  return readFileSync(sample, "utf8");
}

function renderPanel(projectRoot, token) {
  const safeText = escapeHtml(readSampleText(projectRoot, "case_00906"));
  const maliciousText = escapeHtml(readSampleText(projectRoot, "case_01084"));
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Skill 准入</title><style>
:root{color-scheme:dark;--bg:#0b1020;--card:#141b2d;--line:#2b3654;--text:#e9eefc;--muted:#9ca9c8;--green:#39d98a;--red:#ff647c;--blue:#66a6ff}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#0b1020,#10182b);color:var(--text);font:14px/1.55 system-ui,"Microsoft YaHei",sans-serif}.wrap{max-width:1500px;margin:auto;padding:24px}.hero{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:18px}.eyebrow{color:var(--blue);font-weight:700;letter-spacing:.08em}.hero h1{margin:4px 0;font-size:28px}.hero p{margin:0;color:var(--muted)}.badge{border:1px solid #31558e;background:#142849;color:#a9cbff;padding:7px 12px;border-radius:999px;white-space:nowrap}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.card{background:rgba(20,27,45,.96);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 12px 34px #0004}.card.safe{border-top:3px solid var(--green)}.card.bad{border-top:3px solid var(--red)}h2{margin:0 0 6px;font-size:19px}.meta{color:var(--muted);margin-bottom:12px}.facts{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.fact{background:#0d1425;border:1px solid var(--line);padding:5px 9px;border-radius:8px;font-size:12px}button{width:100%;border:0;border-radius:10px;padding:12px 16px;color:#07131a;font-weight:800;cursor:pointer;font-size:15px}button:disabled{opacity:.45;cursor:wait}.safe button{background:var(--green)}.bad button{background:var(--red);color:white}.result{margin-top:12px;min-height:116px;background:#0a1020;border:1px solid var(--line);border-radius:10px;padding:12px;white-space:pre-wrap}.result.idle{color:var(--muted)}details{margin-top:12px}summary{cursor:pointer;color:#b9c7e6}pre{max-height:330px;overflow:auto;background:#090e1b;border:1px solid #25304a;border-radius:9px;padding:12px;white-space:pre-wrap;font:12px/1.5 Consolas,monospace}.flow{margin:16px 0;padding:13px 16px;border:1px solid var(--line);border-radius:12px;background:#10182a;color:#cbd6ef}.arrow{color:var(--blue);padding:0 5px}.terminal-card{margin-top:18px;background:#070b13;border:1px solid #33415f;border-radius:14px;overflow:hidden;box-shadow:0 14px 40px #0006}.terminal-head{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;background:#11192a;border-bottom:1px solid #293650}.terminal-title{display:flex;align-items:center;gap:9px;font-weight:700}.lights{display:flex;gap:6px}.light{width:10px;height:10px;border-radius:50%}.light.r{background:#ff647c}.light.y{background:#f7c948}.light.g{background:#39d98a}.terminal-state{color:var(--muted);font-size:12px}.progress-track{height:4px;background:#111827}.progress-bar{display:block;width:0;height:100%;background:linear-gradient(90deg,var(--blue),var(--green));transition:width .35s ease}.terminal{height:360px;overflow:auto;margin:0;border:0;border-radius:0;background:#070b13;color:#c8d5ef;padding:15px;font:12px/1.65 Consolas,"Cascadia Mono",monospace;white-space:pre-wrap}.evidence{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;padding:12px 14px;background:#0d1422;border-top:1px solid #293650}.evidence div{background:#111b2e;border:1px solid #293650;border-radius:8px;padding:8px}.evidence b{display:block;color:#8fa4cc;font-size:11px}.evidence span{display:block;margin-top:3px;word-break:break-all}.running-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--blue);box-shadow:0 0 12px var(--blue)}@media(max-width:850px){.grid{grid-template-columns:1fr}.hero{align-items:start;flex-direction:column}.evidence{grid-template-columns:1fr 1fr}}
</style></head><body><main class="wrap">
<div class="hero"><div><div class="eyebrow">AEGIS CHAIN × OPENCLAW</div><h1>第三方 Skill 安装前安全准入</h1><p>同一业务主程序，两种供应链包；点击后触发真实 OpenClaw 安装流程。</p></div><div class="badge">静态审计 + Docker 隔离试运行</div></div>
<div class="flow">Web 控制台 <span class="arrow">→</span> openclaw skills install <span class="arrow">→</span> security.installPolicy <span class="arrow">→</span> ALLOW / BLOCK <span class="arrow">→</span> 审计留痕</div>
<section class="grid">
<article class="card safe"><h2>正常 Skill · case_00906</h2><div class="meta">meeting-notes-generator｜权威公开数据集 SkillTrustBench</div><div class="facts"><span class="fact">预期：ALLOW</span><span class="fact">动态：必须通过</span><span class="fact">网络：禁用</span><span class="fact">GPU：不使用</span></div><button data-case="safe">安装安全 Skill</button><div id="safe-result" class="result idle">等待触发。通过后会真实安装到 OpenClaw workspace。</div><details><summary>查看正常 Skill 本体（SKILL.md）</summary><pre>${safeText}</pre></details></article>
<article class="card bad"><h2>恶意同名变体 · case_01084</h2><div class="meta">主程序哈希相同，但指令被篡改并夹带隐藏工具覆盖脚本</div><div class="facts"><span class="fact">预期：BLOCK</span><span class="fact">风险：T01/T04/T07</span><span class="fact">动态执行：0 次</span><span class="fact">安装残留：0</span></div><button data-case="malicious">阻断恶意 Skill</button><div id="malicious-result" class="result idle">等待触发。命中静态阻断规则后不会进入容器执行。</div><details><summary>查看恶意 Skill 本体（SKILL.md）</summary><pre>${maliciousText}</pre></details></article>
</section>
<section class="terminal-card" aria-label="实时执行终端">
  <div class="terminal-head"><div class="terminal-title"><span class="lights"><span class="light r"></span><span class="light y"></span><span class="light g"></span></span>Aegis 原始执行日志</div><div id="terminal-state" class="terminal-state">等待运行</div></div><div class="progress-track"><span id="progress-bar" class="progress-bar"></span></div>
  <pre id="terminal-output" class="terminal">$ 等待选择上方演示样本……</pre>
  <div class="evidence"><div><b>数据集样本</b><span id="ev-case">—</span></div><div><b>最终决策</b><span id="ev-decision">—</span></div><div><b>安装状态</b><span id="ev-install">—</span></div><div><b>端到端耗时</b><span id="ev-duration">—</span></div><div><b>静态命中规则</b><span id="ev-rules">—</span></div><div><b>动态审计结论</b><span id="ev-dynamic">—</span></div><div><b>审计哈希链</b><span id="ev-chain">—</span></div><div><b>主程序 SHA-256</b><span id="ev-hash">—</span></div></div>
</section></main><script>
const token=${JSON.stringify(token)};
function format(r){const ok=r.accepted?'✅':'❌';const lines=[ok+' '+r.title,'决策：'+r.decision,'OpenClaw 安装：'+(r.installed?'成功':'未安装'),'静态规则：'+(r.finding_rule_ids||[]).filter(x=>!x.startsWith('AEGIS_DYNAMIC_')).join(', '),'动态结论：'+r.dynamic_summary,'耗时：'+r.duration_ms+' ms','审计链：'+(r.audit_chain_valid?'有效':'未验证')];if(r.error)lines.push('错误：'+r.error);return lines.join('\\n')}
const terminal=document.getElementById('terminal-output'),terminalState=document.getElementById('terminal-state'),progressBar=document.getElementById('progress-bar');
function appendLog(line){if(terminal.textContent)terminal.textContent+=String.fromCharCode(10);terminal.textContent+=line;const match=line.match(/\\[STEP (\\d)\\/6\\]/);if(match){const step=Number(match[1]);progressBar.style.width=(step/6*100)+'%';terminalState.innerHTML='<span class="running-dot"></span> 步骤 '+step+'/6'}terminal.scrollTop=terminal.scrollHeight}
function updateEvidence(r){const staticRules=(r.finding_rule_ids||[]).filter(x=>!x.startsWith('AEGIS_DYNAMIC_'));document.getElementById('ev-case').textContent=r.case_id||'—';document.getElementById('ev-decision').textContent=r.decision;document.getElementById('ev-install').textContent=r.installed?'已安装':'未安装';document.getElementById('ev-duration').textContent=r.duration_ms+' ms';document.getElementById('ev-rules').textContent=staticRules.join(', ')||'无阻断规则';document.getElementById('ev-dynamic').textContent=r.dynamic_summary||'—';document.getElementById('ev-chain').textContent=r.audit_chain_valid?'有效':'无效/未验证';document.getElementById('ev-hash').textContent=r.main_program_sha256||'—'}
async function run(button){const scenario=button.dataset.case,box=document.getElementById(scenario+'-result');for(const b of document.querySelectorAll('button[data-case]'))b.disabled=true;box.className='result';box.textContent='正在执行真实准入扫描，请查看下方终端……';terminal.textContent='';progressBar.style.width='2%';terminalState.innerHTML='<span class="running-dot"></span> 运行中 · '+(scenario==='safe'?'安全 Skill':'恶意 Skill');appendLog('[UI] OpenClaw Control UI submitted scenario='+scenario);try{const response=await fetch('${API_PATH}',{method:'POST',headers:{'Content-Type':'application/json','X-Aegis-Demo-Token':token},body:JSON.stringify({scenario})});if(!response.ok){let message='请求失败';try{message=(await response.json()).error||message}catch{}throw new Error(message)}if(!response.body)throw new Error('浏览器不支持流式响应');const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='',finalResult=null;while(true){const chunk=await reader.read();if(chunk.done)break;buffer+=decoder.decode(chunk.value,{stream:true});const lines=buffer.split(String.fromCharCode(10));buffer=lines.pop()||'';for(const line of lines){if(!line.trim())continue;const event=JSON.parse(line);if(event.type==='log'||event.type==='heartbeat')appendLog(event.line);if(event.type==='result'){finalResult=event.result;appendLog('[RESULT] decision='+finalResult.decision+' installed='+finalResult.installed+' audit_chain_valid='+finalResult.audit_chain_valid)}}}if(!finalResult)throw new Error('扫描结束但缺少最终结果');box.textContent=format(finalResult);box.style.borderColor=finalResult.accepted?'var(--green)':'var(--red)';progressBar.style.width='100%';terminalState.textContent=finalResult.accepted?'已完成 · 证据已验证':'执行失败';updateEvidence(finalResult)}catch(error){box.textContent='❌ '+error.message;box.style.borderColor='var(--red)';appendLog('[ERROR] '+error.message);progressBar.style.background='var(--red)';terminalState.textContent='失败关闭'}finally{for(const b of document.querySelectorAll('button[data-case]'))b.disabled=false}}
for(const button of document.querySelectorAll('button[data-case]'))button.addEventListener('click',()=>run(button));
</script></body></html>`;
}

async function runScenario(projectRoot, scenario, onEvent) {
  const runner = path.join(projectRoot, "demo_web", "run_openclaw_web_case.ps1");
  return await new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-File", runner, "-Scenario", scenario, "-ProjectRoot", projectRoot,
    ], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderrBuffer = "";
    const startedAt = Date.now();
    const emitStderrLines = (flush = false) => {
      const parts = stderrBuffer.split(/\r?\n/u);
      const tail = parts.pop() ?? "";
      const complete = flush ? parts.concat(tail ? [tail] : []) : parts;
      stderrBuffer = flush ? "" : tail;
      for (const line of complete) if (line.trim()) onEvent({ type: "log", line: redactLogLine(line, projectRoot) });
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderrBuffer += chunk; emitStderrLines(false); });
    const heartbeat = setInterval(() => {
      const seconds = Math.floor((Date.now() - startedAt) / 1000);
      onEvent({ type: "heartbeat", line: `[gateway] process running; elapsed=${seconds}s` });
    }, 5000);
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Admission run exceeded 180 seconds and was terminated."));
    }, 180_000);
    child.once("error", (error) => { clearInterval(heartbeat); clearTimeout(timeout); reject(error); });
    child.once("close", (code) => {
      clearInterval(heartbeat);
      clearTimeout(timeout);
      emitStderrLines(true);
      try {
        const result = JSON.parse(stdout.trim());
        if (code !== 0 && !result.accepted) reject(new Error(result.error || `Runner exited with code ${code}`));
        else resolve(result);
      } catch (error) { reject(new Error(`Runner returned invalid JSON: ${error.message}`)); }
    });
  });
}

async function runUploadedSkillOperation(projectRoot, request, onEvent = () => {}) {
  const python = adminRuntime(projectRoot);
  const script = path.join(projectRoot, "demo_web", "tools", "openclaw_uploaded_skill_cli.py");
  return await new Promise((resolve, reject) => {
    const child = spawn(python, [script], {
      cwd: projectRoot,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        PYTHONUTF8: "1",
        PYTHONIOENCODING: "utf-8",
        AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS: "60",
        AEGIS_OPENCLAW_REVIEW_MODE: "block",
        AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY: "required",
        AEGIS_CUSTOM_RULES_PATH: path.join(projectRoot, "demo_web", "data", "openclaw-final", "custom_rules.json"),
        AEGIS_OPENCLAW_AUDIT_DB: path.join(projectRoot, "demo_web", "data", "openclaw-final", "admission_audit.db"),
        DOCKER_CONFIG: path.join(process.env.USERPROFILE || os.homedir(), ".docker"),
      },
    });
    let stdout = "";
    let stderrBuffer = "";
    const flushLogs = (flush = false) => {
      const parts = stderrBuffer.split(/\r?\n/u);
      const tail = parts.pop() ?? "";
      const complete = flush ? parts.concat(tail ? [tail] : []) : parts;
      stderrBuffer = flush ? "" : tail;
      for (const line of complete) if (line.trim()) onEvent({ type: "log", line: redactLogLine(line, projectRoot) });
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 4 * 1024 * 1024) child.kill();
    });
    child.stderr.on("data", (chunk) => { stderrBuffer += chunk; flushLogs(false); });
    const timeoutMs = request?.operation === "prepare_scan" ? 180_000 : 30_000;
    const heartbeat = setInterval(() => onEvent({ type: "heartbeat", line: "[gateway] 安全引擎仍在运行……" }), 5_000);
    const timeout = setTimeout(() => {
      child.kill();
      reject(new UploadError("ENGINE_TIMEOUT", "安全引擎执行超时，已失败关闭。", 504));
    }, timeoutMs);
    child.once("error", (error) => { clearInterval(heartbeat); clearTimeout(timeout); reject(error); });
    child.once("close", () => {
      clearInterval(heartbeat);
      clearTimeout(timeout);
      flushLogs(true);
      try {
        const result = JSON.parse(stdout.trim());
        if (!result.ok) reject(new UploadError(result.error?.code || "ENGINE_FAILED", result.error?.message || "安全引擎执行失败。"));
        else resolve(result.data);
      } catch (error) {
        if (error instanceof UploadError) reject(error);
        else reject(new UploadError("ENGINE_RESPONSE_INVALID", `安全引擎返回无效结果：${error.message}`));
      }
    });
    child.stdin.end(JSON.stringify(request));
  });
}

function openclawRuntime() {
  const node = process.platform === "win32"
    ? path.join(process.env.ProgramFiles || "C:\\Program Files", "nodejs", "node.exe")
    : process.execPath;
  const module = process.env.AEGIS_OPENCLAW_MJS
    || path.join(process.env.APPDATA || "", "npm", "node_modules", "openclaw", "openclaw.mjs");
  if (!existsSync(node) || !existsSync(module)) {
    throw new UploadError("OPENCLAW_RUNTIME_MISSING", "OpenClaw CLI 运行时不可用。", 503);
  }
  return { node, module };
}

async function runOpenClaw(projectRoot, args, onEvent = () => {}, timeoutMs = 180_000) {
  const runtime = openclawRuntime();
  return await new Promise((resolve, reject) => {
    const child = spawn(runtime.node, [runtime.module, ...args], {
      cwd: projectRoot,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const emit = (channel, chunk) => {
      const text = redactLogLine(chunk, projectRoot);
      for (const line of text.split(/\r?\n/u)) if (line.trim()) onEvent({ type: "log", line: `[openclaw:${channel}] ${line}` });
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; emit("stdout", chunk); });
    child.stderr.on("data", (chunk) => { stderr += chunk; emit("stderr", chunk); });
    const timeout = setTimeout(() => { child.kill(); reject(new UploadError("OPENCLAW_TIMEOUT", "OpenClaw 命令执行超时。", 504)); }, timeoutMs);
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (code) => {
      clearTimeout(timeout);
      resolve({ code: Number(code ?? 1), stdout, stderr });
    });
  });
}

async function resolveWorkspace(projectRoot) {
  const completed = await runOpenClaw(projectRoot, ["config", "get", "agents.defaults.workspace", "--json"], () => {}, 30_000);
  if (completed.code !== 0) throw new UploadError("WORKSPACE_UNAVAILABLE", "无法读取 OpenClaw 默认工作区。", 503);
  let value;
  try { value = JSON.parse(completed.stdout.trim()); } catch { value = completed.stdout.trim(); }
  if (value && typeof value === "object") value = value.value ?? value.path;
  if (typeof value !== "string" || !path.isAbsolute(value)) throw new UploadError("WORKSPACE_INVALID", "OpenClaw 默认工作区路径无效。", 503);
  return path.resolve(value);
}

async function resolveInstallContext(projectRoot, session) {
  const workspace = await resolveWorkspace(projectRoot);
  const skillsRoot = path.resolve(workspace, "skills");
  const destination = path.resolve(skillsRoot, session.targetName);
  if (path.dirname(destination).toLowerCase() !== skillsRoot.toLowerCase()) {
    throw new UploadError("INSTALL_PATH_DENIED", "安装目标超出 OpenClaw Skill 目录。", 400);
  }
  return { skillsRoot, destination, existed: existsSync(destination) };
}

async function installUploadedSkill(projectRoot, session, installContext, onEvent) {
  const verification = await runUploadedSkillOperation(projectRoot, {
    operation: "verify",
    source_root: session.sourceRoot,
    expected_sha256: session.scan.source_tree_sha256,
  }, onEvent);
  onEvent({ type: "log", line: `[verify] 扫描指纹复核通过 ${verification.source_tree_sha256}` });
  const { skillsRoot, destination, existed } = installContext;
  const backup = path.join(skillsRoot, `.aegis-backup-${session.targetName}-${randomBytes(6).toString("hex")}`);
  let backedUp = false;
  try {
    if (existed) {
      renameSync(destination, backup);
      backedUp = true;
      onEvent({ type: "log", line: "[transaction] 已暂存原版本；安装失败时将自动恢复。" });
    }
    onEvent({ type: "log", line: "[install] 调用 OpenClaw skills install；原生 installPolicy 将执行第二次安全复扫。" });
    const completed = await runOpenClaw(
      projectRoot,
      ["skills", "install", session.sourceRoot, "--as", session.targetName],
      onEvent,
    );
    if (completed.code !== 0 || !existsSync(destination)) {
      throw new UploadError("INSTALL_FAILED", "OpenClaw 未完成安装，原版本（如有）将恢复。", 500);
    }
    const audits = await runAdminOperation(projectRoot, { operation: "list_audits", limit: 10 });
    const matching = audits.data?.audits?.find((item) =>
      item.target_type === "skill"
      && item.target_name === session.targetName
      && item.source_tree_sha256 === session.scan.source_tree_sha256
      && item.decision === "allow"
    );
    if (!matching || audits.data?.integrity?.valid !== true) {
      throw new UploadError("INSTALL_EVIDENCE_MISSING", "安装完成但未找到有效的 ALLOW 审计证据，已按失败关闭处理。", 500);
    }
    if (backedUp) rmSync(backup, { recursive: true, force: true });
    session.installed = true;
    session.state = "installed";
    return {
      installed: true,
      updated: existed,
      target_name: session.targetName,
      install_path: destination,
      source_tree_sha256: session.scan.source_tree_sha256,
      audit: matching,
      audit_integrity: audits.data.integrity,
    };
  } catch (error) {
    if (backedUp) {
      if (existsSync(destination)) rmSync(destination, { recursive: true, force: true });
      if (existsSync(backup)) renameSync(backup, destination);
      onEvent({ type: "log", line: "[rollback] 安装未成功，原 Skill 已恢复。" });
    } else if (!existed && existsSync(destination)) {
      rmSync(destination, { recursive: true, force: true });
      onEvent({ type: "log", line: "[rollback] 已清理未获有效审计证据的安装目录。" });
    }
    throw error;
  }
}

export default definePluginEntry({
  id: "aegis-admission-ui",
  name: "Aegis Chain 供应链安全",
  description: "OpenClaw 安装前准入、报告、审计与安全规则管理。",
  register(api) {
    const projectRoot = projectRootFromModule();
    const uploadsRoot = path.join(projectRoot, "demo_web", "data", "openclaw-final", "uploads");
    const uploadStore = new UploadSessionStore(uploadsRoot);
    api.session.controls.registerControlUiDescriptor({
      surface: "tab", id: "admission", label: "Aegis 准入", description: "Skill 安装前安全审计", icon: "shield", group: "control", order: 35, path: PANEL_PATH,
    });
    api.session.controls.registerControlUiDescriptor({
      surface: "tab", id: "reports", label: "Aegis 报告", description: "查看并导出安装前安全报告", icon: "file-text", group: "control", order: 36, path: REPORTS_PATH,
    });
    api.session.controls.registerControlUiDescriptor({
      surface: "tab", id: "audit", label: "Aegis 审计", description: "核验安装和规则变更哈希链", icon: "history", group: "control", order: 37, path: AUDIT_PATH,
    });
    api.session.controls.registerControlUiDescriptor({
      surface: "tab", id: "rules", label: "Aegis 规则", description: "管理结构化规则与 YARA", icon: "sliders", group: "control", order: 38, path: RULES_PATH,
    });
    api.session.controls.registerControlUiDescriptor({
      surface: "tab", id: "mcp-admission", label: "Aegis MCP", description: "MCP 配置提交前扫描", icon: "server", group: "control", order: 39, path: MCP_PATH,
    });
    api.registerHttpRoute({ path: PANEL_PATH, auth: "plugin", match: "exact", handler: async (req, res) => {
      if ((req.method ?? "GET").toUpperCase() !== "GET") { res.statusCode = 405; res.end("Method Not Allowed"); return true; }
      try { sendHtml(res, renderAdmissionPage(issueToken())); } catch (error) { sendJson(res, 500, { error: String(error) }); }
      return true;
    }});
    api.registerHttpRoute({ path: API_PATH, auth: "plugin", match: "exact", handler: async (req, res) => {
      const method = (req.method ?? "GET").toUpperCase();
      const origin = String(req.headers.origin ?? "");
      if (origin && origin !== "null") { sendJson(res, 403, { error: "不允许的浏览器来源。" }); return true; }
      setSandboxCorsHeaders(res);
      if (method === "OPTIONS") { res.statusCode = 204; res.end(); return true; }
      if (method !== "POST") { res.statusCode = 405; res.end("Method Not Allowed"); return true; }
      if (!consumeToken(req.headers["x-aegis-token"])) { sendJson(res, 403, { error: { code: "TOKEN_INVALID", message: "页面令牌无效或已过期，请刷新页面。" } }); return true; }
      const action = String(req.headers["x-aegis-action"] ?? "").toLowerCase();
      let activeSession = null;
      let ownsRunning = false;
      let installContext = null;
      try {
        if (action === "create") {
          if (!String(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) throw new UploadError("CONTENT_TYPE_INVALID", "创建会话仅接受 JSON。", 415);
          const body = await readJsonBody(req);
          const session = uploadStore.create({ sourceKind: body.source_kind, targetName: body.target_name, displayName: body.display_name });
          sendJson(res, 201, { ok: true, data: { session_id: session.id, expires_in_seconds: Math.floor(SESSION_TTL_MS / 1000) } });
          return true;
        }
        if (action === "upload") {
          if (!String(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/octet-stream")) throw new UploadError("CONTENT_TYPE_INVALID", "文件上传仅接受二进制流。", 415);
          const session = uploadStore.get(req.headers["x-aegis-session"]);
          const progress = await uploadStore.receiveFile(req, session, req.headers["x-aegis-relative-path"]);
          sendJson(res, 200, { ok: true, data: progress });
          return true;
        }
        if (action === "cancel") {
          const body = await readJsonBody(req);
          const session = uploadStore.get(body.session_id);
          if (session.running) throw new UploadError("SESSION_BUSY", "扫描或安装运行中，不能取消会话。", 409);
          uploadStore.remove(session.id);
          sendJson(res, 200, { ok: true, data: { removed: true } });
          return true;
        }
        if (action !== "scan" && action !== "install") throw new UploadError("ACTION_INVALID", "不支持的准入操作。", 400);
        if (!String(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) throw new UploadError("CONTENT_TYPE_INVALID", "扫描与安装仅接受 JSON。", 415);
        const body = await readJsonBody(req);
        const session = uploadStore.get(body.session_id);
        activeSession = session;
        if (running || session.running) throw new UploadError("ENGINE_BUSY", "已有准入任务正在运行，请稍后重试。", 409);
        if (action === "scan" && (session.state !== "uploading" || session.fileCount < 1)) throw new UploadError("UPLOAD_INCOMPLETE", "上传尚未完成或该会话已扫描。", 409);
        if (action === "install" && (session.state !== "scanned" || session.scan?.install_eligible !== true || !session.sourceRoot)) throw new UploadError("INSTALL_NOT_ELIGIBLE", "当前会话没有有效的 ALLOW 安装资格。", 409);
        if (action === "install") {
          installContext = await resolveInstallContext(projectRoot, session);
          if (installContext.existed && body.overwrite_confirmed !== true) {
            sendJson(res, 200, { ok: true, data: { installed: false, requires_confirmation: true } });
            return true;
          }
        }
        running = true;
        session.running = true;
        ownsRunning = true;
        session.state = action === "scan" ? "scanning" : "installing";
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
        res.setHeader("Cache-Control", "no-store, no-transform");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Accel-Buffering", "no");
        res.flushHeaders?.();
        let result;
        if (action === "scan") {
          sendStreamEvent(res, { type: "progress", percent: 40 });
          sendStreamEvent(res, { type: "log", line: `[gateway] 已接收正式上传会话 ${session.id}；开始静态与动态审计。` });
          const engine = await runUploadedSkillOperation(projectRoot, {
            operation: "prepare_scan",
            session_root: session.root,
            uploads_root: uploadsRoot,
            source_kind: session.sourceKind,
            target_name: session.targetName,
          }, (event) => sendStreamEvent(res, event));
          session.sourceRoot = engine.source_root;
          result = { ...engine, source_root: undefined, session_id: session.id };
          session.scan = result;
          session.state = result.install_eligible ? "scanned" : "blocked";
          sendStreamEvent(res, { type: "progress", percent: 100 });
        } else {
          sendStreamEvent(res, { type: "progress", percent: 10 });
          result = await installUploadedSkill(projectRoot, session, installContext, (event) => sendStreamEvent(res, event));
          sendStreamEvent(res, { type: "progress", percent: 100 });
        }
        sendStreamEvent(res, { type: "result", result });
        res.end();
      } catch (error) {
        if (ownsRunning && activeSession && !activeSession.installed) {
          activeSession.state = action === "scan" ? "failed" : "scanned";
        }
        const detail = error?.stdout?.toString?.().trim() || error?.stderr?.toString?.().trim() || error?.message || String(error);
        if (res.headersSent) {
          sendStreamEvent(res, { type: "log", line: `[ERROR] ${redactLogLine(detail, projectRoot)}` });
          sendStreamEvent(res, { type: "error", error: { code: error?.code || "ADMISSION_FAILED", message: redactLogLine(detail, projectRoot) } });
          res.end();
        } else sendJson(res, Number(error?.status || 500), { ok: false, error: { code: error?.code || "ADMISSION_FAILED", message: redactLogLine(detail, projectRoot) } });
      } finally {
        if (ownsRunning && activeSession) {
          activeSession.running = false;
          running = false;
        }
      }
      return true;
    }});
    for (const [routePath, renderer] of [
      [REPORTS_PATH, renderReportsPage],
      [AUDIT_PATH, renderAuditPage],
      [RULES_PATH, renderRulesPage],
      [MCP_PATH, renderMcpPage],
    ]) {
      api.registerHttpRoute({ path: routePath, auth: "plugin", match: "exact", handler: async (req, res) => {
        if ((req.method ?? "GET").toUpperCase() !== "GET") { res.statusCode = 405; res.end("Method Not Allowed"); return true; }
        try { sendHtml(res, renderer(issueToken())); } catch (error) { sendJson(res, 500, { error: String(error) }); }
        return true;
      }});
    }
    api.registerHttpRoute({ path: ADMIN_API_PATH, auth: "plugin", match: "exact", handler: async (req, res) => {
      const method = (req.method ?? "GET").toUpperCase();
      const origin = String(req.headers.origin ?? "");
      if (origin && origin !== "null") { sendJson(res, 403, { ok: false, error: { message: "不允许的浏览器来源。" } }); return true; }
      setSandboxCorsHeaders(res);
      if (method === "OPTIONS") { res.statusCode = 204; res.end(); return true; }
      if (method !== "POST") { res.statusCode = 405; res.end("Method Not Allowed"); return true; }
      if (!consumeToken(req.headers["x-aegis-demo-token"])) { sendJson(res, 403, { ok: false, error: { message: "页面令牌无效或已过期，请刷新页面。" } }); return true; }
      if (!String(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) { sendJson(res, 415, { ok: false, error: { message: "仅接受 JSON 请求。" } }); return true; }
      try {
        const body = await readJsonBody(req, MAX_ADMIN_BODY_BYTES);
        const result = await runAdminOperation(projectRoot, body);
        sendJson(res, 200, result);
      } catch (error) {
        sendJson(res, 400, { ok: false, error: { message: String(error?.message || error).slice(0, 500) } });
      }
      return true;
    }});
    api.registerHttpRoute({ path: REPORT_PDF_PATH, auth: "plugin", match: "exact", handler: async (req, res) => {
      const method = (req.method ?? "GET").toUpperCase();
      const origin = String(req.headers.origin ?? "");
      if (origin && origin !== "null") { sendJson(res, 403, { ok: false, error: { message: "不允许的浏览器来源。" } }); return true; }
      setSandboxCorsHeaders(res);
      if (method === "OPTIONS") { res.statusCode = 204; res.end(); return true; }
      if (method !== "POST") { res.statusCode = 405; res.end("Method Not Allowed"); return true; }
      if (!consumeToken(req.headers["x-aegis-demo-token"])) { sendJson(res, 403, { ok: false, error: { message: "页面令牌无效或已过期，请刷新页面。" } }); return true; }
      try {
        const body = await readJsonBody(req, MAX_BODY_BYTES);
        const sequence = Number(body?.sequence);
        if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("审计序号无效。");
        const result = await runAdminOperation(projectRoot, { operation: "get_audit", sequence });
        const pdf = await renderPdf(renderReportHtml(result.data.audit, result.data.integrity));
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="Aegis-Admission-${sequence}.pdf"`);
        res.setHeader("Content-Length", String(pdf.length));
        res.setHeader("Cache-Control", "no-store");
        res.end(pdf);
      } catch (error) {
        sendJson(res, 400, { ok: false, error: { message: String(error?.message || error).slice(0, 500) } });
      }
      return true;
    }});
  },
});
