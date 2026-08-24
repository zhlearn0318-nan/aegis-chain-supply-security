import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { GatewayApiError, gatewayApi, normalizeApiError } from './api.js'
import './styles.css'

const icons = {
  shield: '⬡', scan: '⌁', code: '</>', link: '◇', upload: '⇧',
  history: '◷', export: '↧', check: '✓', alert: '!', unknown: '?',
}

function shortHash(value) {
  return value ? `${value.slice(0, 12)}…${value.slice(-6)}` : '等待计算'
}

function formatTime(value) {
  if (!value) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).format(new Date(value))
}

function decisionMeta(decision) {
  return {
    ALLOW: { label: '允许', icon: icons.check, cls: 'allow' },
    REVIEW: { label: '复核', icon: icons.alert, cls: 'review' },
    BLOCK: { label: '阻断', icon: icons.alert, cls: 'block' },
    UNKNOWN: { label: '未知', icon: icons.unknown, cls: 'unknown' },
  }[decision] || { label: decision || '等待', icon: '·', cls: 'unknown' }
}

function systemMeta(health, error) {
  if (health?.status === 'ready') return { cls: 'ready', label: '本地引擎就绪' }
  if (health?.status === 'degraded') return { cls: 'degraded', label: '部分能力降级' }
  if (error) return { cls: 'unavailable', label: '网关连接失败' }
  return { cls: 'loading', label: '正在连接引擎' }
}

function ErrorNotice({ error, className = '' }) {
  if (!error) return null
  const normalized = normalizeApiError(error)
  const details = normalized.details == null
    ? ''
    : JSON.stringify(normalized.details, null, 2)
  return (
    <div className={`error-notice ${className}`} role="alert">
      <span className="error-code">{normalized.code}</span>
      <div>
        <strong>{normalized.message}</strong>
        {normalized.status > 0 && <small>HTTP {normalized.status}</small>}
        {details && <details><summary>查看错误上下文</summary><pre>{details}</pre></details>}
      </div>
    </div>
  )
}

function EngineCard({ engine }) {
  return (
    <article className="engine-card">
      <div className="engine-topline">
        <span className={`status-dot ${engine.ready ? 'online' : 'offline'}`} />
        <span>{engine.ready ? 'READY' : 'OFFLINE'}</span>
        <span className="engine-version">{engine.version}</span>
      </div>
      <h3>{engine.name}</h3>
      <div className="chip-row">
        {engine.analyzers.map((name) => <span className="chip" key={name}>{name}</span>)}
      </div>
      {!engine.ready && engine.message && (
        <p className="engine-health-reason">
          <code>{engine.reason_code || 'CAPABILITY_UNAVAILABLE'}</code>
          {engine.message}
        </p>
      )}
    </article>
  )
}

function PolicyStatusCard({ policy }) {
  return (
    <article className="engine-card policy-health-card">
      <div className="engine-topline">
        <span className={`status-dot ${policy.ready ? 'online' : 'offline'}`} />
        <span>{policy.ready ? 'POLICY READY' : 'POLICY ERROR'}</span>
        <span className="engine-version">v{policy.version}</span>
      </div>
      <h3>准入策略</h3>
      <div className="chip-row">
        <span className="chip">{policy.id}</span>
        <span className={`chip ${policy.fail_closed ? 'chip-locked' : 'chip-warning'}`}>
          {policy.fail_closed ? 'FAIL CLOSED' : 'FAIL OPEN'}
        </span>
      </div>
      {policy.error && <p className="policy-health-error">{policy.error}</p>}
    </article>
  )
}

function PresetCard({ preset, busy, onRun }) {
  return (
    <button className={`preset-card tone-${preset.tone}`} disabled={busy} onClick={() => onRun(preset.id)}>
      <span className="preset-kind">{preset.kind.toUpperCase()}</span>
      <strong>{preset.name}</strong>
      <span>{preset.description}</span>
      <em>{icons.scan} 真实扫描</em>
    </button>
  )
}

function Metric({ label, value, tone = '' }) {
  return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>
}

function FindingRow({ finding }) {
  const severity = (finding.severity || 'UNKNOWN').toLowerCase()
  const location = finding.location || {}
  const where = location.file
    ? `${location.file}${location.line ? `:${location.line}` : ''}`
    : location.object || '未指定位置'
  return (
    <article className="finding-row">
      <span className={`severity severity-${severity}`}>{finding.severity}</span>
      <div className="finding-main">
        <div className="finding-title"><strong>{finding.title}</strong><code>{finding.analyzer}</code></div>
        <p>{finding.description || finding.evidence || '扫描器返回了风险发现。'}</p>
        <div className="finding-evidence"><span>证据位置</span><code>{where}</code></div>
      </div>
    </article>
  )
}

function PolicyTrace({ trace, decision, status }) {
  if (!trace) return null
  const pending = ['queued', 'running'].includes(status)
  const tone = pending ? 'pending' : decisionMeta(decision).cls
  return (
    <section className={`policy-trace trace-${tone}`} aria-labelledby="policy-trace-title">
      <div className="policy-trace-heading">
        <div>
          <span className="eyebrow">ADMISSION POLICY TRACE</span>
          <h4 id="policy-trace-title">准入策略证据</h4>
        </div>
        <span className="policy-lock">{trace.fail_closed ? '失败闭锁已启用' : '失败开放'}</span>
      </div>
      <div className="policy-trace-grid">
        <div><span>策略版本</span><code>{trace.policy_id}@{trace.policy_version}</code></div>
        <div><span>命中规则</span><code>{trace.rule_id}</code></div>
        <div><span>命中等级</span><strong>{trace.matched_severities?.join(' / ') || '无'}</strong></div>
        <div><span>关联证据</span><strong>{trace.matched_finding_ids?.length || 0} 条 Finding</strong></div>
      </div>
      <p className="policy-reason"><span>决策说明</span>{trace.reason}</p>
      {!!trace.matched_finding_ids?.length && (
        <div className="policy-evidence-ids" aria-label="命中的 Finding 标识">
          {trace.matched_finding_ids.slice(0, 8).map((id) => <code key={id}>{id}</code>)}
          {trace.matched_finding_ids.length > 8 && <span>+{trace.matched_finding_ids.length - 8}</span>}
        </div>
      )}
    </section>
  )
}

function ResultPanel({ job }) {
  if (!job) {
    return (
      <div className="result-empty">
        <span className="radar" />
        <strong>等待扫描任务</strong>
        <p>选择预置样本或上传制品，结果将在这里实时呈现。</p>
      </div>
    )
  }
  const meta = decisionMeta(job.decision)
  const running = ['queued', 'running'].includes(job.status)
  const accepted = job.status === 'queued'
  const progressLabel = accepted
    ? '网关已通过 HTTP 202 接受任务，正在等待本地扫描器执行。'
    : '本地扫描器正在运行，完成后将核验结果并执行准入策略。'
  return (
    <div className="result-panel" aria-live="polite" aria-busy={running}>
      <div className="result-header">
        <div>
          <span className="eyebrow">LIVE SCAN RESULT</span>
          <h3>{job.display_name}</h3>
          <p className="mono">SCHEMA {job.schema_version} · SHA-256 {shortHash(job.artifact_sha256)}</p>
        </div>
        <div className={`decision ${running ? 'running' : meta.cls}`}>
          <span>{running ? '⌁' : meta.icon}</span>
          <div>
            <small>{accepted ? 'HTTP 202 · ACCEPTED' : running ? 'SCANNING' : 'DECISION'}</small>
            <strong>{accepted ? '等待执行' : running ? '扫描中' : meta.label}</strong>
          </div>
        </div>
      </div>

      {running && <div className="scan-progress" role="status"><i /><span>{progressLabel}</span></div>}
      {job.error && <div className="error-box"><strong>失败闭锁 / UNKNOWN</strong><span>{job.error}</span></div>}

      <div className="metric-grid">
        <Metric label="风险发现" value={job.summary?.total_findings ?? 0} />
        <Metric label="严重/高危" value={(job.summary?.critical || 0) + (job.summary?.high || 0)} tone="risk" />
        <Metric label="中危" value={job.summary?.medium ?? 0} tone="warn" />
        <Metric label="耗时" value={job.duration_ms ? `${job.duration_ms} ms` : '—'} />
      </div>

      <div className="result-meta">
        <span>分析器</span>
        <div className="chip-row">{(job.analyzers || []).map((item) => <span className="chip" key={item}>{item}</span>)}</div>
      </div>

      <PolicyTrace trace={job.policy_trace} decision={job.decision} status={job.status} />

      <div className="finding-list">
        {(job.findings || []).slice(0, 8).map((finding) => <FindingRow key={finding.id} finding={finding} />)}
        {job.status === 'completed' && !job.findings?.length && (
          <div className="clean-state"><span>{icons.check}</span><div><strong>未发现超过阈值的静态风险</strong><p>结论仅覆盖本次成功执行的分析器，不代表绝对安全。</p></div></div>
        )}
      </div>

      {job.status === 'completed' && (
        <div className="result-actions">
          <a className="secondary-button" href={gatewayApi.exportUrl(job.id, 'json')}>{icons.export} 导出 JSON</a>
          <a className="secondary-button" href={gatewayApi.exportUrl(job.id, 'md')}>{icons.export} 汇报摘要</a>
        </div>
      )}
    </div>
  )
}

function UploadPanel({ busy, onStarted }) {
  const [tab, setTab] = useState('skill')
  const [skill, setSkill] = useState(null)
  const [mcp, setMcp] = useState(null)
  const [requirements, setRequirements] = useState(null)
  const [error, setError] = useState(null)

  async function submit(event) {
    event.preventDefault()
    setError(null)
    let createScan
    if (tab === 'skill') {
      if (!skill) return setError(new GatewayApiError({ code: 'INPUT_REQUIRED', message: '请选择 Skill ZIP。' }))
      createScan = () => gatewayApi.uploadSkill(skill)
    } else if (tab === 'mcp') {
      if (!mcp) return setError(new GatewayApiError({ code: 'INPUT_REQUIRED', message: '请选择 MCP JSON。' }))
      createScan = () => gatewayApi.uploadMcp(mcp, requirements)
    } else {
      if (!requirements) return setError(new GatewayApiError({ code: 'INPUT_REQUIRED', message: '请选择 requirements.txt。' }))
      createScan = () => gatewayApi.uploadDependency(requirements)
    }
    try {
      onStarted(await createScan())
    } catch (err) { setError(normalizeApiError(err)) }
  }

  return (
    <form className="upload-panel" onSubmit={submit}>
      <div className="tabs">
        {[['skill', 'Skill ZIP'], ['mcp', 'MCP JSON'], ['dependency', '依赖文件']].map(([id, label]) => (
          <button type="button" aria-pressed={tab === id} className={tab === id ? 'active' : ''} onClick={() => { setTab(id); setError(null) }} key={id}>{label}</button>
        ))}
      </div>
      <div className="drop-zone">
        <span className="upload-icon">{icons.upload}</span>
        {tab === 'skill' && <><strong>{skill?.name || '选择 Skill ZIP'}</strong><p>包内必须且只能包含一个 SKILL.md，最大 15 MB。</p><label>浏览文件<input type="file" accept=".zip" onChange={(e) => setSkill(e.target.files[0])} /></label></>}
        {tab === 'mcp' && <><strong>{mcp?.name || '选择 MCP 离线 JSON'}</strong><p>支持 tools、prompts、resources 或 contents。</p><label>浏览 JSON<input type="file" accept=".json" onChange={(e) => setMcp(e.target.files[0])} /></label><label className="sub-file">可选 requirements.txt<input type="file" accept=".txt" onChange={(e) => setRequirements(e.target.files[0])} /></label></>}
        {tab === 'dependency' && <><strong>{requirements?.name || '选择 requirements.txt'}</strong><p>调用 MCP Scanner 同源的 pip-audit 依赖检测链路。</p><label>浏览文件<input type="file" accept=".txt" onChange={(e) => setRequirements(e.target.files[0])} /></label></>}
      </div>
      <div className="privacy-note"><span>⌫</span> 原始样本仅用于本次扫描，任务结束后自动删除。</div>
      <ErrorNotice error={error} className="inline-error" />
      <button className="primary-button" disabled={busy}>{busy ? '扫描器运行中…' : `${icons.scan} 开始真实扫描`}</button>
    </form>
  )
}

function DynamicAuditPanel({ engine, closureEngine }) {
  const [adminToken, setAdminToken] = useState('')
  const [connected, setConnected] = useState(false)
  const [history, setHistory] = useState([])
  const [current, setCurrent] = useState(null)
  const [error, setError] = useState(null)
  const [submissionNotice, setSubmissionNotice] = useState('')
  const running = current && ['queued', 'running'].includes(current.status)

  function rememberError(err) {
    const normalized = normalizeApiError(err)
    setError(normalized)
    if (normalized.code === 'ADMIN_TOKEN_INVALID') {
      setConnected(false)
      setAdminToken('')
    }
  }

  async function loadHistory() {
    if (!adminToken) {
      setError(new GatewayApiError({ code: 'INPUT_REQUIRED', message: '请输入管理员令牌。' }))
      return
    }
    try {
      const jobs = await gatewayApi.listDynamicAudits(adminToken, 10)
      setHistory(jobs)
      setConnected(true)
      setError(null)
    } catch (err) { rememberError(err) }
  }

  async function startAudit(auditType) {
    if (!adminToken) {
      setError(new GatewayApiError({ code: 'INPUT_REQUIRED', message: '请输入管理员令牌。' }))
      return
    }
    try {
      const job = auditType === 'skill_runtime_closure'
        ? await gatewayApi.startSkillClosureAudit(adminToken)
        : await gatewayApi.startDynamicAudit(adminToken)
      setCurrent(job)
      setConnected(true)
      setError(null)
      setSubmissionNotice(job.deduplicated
        ? '相同验证已在队列或执行中，本次请求已合并到原任务。'
        : '任务已进入持久队列；服务将按提交顺序逐个执行。')
    } catch (err) { rememberError(err) }
  }

  useEffect(() => {
    if (!current || !adminToken || !['queued', 'running'].includes(current.status)) return
    let cancelled = false
    let timer

    async function poll() {
      try {
        const next = await gatewayApi.getDynamicAudit(adminToken, current.id)
        if (cancelled) return
        setCurrent(next)
        setError(null)
        if (['queued', 'running'].includes(next.status)) {
          timer = setTimeout(poll, 800)
        } else {
          const jobs = await gatewayApi.listDynamicAudits(adminToken, 10)
          if (!cancelled) setHistory(jobs)
        }
      } catch (err) {
        if (!cancelled) rememberError(err)
      }
    }

    timer = setTimeout(poll, 500)
    return () => { cancelled = true; clearTimeout(timer) }
  }, [current?.id, current?.status, adminToken])

  function clearSession() {
    setAdminToken('')
    setConnected(false)
    setHistory([])
    setCurrent(null)
    setError(null)
    setSubmissionNotice('')
  }

  const metrics = current?.metrics
  const isClosure = current?.audit_type === 'skill_runtime_closure'
  const addedPaths = new Set(current?.closure?.delta?.added || [])
  const addedFiles = (current?.closure?.post_manifest || []).filter((item) => addedPaths.has(item.path))
  const runtimeRisks = current?.closure?.static_lift?.runtime_risk_findings || []
  const statusLabel = current?.status === 'completed'
    ? isClosure ? '闭包验证通过' : '机制验证通过'
    : current?.status === 'failed'
      ? '机制验证异常'
      : current?.status === 'queued'
        ? `排队中${current.queue_position ? `（第 ${current.queue_position} 位）` : ''}`
        : current?.status === 'running'
          ? '正在验证'
        : '等待管理员启动'

  return (
    <section className="dynamic-admin section-frame" id="dynamic">
      <div className="section-heading">
        <div><span className="eyebrow">ADMIN · CONTROLLED DYNAMIC AUDIT</span><h2>管理员动态验证</h2></div>
        <p>提供基础观测机制和 Skill 运行时闭包两类固定验证。两者都只运行平台内置、SHA-256 锁定样本，不接收用户代码，也不改变准入结论。</p>
      </div>

      <div className="dynamic-safety-strip">
        <span className={`status-dot ${engine?.ready && closureEngine?.ready ? 'online' : 'offline'}`} />
        <strong>{engine?.ready && closureEngine?.ready ? '两类受控验证均已就绪' : '动态能力未完全就绪'}</strong>
        <code>HASH LOCKED</code><code>DECISION Δ = 0</code><code>NO USER CODE</code>
      </div>
      {(!engine?.ready || !closureEngine?.ready) && (
        <div className="dynamic-degradation" role="status">
          {!engine?.ready && <p><code>{engine?.reason_code || 'DYNAMIC_FIXTURE_UNAVAILABLE'}</code>{engine?.message || '基础动态验证尚未就绪。'}</p>}
          {!closureEngine?.ready && <p><code>{closureEngine?.reason_code || 'SKILL_CLOSURE_UNAVAILABLE'}</code>{closureEngine?.message || 'Docker Skill 闭包尚未就绪。'}</p>}
        </div>
      )}

      <div className="dynamic-grid">
        <div className="admin-access-card">
          <span className="eyebrow">01 · ADMIN ACCESS</span>
          <h3>本次页面会话令牌</h3>
          <p>令牌只保存在当前 React 内存中；不写入 localStorage、sessionStorage、数据库或任务记录，刷新页面即消失。</p>
          <label htmlFor="admin-token">管理员令牌</label>
          <input
            id="admin-token"
            type="password"
            autoComplete="off"
            spellCheck="false"
            value={adminToken}
            onChange={(event) => { setAdminToken(event.target.value); setConnected(false); setError(null) }}
            placeholder="输入 AEGIS_ADMIN_TOKEN 的值"
          />
          <div className="admin-actions">
            <button className="secondary-button" type="button" onClick={loadHistory} disabled={!adminToken}>验证并加载历史</button>
            <button className="ghost-button" type="button" onClick={clearSession} disabled={!adminToken && !connected}>清除会话</button>
          </div>
          <span className={`admin-session ${connected ? 'connected' : ''}`}>{connected ? '✓ 管理员会话已验证' : '○ 尚未验证'}</span>
          <ErrorNotice error={error} className="inline-error" />
        </div>

        <div className="dynamic-run-card">
          <div className="dynamic-run-head">
            <div><span className="eyebrow">02 · FIXED EXECUTION</span><h3>选择固定验证类型</h3></div>
            <span className={`dynamic-state state-${current?.status || 'idle'}`}>{statusLabel}</span>
          </div>
          <div className="audit-option-grid">
            <button type="button" onClick={() => startAudit('mechanism_fixture')} disabled={!adminToken || !engine?.ready}>
              <span>基础机制</span><strong>进程 · 文件 · 回环网络</strong><small>3 个可信样本 / INFO 观测</small>
            </button>
            <button type="button" onClick={() => startAudit('skill_runtime_closure')} disabled={!adminToken || !closureEngine?.ready}>
              <span>Skill 闭包</span><strong>运行前后目录 · 静态复审</strong><small>Docker 隔离 / Cisco + Aegis</small>
            </button>
          </div>
          {submissionNotice && <div className="dynamic-running-note">{icons.scan} {submissionNotice}</div>}
          <small>接口不接收请求体，不允许上传脚本、指定路径或传入命令。</small>
        </div>
      </div>

      <div className="dynamic-result" aria-live="polite" aria-busy={running}>
        <div className="dynamic-result-head">
          <div><span className="eyebrow">REDACTED MECHANISM EVIDENCE</span><h3>{current?.display_name || '尚无动态验证结果'}</h3></div>
          {current && <code>{current.id.slice(0, 12)} · {current.status}</code>}
        </div>
        {running && <div className="scan-progress" role="status"><i /><span>{current.status === 'queued' ? `等待全局动态验证执行槽位${current.queue_position ? `，当前第 ${current.queue_position} 位` : ''}。` : '后台正在按固定清单执行，页面将自动刷新脱敏证据。'}</span></div>}
        {current?.error && <div className="error-box"><strong>{current.error_code}</strong><span>{current.error}</span></div>}
        <div className="dynamic-metrics">
          {isClosure
            ? <>
                <Metric label="新增文件" value={metrics ? `${metrics.materialized_files_observed}/${metrics.materialized_files_expected}` : '—'} />
                <Metric label="闭包覆盖率" value={metrics ? `${Math.round((metrics.closure_coverage_rate || 0) * 100)}%` : '—'} />
                <Metric label="运行时风险" value={metrics?.runtime_risk_findings ?? '—'} tone={metrics?.runtime_risk_findings ? 'risk' : ''} />
              </>
            : <>
                <Metric label="完成样本" value={metrics ? `${metrics.fixtures_completed}/${metrics.fixtures_total}` : '—'} />
                <Metric label="预期机制" value={metrics ? `${metrics.expected_checks_passed}/${metrics.expected_checks_total}` : '—'} />
                <Metric label="策略违规" value={metrics?.policy_violations ?? '—'} tone={metrics?.policy_violations ? 'risk' : ''} />
              </>}
          <Metric label="决策改变" value={metrics?.decision_changes ?? 0} />
        </div>
        {isClosure ? (
          <div className="dynamic-evidence-grid closure-evidence-grid">
            <div>
              <h4>运行时新增文件</h4>
              {!addedFiles.length && <p className="dynamic-empty">完成闭包验证后显示新增文件的路径、类型与哈希摘要。</p>}
              {addedFiles.map((file) => (
                <div className="closure-file-row" key={file.path}>
                  <span>{file.category}</span><strong>{file.path}</strong><code>{shortHash(file.sha256)}</code>
                </div>
              ))}
            </div>
            <div>
              <h4>静态复审新增风险</h4>
              {!runtimeRisks.length && <p className="dynamic-empty">只展示定位到运行时新增文件的脱敏规则结果。</p>}
              {runtimeRisks.map((finding) => (
                <div className="closure-risk-row" key={finding.id}>
                  <span className={`severity severity-${String(finding.severity || 'UNKNOWN').toLowerCase()}`}>{finding.severity}</span>
                  <strong>{finding.rule_id}</strong>
                  <code>{finding.location?.file}{finding.location?.line ? `:${finding.location.line}` : ''}</code>
                </div>
              ))}
            </div>
            <div className="closure-scan-summary">
              <h4>静态提升摘要</h4>
              <p>发现数量 <strong>{current?.closure?.static_lift?.pre_findings_total ?? '—'}</strong> → <strong>{current?.closure?.static_lift?.post_findings_total ?? '—'}</strong>，新增 <strong>{current?.closure?.static_lift?.new_findings_total ?? '—'}</strong> 条；Cisco 前后扫描 <strong>{current?.closure?.static_lift?.vendor_scans ?? '—'}</strong> 次。</p>
              <code>POLICY EFFECT = NONE · RAW CONTENT RETAINED = FALSE</code>
            </div>
          </div>
        ) : (
          <div className="dynamic-evidence-grid">
            <div>
              <h4>样本执行</h4>
              {!current?.fixture_results?.length && <p className="dynamic-empty">完成验证后显示逐样本状态。</p>}
              {current?.fixture_results?.map((fixture) => (
                <div className="fixture-result-row" key={fixture.fixture_id}>
                  <strong>{fixture.fixture_id}</strong><span>{fixture.status}</span><code>{fixture.duration_ms} ms</code>
                </div>
              ))}
            </div>
            <div>
              <h4>INFO 观测事件</h4>
              {!current?.events?.length && <p className="dynamic-empty">只展示脱敏后的机制事件，不保留原始值。</p>}
              {current?.events?.slice(0, 12).map((event) => (
                <div className="event-row" key={`${event.fixture_id}-${event.sequence}`}>
                  <span>INFO</span><strong>{event.event_type}</strong><code>{event.fixture_id}</code>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="dynamic-history">
        <div className="dynamic-history-head"><h3>管理员动态验证历史</h3><button type="button" onClick={loadHistory} disabled={!adminToken}>刷新</button></div>
        {!history.length && <p className="dynamic-empty">验证管理员身份后显示历史；记录不包含管理员令牌。</p>}
        {history.map((job) => (
          <button className="dynamic-history-row" type="button" key={job.id} onClick={() => setCurrent(job)}>
            <span>{formatTime(job.created_at)}</span><strong>{job.display_name}</strong><code>{job.audit_type === 'skill_runtime_closure' ? 'Skill 闭包' : '基础机制'} · {job.status === 'queued' ? `排队第 ${job.queue_position || '—'} 位` : job.status}</code><em>查看证据 →</em>
          </button>
        ))}
      </div>
    </section>
  )
}

function App() {
  const [health, setHealth] = useState(null)
  const [presets, setPresets] = useState([])
  const [history, setHistory] = useState([])
  const [current, setCurrent] = useState(null)
  const [globalError, setGlobalError] = useState(null)
  const resultRef = useRef(null)
  const busy = current && ['queued', 'running'].includes(current.status)

  const completedCount = useMemo(() => history.filter((item) => item.status === 'completed').length, [history])
  const system = systemMeta(health, globalError)

  async function refreshHistory() {
    try { setHistory(await gatewayApi.listScans(12)) }
    catch (err) { setGlobalError(normalizeApiError(err)) }
  }

  useEffect(() => {
    Promise.all([gatewayApi.health(), gatewayApi.presets(), gatewayApi.listScans(12)])
      .then(([h, p, scans]) => {
        setHealth(h); setPresets(p); setHistory(scans); setGlobalError(null)
      })
      .catch((err) => setGlobalError(normalizeApiError(err)))
  }, [])

  useEffect(() => {
    if (!current || !['queued', 'running'].includes(current.status)) return
    let cancelled = false
    let timer
    let attempt = 0
    const delays = [1000, 1000, 2000, 2000, 2000, 5000]

    function schedule() {
      const delay = delays[Math.min(attempt, delays.length - 1)]
      attempt += 1
      timer = setTimeout(poll, delay)
    }

    async function poll() {
      try {
        const next = await gatewayApi.getScan(current.id)
        if (cancelled) return
        setCurrent(next)
        setGlobalError(null)
        if (['queued', 'running'].includes(next.status)) schedule()
        else refreshHistory()
      } catch (err) {
        if (cancelled) return
        const normalized = normalizeApiError(err)
        setGlobalError(normalized)
        if (normalized.code !== 'SCAN_NOT_FOUND') schedule()
      }
    }

    schedule()
    return () => { cancelled = true; clearTimeout(timer) }
  }, [current?.id, current?.status])

  function handleStarted(job) {
    setCurrent(job); setGlobalError(null)
    setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80)
  }

  async function runPreset(id) {
    try { handleStarted(await gatewayApi.runPreset(id)) }
    catch (err) { setGlobalError(normalizeApiError(err)) }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top"><span>{icons.shield}</span><div><strong>AEGIS CHAIN</strong><small>AGENT SUPPLY CHAIN SECURITY</small></div></a>
        <nav><a href="#architecture">系统架构</a><a href="#demo">实时演示</a><a href="#dynamic">动态验证</a><a href="#history">任务历史</a></nav>
        <div className={`system-status ${system.cls}`} role="status">
          <span className={`status-dot ${system.cls === 'ready' ? 'online' : system.cls === 'degraded' ? 'warning' : system.cls === 'unavailable' ? 'offline' : ''}`} />
          {system.label}
        </div>
      </header>

      <main id="top">
        <section className="hero section-frame">
          <div className="hero-copy">
            <span className="eyebrow">LIVE TECHNICAL DEMONSTRATION · STATIC + TRUSTED FIXTURES</span>
            <h1>面向 Agent 生态的<br/><em>供应链静态检测与动态验证</em></h1>
            <p>统一接入 Cisco Skill Scanner 与 MCP Scanner，并加入管理员专用可信样本动态验证和 Skill 运行时目录闭包。动态结果可找回运行后新增风险，但当前不改变最终准入决策。</p>
            <div className="hero-actions"><a className="primary-button" href="#demo">{icons.scan} 进入实时扫描</a><a className="ghost-button" href="#architecture">查看检测链路 →</a></div>
          </div>
          <div className="hero-console">
            <div className="console-head"><span /><span /><span /><code>local-static-gateway</code></div>
            <div className="console-body">
              <p><b>$</b> runtime integrity --verify</p>
              <p><i>✓</i> Skill Scanner · isolated Python 3.11</p>
              <p><i>✓</i> MCP Scanner · isolated Python 3.13</p>
              <p><i>✓</i> Trusted fixtures · hash locked / loopback only</p>
              <p><i>✓</i> Fail-closed decision policy loaded</p>
              <span className="console-cursor">ready for artifact_</span>
            </div>
          </div>
        </section>

        <ErrorNotice error={globalError} className="global-error" />

        <section className="engine-strip section-frame">
          <div className="section-heading compact"><div><span className="eyebrow">RUNTIME ATTESTATION</span><h2>当前运行环境</h2></div><p>{health?.privacy}</p></div>
          <div className="engine-grid">
            {health?.engines?.map((engine) => <EngineCard engine={engine} key={engine.id} />)}
            {health?.policy && <PolicyStatusCard policy={health.policy} />}
          </div>
        </section>

        <section className="architecture section-frame" id="architecture">
          <div className="section-heading"><div><span className="eyebrow">REFERENCE ARCHITECTURE</span><h2>检测器产生证据，平台完成可信决策</h2></div><p>两个 Cisco 项目位于检测执行层；上层统一管理制品摘要、扫描状态、风险证据与四态门禁。</p></div>
          <div className="flow">
            <div className="flow-node"><span>01</span><strong>制品输入</strong><small>Skill ZIP / MCP JSON</small></div><i>→</i>
            <div className="flow-node"><span>02</span><strong>临时快照</strong><small>SHA-256 / 安全解包</small></div><i>→</i>
            <div className="flow-node accent"><span>03</span><strong>双引擎扫描</strong><small>规则 / 字节码 / YARA</small></div><i>→</i>
            <div className="flow-node"><span>04</span><strong>Finding IR</strong><small>证据 / 严重度 / 位置</small></div><i>→</i>
            <div className="flow-node decision-node"><span>05</span><strong>四态门禁</strong><small>ALLOW · REVIEW · BLOCK · UNKNOWN</small></div>
          </div>
          <div className="role-grid"><div><code>SKILL SCANNER</code><strong>Skill 制品安检机</strong><p>说明文档、规则、脚本、字节码与命令管道。</p></div><div><code>MCP SCANNER</code><strong>MCP 能力面安检机</strong><p>Tools、Prompts、Resources 与依赖漏洞。</p></div><div><code>AEGIS GATEWAY</code><strong>可信证据与决策层</strong><p>执行状态核验、统一结果、历史与导出。</p></div></div>
        </section>

        <section className="demo section-frame" id="demo">
          <div className="section-heading"><div><span className="eyebrow">LIVE SCAN LAB</span><h2>现场真实扫描</h2></div><p>使用预置样本快速演示，或上传任意符合格式要求的静态制品。</p></div>
          <div className="demo-layout">
            <div className="preset-column"><h3><span>01</span> 选择预置样本</h3><div className="preset-grid">{presets.map((preset) => <PresetCard preset={preset} busy={busy} onRun={runPreset} key={preset.id} />)}</div></div>
            <div className="or-divider"><span>OR</span></div>
            <div className="upload-column"><h3><span>02</span> 上传自定义制品</h3><UploadPanel busy={busy} onStarted={handleStarted} /></div>
          </div>
        </section>

        <section className="results section-frame" ref={resultRef}>
          <div className="section-heading"><div><span className="eyebrow">EVIDENCE & DECISION</span><h2>统一风险结果</h2></div><p>扫描异常或结果不完整时强制输出 UNKNOWN，绝不把“没有结果”解释为“安全”。</p></div>
          <ResultPanel job={current} />
        </section>

        <DynamicAuditPanel
          engine={health?.engines?.find((engine) => engine.id === 'dynamic-fixture')}
          closureEngine={health?.engines?.find((engine) => engine.id === 'dynamic-skill-closure')}
        />

        <section className="history section-frame" id="history">
          <div className="section-heading compact"><div><span className="eyebrow">LOCAL AUDIT TRAIL</span><h2>扫描历史</h2></div><div className="history-stat"><strong>{completedCount}</strong><span>已完成任务</span></div></div>
          <div className="history-table">
            <div className="history-head"><span>时间</span><span>目标</span><span>类型</span><span>结果</span><span>发现</span><span>操作</span></div>
            {history.length === 0 && <div className="history-empty">暂无历史记录，完成第一次扫描后会显示在这里。</div>}
            {history.map((job) => {
              const meta = decisionMeta(job.decision)
              return <button className="history-row" key={job.id} onClick={() => setCurrent(job)}><span>{formatTime(job.created_at)}</span><strong>{job.display_name}</strong><code>{job.target_kind}</code><span className={`mini-decision ${meta.cls}`}>{meta.label}</span><span>{job.summary?.total_findings || 0}</span><em>查看 →</em></button>
            })}
          </div>
        </section>
      </main>

      <footer><span>AEGIS CHAIN · LOCAL DEMONSTRATION</span><p>静态检测结果不构成绝对安全证明 · 原始上传制品不持久化</p><code>{health?.mode || 'CONNECTING'}</code></footer>
    </div>
  )
}

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>)
