import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { renderAdmissionPage } from "./admission_page.js";
import { renderReportHtml, renderReportsPage, renderRulesPage } from "./admin_pages.js";
import { renderSecurityCenterPage } from "./security_center_page.js";

test("security center provides overview and all five feature tabs", () => {
  const html = renderSecurityCenterPage("a".repeat(64));
  for (const label of ["安全总览", "准入扫描", "报告与审计", "规则管理", "MCP 准入"]) {
    assert.match(html, new RegExp(label));
  }
  assert.doesNotMatch(html, /data-tab="audit"/);
  assert.match(html, /data-tab="overview"/);
  assert.match(html, /\/plugins\/aegis-admission\/panel\?embed=1/);
  assert.match(html, /\/plugins\/aegis-admin\/mcp\?embed=1/);
  assert.doesNotMatch(html, /case_00906|case_01084/);
  assert.doesNotMatch(html, /<iframe/i);
});

test("reports page combines scan reports and both audit trails", () => {
  const html = renderReportsPage("a".repeat(64));
  assert.match(html, /Aegis 报告与审计/);
  assert.match(html, /安装前扫描报告/);
  assert.match(html, /安装准入审计/);
  assert.match(html, /规则变更审计/);
  assert.match(html, /复核 REVIEW/);
  assert.match(html, /data-pdf/);
  assert.match(html, /document\.body\.appendChild\(anchor\)/);
  assert.match(html, /PDF 已生成并开始下载/);
  const script = html.match(/<script>([\s\S]*)<\/script>/)?.[1];
  assert.ok(script);
  assert.doesNotThrow(() => new Function(script));
});

test("PDF report preserves REVIEW as an independent decision", () => {
  const html = renderReportHtml({
    sequence: 1,
    decision: "warn",
    created_at: "2026-09-05T00:00:00Z",
    target_type: "skill",
    target_name: "review-sample",
    duration_ms: 120,
    reason_code: "MANUAL_REVIEW_REQUIRED",
    finding_rule_ids: [],
    chain_sha256: "a".repeat(64),
  }, { valid: true, rows: 1 });
  assert.match(html, />REVIEW</);
  assert.match(html, /#9a6200/);
});

test("security overview presents ALLOW REVIEW and BLOCK independently", () => {
  const html = renderSecurityCenterPage("a".repeat(64));
  assert.match(html, /id="metric-allow"/);
  assert.match(html, /id="metric-review"/);
  assert.match(html, /id="metric-block"/);
  assert.match(html, /允许 ALLOW/);
  assert.match(html, /复核 REVIEW/);
  assert.match(html, /阻断 BLOCK/);
  assert.match(html, /raw==='review'\|\|raw==='warn'/);
  assert.doesNotMatch(html, /decision==='allow'\?'allow':'block'/);
});

test("admission page gives REVIEW its own state and user guidance", () => {
  const html = renderAdmissionPage("a".repeat(64));
  assert.match(html, /REVIEW · 复核/);
  assert.match(html, /\.decision\.review/);
  assert.match(html, /扫描完成，等待人工复核/);
  assert.match(html, /REVIEW 不等同于恶意/);
  assert.match(html, /data-decision-guide="REVIEW"/);
});

test("formal upload scan preserves REVIEW while keeping it install-ineligible", () => {
  const source = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  assert.match(source, /AEGIS_OPENCLAW_REVIEW_MODE:\s*"warn"/);
  assert.match(source, /\["REVIEW", "WARN"\]\.includes/);
  assert.match(source, /session\.scan\?\.install_eligible !== true/);
});

test("plugin registers exactly one OpenClaw sidebar tab", () => {
  const source = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  assert.equal((source.match(/registerControlUiDescriptor\s*\(\s*\{/g) || []).length, 1);
  assert.match(source, /label:\s*"Aegis 安全中心"/);
  assert.match(source, /id:\s*"admission"/);
});

test("legacy feature routes remain available through embedded paths", () => {
  const source = readFileSync(new URL("./index.js", import.meta.url), "utf8");
  assert.match(source, /CENTER_PATH/);
  assert.match(source, /isEmbeddedRequest/);
  assert.match(source, /sendRedirect/);
  assert.match(source, /\[AUDIT_PATH, "reports", renderReportsPage\]/);
  assert.match(source, /parsed\.host\.toLowerCase\(\) === requestHost/);
});

test("rule form does not shadow the native reset method", () => {
  const html = renderRulesPage("a".repeat(64));
  assert.match(html, /id="reset-button"/);
  assert.doesNotMatch(html, /id="reset"/);
});
