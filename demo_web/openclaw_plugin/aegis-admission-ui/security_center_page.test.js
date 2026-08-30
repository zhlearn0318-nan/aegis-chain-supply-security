import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { renderRulesPage } from "./admin_pages.js";
import { renderSecurityCenterPage } from "./security_center_page.js";

test("security center provides overview and all five feature tabs", () => {
  const html = renderSecurityCenterPage("a".repeat(64));
  for (const label of ["安全总览", "准入扫描", "扫描报告", "审计记录", "规则管理", "MCP 准入"]) {
    assert.match(html, new RegExp(label));
  }
  assert.match(html, /data-tab="overview"/);
  assert.match(html, /\/plugins\/aegis-admission\/panel\?embed=1/);
  assert.match(html, /\/plugins\/aegis-admin\/mcp\?embed=1/);
  assert.doesNotMatch(html, /case_00906|case_01084/);
  assert.doesNotMatch(html, /<iframe/i);
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
});

test("rule form does not shadow the native reset method", () => {
  const html = renderRulesPage("a".repeat(64));
  assert.match(html, /id="reset-button"/);
  assert.doesNotMatch(html, /id="reset"/);
});
