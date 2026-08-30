import path from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const playwrightEntry = path.join(
  process.env.APPDATA,
  "npm",
  "node_modules",
  "openclaw",
  "node_modules",
  "playwright-core",
  "index.mjs",
);
const { chromium } = await import(pathToFileURL(playwrightEntry).href);
const edgeCandidates = [
  path.join(process.env["ProgramFiles(x86)"] ?? "", "Microsoft", "Edge", "Application", "msedge.exe"),
  path.join(process.env.ProgramFiles ?? "", "Microsoft", "Edge", "Application", "msedge.exe"),
];
const executablePath = edgeCandidates.find((candidate) => candidate && path.isAbsolute(candidate) && existsSync(candidate));
if (!executablePath) throw new Error("Microsoft Edge was not found");

const baseUrl = "http://127.0.0.1:18789";
const projectRoot = process.cwd();
const browser = await chromium.launch({ executablePath, headless: true });
try {
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  page.on("pageerror", (error) => consoleErrors.push(`pageerror: ${error.message}`));

  const pluginSource = readFileSync(path.join(projectRoot, "demo_web", "openclaw_plugin", "aegis-admission-ui", "index.js"), "utf8");
  const descriptorContract = {
    registrations: (pluginSource.match(/registerControlUiDescriptor\s*\(\s*\{/g) || []).length,
    label: pluginSource.includes('label: "Aegis 安全中心"') ? "Aegis 安全中心" : null,
  };
  if (descriptorContract.registrations !== 1 || descriptorContract.label !== "Aegis 安全中心") throw new Error(`Sidebar descriptor contract failed: ${JSON.stringify(descriptorContract)}`);
  await page.goto(baseUrl);
  await page.setContent(
    `<iframe id="plugin" sandbox="allow-scripts allow-downloads" src="${baseUrl}/plugins/aegis-security-center/panel" style="width:1400px;height:1050px"></iframe>`,
  );
  const handle = await page.locator("#plugin").elementHandle();
  const frame = await handle.contentFrame();
  await frame.locator('[data-tab="overview"].active').waitFor({ timeout: 15_000 });
  await frame.waitForFunction(() => /^\d+$/.test(document.querySelector("#metric-total")?.textContent || ""), undefined, { timeout: 45_000 });
  const overview = await frame.evaluate(() => ({
    total: document.querySelector("#metric-total")?.textContent,
    allow: document.querySelector("#metric-allow")?.textContent,
    block: document.querySelector("#metric-block")?.textContent,
    chain: document.querySelector("#metric-chain")?.textContent,
  }));

  const checks = [
    { tab: "reports", path: "/plugins/aegis-admin/reports?embed=1", title: "Aegis 报告中心", ready: "#total" },
    { tab: "audit", path: "/plugins/aegis-admin/audit?embed=1", title: "Aegis 审计记录", ready: "#install-integrity" },
    { tab: "rules", path: "/plugins/aegis-admin/rules?embed=1", title: "Aegis 规则管理", ready: "#revision" },
    { tab: "mcp", path: "/plugins/aegis-admin/mcp?embed=1", title: "Aegis MCP 准入", ready: "#form" },
  ];
  const modules = [];
  for (let index = 0; index < checks.length; index += 1) {
    const check = checks[index];
    if (index === 0) await frame.locator(`[data-tab="${check.tab}"]`).click();
    else await frame.locator(`.aegis-center-nav a[href="${check.path}"]`).click();
    await frame.waitForURL((url) => `${url.pathname}${url.search}` === check.path, { timeout: 15_000 });
    await frame.locator(check.ready).waitFor({ state: "attached", timeout: 30_000 });
    const state = await frame.evaluate(() => ({
      title: document.querySelector("h1")?.textContent,
      active: document.querySelector(".aegis-center-nav a.active")?.textContent,
      navCount: document.querySelectorAll(".aegis-center-nav a").length,
    }));
    if (state.title !== check.title || state.navCount !== 6) throw new Error(`Feature navigation failed: ${JSON.stringify({ check, state })}`);
    modules.push({ tab: check.tab, ...state });
  }

  await frame.locator('.aegis-center-nav a[href="/plugins/aegis-security-center/panel"]').click();
  await frame.waitForURL((url) => url.pathname === "/plugins/aegis-security-center/panel", { timeout: 15_000 });
  await frame.locator('[data-tab="overview"].active').waitFor({ timeout: 15_000 });

  const result = { descriptorContract, overview, modules, returnedToOverview: true, consoleErrors };
  if (!overview.chain?.startsWith("有效") || consoleErrors.length) throw new Error(`Security center navigation acceptance failed: ${JSON.stringify(result)}`);
  writeFileSync(path.join(projectRoot, "demo_web", "data", "aegis-security-center-navigation-test.json"), JSON.stringify(result, null, 2), "utf8");
  console.log(JSON.stringify(result, null, 2));
} finally {
  await browser.close();
}
