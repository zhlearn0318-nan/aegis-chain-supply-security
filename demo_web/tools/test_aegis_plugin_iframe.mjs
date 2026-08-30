import path from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync, writeFileSync } from "node:fs";

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

const projectRoot = process.cwd();
const expectBlock = process.argv.includes("--malicious");
const caseId = expectBlock ? "case_01084" : "case_00906";
const skillDirectory = path.join(projectRoot, "datasets", "skilltrustbench_v1_0", "full", "cases", caseId);
if (!existsSync(path.join(skillDirectory, "SKILL.md"))) throw new Error("Acceptance Skill is missing");
const zipFlag = process.argv.indexOf("--zip");
const zipPath = zipFlag >= 0 ? path.resolve(process.argv[zipFlag + 1] || "") : null;
if (zipFlag >= 0 && (!zipPath || !existsSync(zipPath))) throw new Error("ZIP acceptance fixture is missing");

const browser = await chromium.launch({ executablePath, headless: true });
try {
  const page = await browser.newPage();
  const consoleMessages = [];
  page.on("console", (message) => consoleMessages.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => consoleMessages.push(`pageerror: ${error.message}`));
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("http://127.0.0.1:18789/");
  await page.setContent(
    '<iframe id="plugin" sandbox="allow-scripts" src="http://127.0.0.1:18789/plugins/aegis-security-center/panel" style="width:1280px;height:1000px"></iframe>',
  );
  const centerHandle = await page.locator("#plugin").elementHandle();
  const center = await centerHandle.contentFrame();
  await center.locator('[data-tab="overview"].active').waitFor({ state: "visible", timeout: 15_000 });
  await center.waitForFunction(
    () => /^\d+$/.test(document.querySelector("#metric-total")?.textContent || ""),
    undefined,
    { timeout: 45_000 },
  );
  const centerState = await center.evaluate(() => ({
    title: document.querySelector("h1")?.textContent,
    activeTab: document.querySelector(".nav-button.active")?.dataset.tab,
    tabCount: document.querySelectorAll(".nav-button").length,
    total: document.querySelector("#metric-total")?.textContent,
    chain: document.querySelector("#metric-chain")?.textContent,
  }));
  if (centerState.title !== "Aegis 安全中心" || centerState.activeTab !== "overview" || centerState.tabCount !== 6 || !centerState.chain?.startsWith("有效")) {
    throw new Error(`Security center overview acceptance failed: ${JSON.stringify({ centerState, consoleMessages })}`);
  }
  await center.locator('[data-tab="admission"]').click();
  await center.waitForURL(/\/plugins\/aegis-admission\/panel\?embed=1/, { timeout: 15_000 });
  const frame = center;
  const input = zipPath ? frame.locator("#zip-input") : frame.locator("#folder-input");
  await input.waitFor({ state: "attached", timeout: 15_000 });
  await input.setInputFiles(zipPath || skillDirectory);
  await frame.locator("#target-name").fill(expectBlock ? "aegis-formal-ui-blocked" : (zipPath ? "aegis-formal-ui-zip-safe" : "aegis-formal-ui-safe"));
  await frame.waitForTimeout(500);
  const selected = await frame.locator("#selection").innerText();
  const inputState = await frame.evaluate(() => ({
    fileCount: document.querySelector("#folder-input")?.files?.length || document.querySelector("#zip-input")?.files?.length,
    scanDisabled: document.querySelector("#scan-button")?.disabled,
    selected: document.querySelector("#selection")?.textContent,
  }));
  if (inputState.scanDisabled) {
    throw new Error(`Folder selection did not enable scanning: ${JSON.stringify({ inputState, consoleMessages })}`);
  }
  await frame.locator("#scan-button").click();
  await frame.waitForFunction(
    () => ["ALLOW", "BLOCK", "ERROR"].includes(document.querySelector("#decision")?.textContent || ""),
    undefined,
    { timeout: 180_000 },
  );
  const afterScan = await frame.evaluate(() => ({
    decision: document.querySelector("#decision")?.textContent,
    reason: document.querySelector("#reason")?.textContent,
    fileFact: document.querySelector("#file-fact")?.textContent,
    hash: document.querySelector("#hash-fact")?.textContent,
    dynamic: document.querySelector("#dynamic-fact")?.textContent,
    chain: document.querySelector("#chain-fact")?.textContent,
    installEnabled: !document.querySelector("#install-button")?.disabled,
    terminalText: document.querySelector("#terminal-output")?.innerText,
  }));
  if (expectBlock) {
    const result = JSON.stringify({ centerState, selected, afterScan, afterInstall: null, consoleMessages }, null, 2);
    writeFileSync(path.join(projectRoot, "demo_web", "data", "aegis-plugin-iframe-block-test.json"), result, "utf8");
    if (afterScan.decision !== "BLOCK" || afterScan.installEnabled || afterScan.dynamic !== "静态阻断，未执行") {
      throw new Error(`Formal block acceptance failed: ${result}`);
    }
    console.log(result);
  } else {
  if (afterScan.decision !== "ALLOW" || !afterScan.installEnabled) {
    throw new Error(`Formal scan acceptance failed: ${JSON.stringify({ selected, afterScan, consoleMessages }, null, 2)}`);
  }
  await frame.locator("#install-button").click();
  await frame.waitForFunction(
    () => ["安装完成", "安装失败（原版本已保留）", "等待更新确认"].includes(document.querySelector("#terminal-state")?.textContent || ""),
    undefined,
    { timeout: 180_000 },
  );
  if (await frame.locator("#terminal-state").innerText() === "等待更新确认") {
    if (await frame.locator("#install-button").innerText() !== "确认更新并替换") {
      throw new Error("Inline overwrite confirmation was not rendered");
    }
    await frame.locator("#install-button").click();
    await frame.waitForFunction(
      () => ["安装完成", "安装失败（原版本已保留）"].includes(document.querySelector("#terminal-state")?.textContent || ""),
      undefined,
      { timeout: 240_000 },
    );
  }
  const afterInstall = await frame.evaluate(() => ({
    terminalState: document.querySelector("#terminal-state")?.textContent,
    installNote: document.querySelector("#install-note")?.textContent,
    progressWidth: document.querySelector("#progress-bar")?.style.width,
    terminalText: document.querySelector("#terminal-output")?.innerText,
  }));
  const result = JSON.stringify({ centerState, selected, afterScan, afterInstall, consoleMessages }, null, 2);
  writeFileSync(path.join(projectRoot, "demo_web", "data", "aegis-plugin-iframe-test.json"), result, "utf8");
  if (afterInstall.terminalState !== "安装完成") throw new Error(`Formal install acceptance failed: ${result}`);
  console.log(result);
  }
} finally {
  await browser.close();
}
