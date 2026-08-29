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

const browser = await chromium.launch({ executablePath, headless: true });
try {
  const page = await browser.newPage();
  const consoleMessages = [];
  page.on("console", (message) => consoleMessages.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => consoleMessages.push(`pageerror: ${error.message}`));
  await page.goto("http://127.0.0.1:18789/");
  await page.setContent(
    '<iframe id="plugin" sandbox="allow-scripts" src="http://127.0.0.1:18789/plugins/aegis-admission/panel" style="width:1200px;height:800px"></iframe>',
  );
  const frameHandle = await page.locator("#plugin").elementHandle();
  const frame = await frameHandle.contentFrame();
  await frame.locator('button[data-case="malicious"]').waitFor({ state: "visible", timeout: 15_000 });
  const beforeClick = await frame.evaluate(() => ({
    readyState: document.readyState,
    scriptCount: document.scripts.length,
    tokenType: typeof token,
  }));
  await frame.locator('button[data-case="malicious"]').click();
  await frame.waitForTimeout(1200);
  const duringRun = {
    resultText: await frame.locator("#malicious-result").innerText(),
    buttonDisabled: await frame.locator('button[data-case="malicious"]').isDisabled(),
    terminalText: await frame.locator("#terminal-output").innerText(),
    terminalState: await frame.locator("#terminal-state").innerText(),
  };
  await frame.locator('button[data-case="malicious"]').waitFor({ state: "visible", timeout: 90_000 });
  await frame.waitForFunction(
    () => !document.querySelector('button[data-case="malicious"]')?.disabled,
    undefined,
    { timeout: 90_000 },
  );
  const afterRun = await frame.evaluate(() => ({
    resultText: document.querySelector("#malicious-result")?.innerText,
    buttonDisabled: document.querySelector('button[data-case="malicious"]')?.disabled,
    terminalText: document.querySelector("#terminal-output")?.innerText,
    terminalState: document.querySelector("#terminal-state")?.innerText,
    progressWidth: document.querySelector("#progress-bar")?.style.width,
    evidence: {
      caseId: document.querySelector("#ev-case")?.innerText,
      decision: document.querySelector("#ev-decision")?.innerText,
      installed: document.querySelector("#ev-install")?.innerText,
      dynamic: document.querySelector("#ev-dynamic")?.innerText,
      chain: document.querySelector("#ev-chain")?.innerText,
    },
  }));
  const result = JSON.stringify({ beforeClick, duringRun, afterRun, consoleMessages }, null, 2);
  writeFileSync(path.join(process.cwd(), "demo_web", "data", "aegis-plugin-iframe-test.json"), result, "utf8");
  console.log(result);
} finally {
  await browser.close();
}
