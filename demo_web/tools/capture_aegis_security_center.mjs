import path from "node:path";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";

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

const output = path.resolve(process.argv[2] || "demo_web/data/aegis-security-center.png");
const url = process.argv[3] || "http://127.0.0.1:18789/plugins/aegis-security-center/panel";
const readySelector = process.argv[4] || "#metric-total";
const browser = await chromium.launch({ executablePath, headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 2200, height: 1300 }, deviceScaleFactor: 1 });
  const target = new URL(url);
  await page.goto(target.origin, { waitUntil: "domcontentloaded", timeout: 30_000 });
  await page.setContent(`<iframe id="aegis" sandbox="allow-scripts allow-downloads" src="${target.href}" style="display:block;width:2160px;height:1240px;border:0"></iframe>`);
  const handle = await page.locator("#aegis").elementHandle();
  const frame = await handle.contentFrame();
  await frame.locator(readySelector).waitFor({ state: "visible", timeout: 45_000 });
  if (readySelector === "#metric-total") {
    await frame.waitForFunction(
      () => /^\d+$/.test(document.querySelector("#metric-total")?.textContent || ""),
      undefined,
      { timeout: 45_000 },
    );
  }
  await frame.waitForTimeout(600);
  await page.screenshot({ path: output, fullPage: true });
  console.log(JSON.stringify({ output, url, title: await frame.title() }));
} finally {
  await browser.close();
}
