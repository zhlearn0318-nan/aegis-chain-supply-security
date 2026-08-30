const ITEMS = [
  ["overview", "总览", "/plugins/aegis-security-center/panel"],
  ["admission", "准入扫描", "/plugins/aegis-admission/panel?embed=1"],
  ["reports", "扫描报告", "/plugins/aegis-admin/reports?embed=1"],
  ["audit", "审计记录", "/plugins/aegis-admin/audit?embed=1"],
  ["rules", "规则管理", "/plugins/aegis-admin/rules?embed=1"],
  ["mcp", "MCP 准入", "/plugins/aegis-admin/mcp?embed=1"],
];

export const SECURITY_CENTER_NAV_CSS = `.aegis-center-nav{display:flex;gap:7px;padding:7px;margin-bottom:16px;border:1px solid #2b3857;border-radius:14px;background:#0d1526;overflow:auto;position:sticky;top:0;z-index:9;box-shadow:0 10px 30px #0005}.aegis-center-nav a{display:flex;align-items:center;border-radius:9px;padding:9px 13px;color:#aebbd4;text-decoration:none;white-space:nowrap;font-weight:750}.aegis-center-nav a:hover{background:#18243a;color:#e8f0ff}.aegis-center-nav a.active{background:linear-gradient(145deg,#2d68a7,#234d82);color:white;box-shadow:0 6px 16px #05080f88}`;

export function renderSecurityCenterNav(activeTab) {
  return `<nav class="aegis-center-nav" aria-label="Aegis 安全中心功能导航">${ITEMS.map(([id, label, href]) => `<a href="${href}"${id === activeTab ? ' class="active" aria-current="page"' : ""}>${label}</a>`).join("")}</nav>`;
}
