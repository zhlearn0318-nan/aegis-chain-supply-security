const ICONS = {
  overview: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
  admission: '<svg viewBox="0 0 24 24"><path d="M12 3 19 6v5c0 4.8-2.8 8.1-7 10-4.2-1.9-7-5.2-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/></svg>',
  reports: '<svg viewBox="0 0 24 24"><path d="M6 3h9l3 3v15H6z"/><path d="M15 3v4h4M9 11h6M9 15h6"/></svg>',
  rules: '<svg viewBox="0 0 24 24"><path d="M4 7h10M18 7h2M4 12h3M11 12h9M4 17h8M16 17h4"/><circle cx="16" cy="7" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="14" cy="17" r="2"/></svg>',
  mcp: '<svg viewBox="0 0 24 24"><path d="M8 7h8M8 17h8M7 7v10M17 7v10"/><circle cx="7" cy="7" r="3"/><circle cx="17" cy="7" r="3"/><circle cx="7" cy="17" r="3"/><circle cx="17" cy="17" r="3"/></svg>',
};

const ITEMS = [
  ["overview", "总览", "/plugins/aegis-security-center/panel"],
  ["admission", "准入扫描", "/plugins/aegis-admission/panel?embed=1"],
  ["reports", "报告与审计", "/plugins/aegis-admin/reports?embed=1"],
  ["rules", "规则管理", "/plugins/aegis-admin/rules?embed=1"],
  ["mcp", "MCP 准入", "/plugins/aegis-admin/mcp?embed=1"],
];

export const SECURITY_CENTER_NAV_CSS = `.aegis-center-nav{display:grid;grid-template-columns:repeat(5,minmax(108px,1fr));gap:5px;padding:5px;border:1px solid #dfe7ef;border-radius:12px;background:#fff;box-shadow:0 8px 24px rgba(16,42,67,.055);position:sticky;top:8px;z-index:20}.aegis-center-nav a.nav-button{display:flex;align-items:center;justify-content:center;gap:8px;min-height:42px;border:1px solid transparent;border-radius:8px;padding:8px 11px;color:#5c7085;text-decoration:none;white-space:nowrap;font-weight:700;transition:background .16s ease,color .16s ease,border-color .16s ease}.aegis-center-nav a.nav-button:hover{background:#f5f8fc;color:#24445f;border-color:#e3eaf1}.aegis-center-nav a.nav-button.active{background:#eaf0ff;color:#214fbf;border-color:#cad8fa;box-shadow:inset 0 0 0 1px rgba(36,87,214,.03)}.nav-icon{display:grid;place-items:center;width:18px;height:18px}.nav-icon svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}@media(max-width:850px){.aegis-center-nav{display:flex;overflow:auto;justify-content:flex-start}.aegis-center-nav a.nav-button{flex:0 0 auto;min-width:112px}}`;

export function renderSecurityCenterNav(activeTab) {
  return `<nav class="aegis-center-nav" aria-label="Aegis 安全中心功能导航">${ITEMS.map(([id, label, href]) => `<a class="nav-button${id === activeTab ? " active" : ""}" data-tab="${id}" href="${href}"${id === activeTab ? ' aria-current="page"' : ""}><span class="nav-icon" aria-hidden="true">${ICONS[id]}</span><span>${label}</span></a>`).join("")}</nav>`;
}
