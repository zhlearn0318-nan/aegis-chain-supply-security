# M6-3 acceptance checklist

- [x] Scanner environment is built from an allowlist.
- [x] Real user profile, cloud tokens and authenticated proxy variables are not inherited.
- [x] Synthetic cache profile restores Windows pip compatibility without real profile leakage.
- [x] Cisco Skill Scanner real smoke completed.
- [x] Cisco MCP Scanner real smoke completed.
- [x] pip-audit real smoke completed.
- [x] Audit events omit sourcePath and source content.
- [x] Audit UPDATE/DELETE are rejected at the application database layer.
- [x] Audit write failure changes allow to block.
- [x] Safe/risky CLI decisions were appended to one valid two-row hash chain.
- [x] Full deployment preflight returned ready=true.
- [x] Diagnostic preflight with skipped fixtures returns non-ready.
- [x] Backend full regression passed 390/390.
- [x] Frozen detection rules and policy thresholds were unchanged.

