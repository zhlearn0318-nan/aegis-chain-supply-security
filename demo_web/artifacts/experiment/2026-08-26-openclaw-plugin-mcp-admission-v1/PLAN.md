# M6-4 Plugin/MCP admission plan

- Baseline: `7cbcabe`
- Scope: directory native OpenClaw plugins and manifest-owned MCP server definitions.
- Acceptance: controlled safe plugin allow; controlled runtime-fetch plugin block; real stable OpenClaw safe install succeeds; blocked install has zero residue; audit chain verifies; full preflight and regression pass.
- Boundaries: no third-party package execution, no Cisco-Plugin coverage claim, no config-defined MCP admission claim, no file/archive auto-allow.

