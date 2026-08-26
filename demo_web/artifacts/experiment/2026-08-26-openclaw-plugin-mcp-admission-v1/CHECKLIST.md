# M6-4 acceptance checklist

- [x] Official OpenClaw staged request and plugin manifest contracts inspected locally.
- [x] Plugin uses a dedicated analyzer, not the Cisco Skill pipeline.
- [x] Native manifest, entry, lifecycle, dependency, payload and MCP rules implemented.
- [x] Compatible bundle returns review; file source fails closed.
- [x] Controlled benign MCP plugin returns allow.
- [x] Controlled malicious/runtime-fetch plugins return block.
- [x] Real stable OpenClaw benign plugin install succeeded in isolated state.
- [x] Real stable OpenClaw runtime-fetch plugin was blocked with zero residue.
- [x] Three-row real install audit chain verified.
- [x] Full Skill/Plugin preflight returned ready with four audit rows.
- [x] Rule registry contains all 124 Aegis static rule ids.
- [x] Backend regression passed 395/395.

