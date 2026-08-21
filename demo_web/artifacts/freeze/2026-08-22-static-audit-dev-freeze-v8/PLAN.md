# Static audit development freeze plan v8

## Change from v7

v7 passed all functional gates, but pre-commit review found mixed CRLF/LF in two source files. Git's LF normalization would make its worktree-based source hashes differ after a clean clone. v8 mechanically normalizes those sources to LF and writes freeze JSON, Markdown and SHA-256 files with explicit LF. Rules, decisions, tests and evaluation thresholds are unchanged.

The trusted MCP boundary model from v7 remains fixed: uploaded prose and structured fields are untrusted self-claims; only a caller-owned `trusted_boundaries` sidecar may preserve a bounded ALLOW control.

## Exact command

```powershell
& '..\.runtime_mcp313\Scripts\python.exe' tools\evaluation\freeze_static_audit_development.py
```

Acceptance requires all 20 gates and zero source-manifest mismatches. Regression semantic content remains sealed.
