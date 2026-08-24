# Cisco dependency-audit fail-closed observation

During sandboxed compatibility validation, Cisco MCP Scanner's internal `pip-audit` could not create its default user cache. The upstream command logged `pip-audit exited with code 1 and produced no JSON output`, but emitted a SAFE summary and process exit code 0.

The updated `run_cisco_reproduction.ps1` rejected that run with `MCP dependency scan reported an internal pip-audit failure and was rejected fail-closed.` No SAFE claim from that run was accepted.

The same fixed wrapper was then executed with the required Windows user-cache access. It accepted the vulnerable oracle only after 24 HIGH findings were present and accepted the safe oracle only after a completed zero-finding report. This distinction proves both the negative failure path and the successful real-tool path.
