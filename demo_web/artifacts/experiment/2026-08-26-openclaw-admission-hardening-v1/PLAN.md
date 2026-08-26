# M6-3 OpenClaw admission hardening plan

- Baseline: `8958cd3`
- Branch: `openclaw-install-policy`
- Question: can the real Skill install gate avoid service-secret inheritance, persist minimized auditable decisions, and prove deployment readiness without changing frozen detection policy?
- Null hypothesis: at least one real Cisco/dependency scanner breaks under an allowlisted environment, audit failure can still allow installation, or preflight cannot distinguish diagnostic-only from deployment-ready.
- Acceptance: Skill/MCP/dependency real smoke succeeds; safe=allow, risky=block; two-row audit chain verifies; audit write failure=block; full backend regression passes; rules and policy thresholds unchanged.
- Stop conditions: restoring full service environment inheritance, storing sourcePath/source content in audit, weakening REVIEW/BLOCK policy, or claiming external WORM/SIEM guarantees.

