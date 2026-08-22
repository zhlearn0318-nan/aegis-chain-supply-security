# Main experiment plan

- Run ID: `2026-08-22-static-audit-regression600-v1`
- Hypothesis: the frozen Aegis static layers improve strict macro-F1 over the frozen Cisco baseline without reducing malicious recall or increasing normal FPR by more than 0.02.
- Primary metric: paired delta of strict macro-F1 on all 600 cases, with abstentions counted as errors.
- Safety gates: no sample execution/import/install/network; input and tree hashes must match; no analyzer/policy changes after seal opening.
- Statistics: paired exact McNemar; 10,000 paired bootstrap samples, seed 20260822.
- Decision rule: fixed in `demo_web/docs/M3_STATIC_AUDIT_REGRESSION_PROTOCOL.md` before opening.
- Output policy: immutable directory; compact findings only; preserve failed-run evidence.

Status: protocol/evaluator locked and preflight passed; regression content not opened by this experiment.
