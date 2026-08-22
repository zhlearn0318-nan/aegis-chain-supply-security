# Main experiment checklist

- [x] Separate run branch created from frozen static-audit commit.
- [x] Dataset identity and parent result hashes recorded without reading regression JSONL content.
- [x] Metrics, statistics, safety boundary, failure behavior, and verdict thresholds pre-registered.
- [x] Evaluator implemented.
- [x] Unit and synthetic metric tests pass (258 backend tests passed; 1 dependency deprecation warning).
- [x] Hash-only preflight passes without opening regression content.
- [x] Seal opening recorded durably.
- [x] Exactly 600 unique cases evaluated.
- [x] Input hashes and case trees verified unchanged.
- [x] Metrics/statistics/errors independently recomputed.
- [x] Results, report, manifest, and verification committed.
- [x] Result branch pushed to remote through the GitHub Git Database API; remote tree hash verified.
