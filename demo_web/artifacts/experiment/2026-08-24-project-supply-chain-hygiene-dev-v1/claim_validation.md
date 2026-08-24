# Claim validation

## Supported

- Direct project dependencies and package manager are exactly pinned.
- Python lock entries have SHA-256 hashes; pnpm lock entries have integrity values.
- The installed 126-package shared Python runtime is covered by the Cisco, Web, or security-overlay locks, except the scanner wheel whose source commit is fixed and verified during bootstrap.
- Project-only Python, installed shared Python, and Node vulnerability audits returned zero known findings at the recorded time.
- The generated legal inventory and 152-component CycloneDX SBOM are deterministic for the same locks and installed Windows x64 graph.
- High-confidence repository secret scanning found zero verified leaks and never persisted matched values.
- Cisco dependency-audit internal failure is now rejected by the reproduction wrapper instead of accepted as SAFE.

## Not supported

- The zero-vulnerability result does not remain valid after new advisories are published unless the gate is rerun.
- OSV record counts are not independent-CVE counts.
- Deterministic secret patterns do not prove that every possible credential encoding is absent.
- The license inventory is not legal advice.
- Windows x64 installed Node inventory is not a claim that cross-platform optional packages were installed.
- This run is not the required clean Windows Sandbox release acceptance and does not change production NO-GO.
