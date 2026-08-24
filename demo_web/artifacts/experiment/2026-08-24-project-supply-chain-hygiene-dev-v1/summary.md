# P0-4 project supply-chain hygiene summary

The repository self-audit passed all 12 required gates. The verified installed inventory contains 126 Python and 26 Windows x64 Node components; the CycloneDX 1.6 SBOM contains 152 components. Project development lock, the actual shared Cisco/Aegis Python runtime, and Node audit results all report zero known vulnerabilities at the 2026-08-25 snapshot.

The baseline Cisco dependency lock returned 118 OSV database records across 19 affected packages; these records include aliases and must not be described as 118 independent CVEs. The frontend baseline contained one High advisory for `nanoid@3.3.16`.

Compatibility verification completed the fixed Skill fixture scan, MCP content scan (3 safe / 3 unsafe), vulnerable dependency oracle (24 High findings), safe dependency oracle (0 findings), 348 backend tests, 10 frontend tests, a production build, static preflight, and runtime lock verification.

No static detection rules, admission decisions, M3 sealed regression results, dynamic fixture hashes, or third-party execution boundaries changed.
