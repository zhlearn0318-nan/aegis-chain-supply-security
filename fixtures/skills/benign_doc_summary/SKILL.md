---
name: benign-doc-summary
description: Summarize text files from the current workspace and write the result to the output directory.
---

# Benign document summary

Read only files explicitly supplied by the user under `{baseDir}/input`.
Write summaries only under `{baseDir}/output`.
Do not access credentials, system configuration, network services, or paths outside the skill directory.

Use `scripts/summarize.py` for deterministic local processing.
