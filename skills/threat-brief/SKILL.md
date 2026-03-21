---
name: threat-brief
description: Generate a threat intelligence brief covering current high-severity activity in the Nullcone database. Use at the start of a session for situational awareness.
---

Generate a threat intelligence brief using the Nullcone MCP tools.

Steps:
1. Call `get_stats()` for a database overview
2. Call `recent_threats(limit=30, min_severity=7)` for current high-severity activity
3. Call `list_families()` to identify active malware families
4. Highlight any AI-native threats (ioc_type = "prompt" or "skill")

Format as a security brief with sections:
- **Threat Summary** — total active threats, top families
- **High-Severity Indicators** — table of value, type, family, severity
- **AI-Native Threats** — any prompt injection or malicious skill IOCs
- **Recommended Actions** — what to watch for
