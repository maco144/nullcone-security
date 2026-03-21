---
name: triage-alert
description: Triage a security alert by cross-referencing IOCs against the Nullcone threat database. Use when an EDR, SIEM, or detection rule fires.
---

Triage the following alert: "$ARGUMENTS"

Steps:
1. Extract all IOCs from the alert description (IPs, domains, URLs, hashes)
2. Call `lookup_ioc(value=...)` for each extracted indicator
3. Call `recent_threats(min_severity=7)` to check for active campaigns
4. Cross-reference with known malware families using `list_families()` if needed
5. Assess: known threat? active campaign? likely false positive?
6. If confirmed new threat, submit with `submit_ioc()` to share with the network

Format:
- **Verdict**: Confirmed threat / Suspicious / Likely FP
- **Severity**: (1-10)
- **Matched families**: (if any)
- **Recommended action**: Immediate block / Escalate / Monitor / Close as FP
- **Evidence**: (bullet points)
