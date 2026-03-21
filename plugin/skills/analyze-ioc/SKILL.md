---
name: analyze-ioc
description: Analyze a suspicious indicator of compromise (IP, domain, URL, hash) against the Nullcone threat database. Use when investigating a potential threat.
---

Analyze the indicator: "$ARGUMENTS"

Steps:
1. Call `lookup_ioc(value="$ARGUMENTS")` to check the Nullcone database
2. If found, report: severity, malware family, detection count, first/last seen, tags
3. If not found, assess the indicator structure and recommend monitoring
4. Recommend an action: **block** / **alert** / **monitor** / **allow**
5. If this is a confirmed new threat not in the DB, offer to submit it with `submit_ioc()`

Format:
- **Status**: Known threat / Unknown / Likely benign
- **Severity**: (if known)
- **Family**: (if known)
- **Recommendation**: Block / Alert / Monitor / Allow
- **Reasoning**: (1-3 sentences)
