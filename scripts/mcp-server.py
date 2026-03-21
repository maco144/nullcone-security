#!/usr/bin/env python3
"""
Nullcone MCP Server — lightweight version for Claude Code plugin.

Provides threat intelligence tools via MCP stdio transport, backed by
the Nullcone public REST API (no auth required, zero config).

Install: pip install mcp
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_API_URL = os.getenv("NULLCONE_API_URL", "https://nullcone.ai/api")
_API_KEY = os.getenv("NULLCONE_API_KEY", "")  # optional, for submit
_UA = "nullcone-claude-code-plugin/0.1"


def _api_get(path: str, params: Optional[dict] = None) -> dict | list:
    """GET request to Nullcone REST API."""
    url = f"{_API_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", _UA)
    if _API_KEY:
        req.add_header("X-API-Key", _API_KEY)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _api_post(path: str, body: dict) -> dict:
    """POST request to Nullcone REST API."""
    url = f"{_API_URL}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", _UA)
    if _API_KEY:
        req.add_header("X-API-Key", _API_KEY)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "Nullcone Threat Intelligence",
    instructions=(
        "Threat intelligence tools backed by 658K+ IOCs. "
        "Check indicators with lookup_ioc(), get current threats with recent_threats(), "
        "submit new IOCs with submit_ioc(). Covers IPs, domains, URLs, hashes, CVEs, "
        "prompt injection payloads, and malicious AI skill definitions.\n\n"
        "Free, no auth required for lookups. https://nullcone.ai"
    ),
)


@mcp.tool()
def lookup_ioc(value: str) -> dict:
    """
    Look up a threat indicator by exact value. Returns the full threat
    signature if found (severity, family, confidence, tags, detection count).

    Args:
        value: The IOC value (IP, domain, URL, hash, etc.)
    """
    try:
        return _api_get("/v1/ioc", {"value": value.strip()})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "value": value}
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def recent_threats(limit: int = 20, min_severity: int = 5) -> list[dict] | dict:
    """
    Return the most recently observed threat signatures.

    Args:
        limit:        Max results (1-200)
        min_severity: Minimum severity (0-10)
    """
    try:
        return _api_get("/v1/threats", {
            "limit": max(1, min(limit, 200)),
            "min_severity": min_severity,
        })
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def submit_ioc(
    ioc_type: str,
    value: str,
    severity: int = 5,
    confidence: int = 70,
    context: str = "",
    tags: str = "",
    source: str = "claude-code-plugin",
    family_hint: str = "",
) -> dict:
    """
    Submit a new threat indicator to the shared intelligence network.
    Requires NULLCONE_API_KEY env var for authenticated submission.

    Args:
        ioc_type:    One of: ip, domain, url, hash_md5, hash_sha1, hash_sha256,
                     email, yara, mutex, filepath, asn, ja3, imphash, cve, prompt, skill
        value:       The indicator value
        severity:    0-10 (5=medium, 7=high, 9=critical)
        confidence:  0-100
        context:     Why this is malicious
        tags:        Comma-separated tags
        source:      Origin of the intel
        family_hint: Malware family name
    """
    if not _API_KEY:
        return {"error": "NULLCONE_API_KEY not set. Get a free key at https://nullcone.ai"}
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    try:
        return _api_post("/v1/ioc", {
            "ioc_type": ioc_type,
            "value": value,
            "severity": severity,
            "confidence": confidence,
            "context": context,
            "tags": tag_list,
            "source": source,
            "family_hint": family_hint,
        })
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def search_by_type(ioc_type: str, limit: int = 50, min_severity: int = 0) -> list[dict] | dict:
    """
    Return threat signatures filtered by IOC type.

    Args:
        ioc_type:     One of: ip, domain, url, hash_sha256, prompt, skill, cve, etc.
        limit:        Max results (1-500)
        min_severity: Minimum severity (0-10)
    """
    try:
        return _api_get("/v1/threats", {
            "ioc_type": ioc_type,
            "limit": max(1, min(limit, 500)),
            "min_severity": min_severity,
        })
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def get_stats() -> dict:
    """Return aggregate statistics for the threat intelligence database."""
    try:
        return _api_get("/v1/stats")
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def poll_since(last_id: int = 0, batch_size: int = 1000, min_severity: int = 0) -> dict:
    """
    Fetch new threat signatures since a high-water mark ID. Persist next_id
    between calls for incremental sync.

    Args:
        last_id:      Last signature ID seen (0 for all)
        batch_size:   Max results (1-5000)
        min_severity: Skip below this severity (0-10)
    """
    try:
        return _api_get("/v1/threats", {
            "last_id": last_id,
            "limit": max(1, min(batch_size, 5000)),
            "min_severity": min_severity,
        })
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("threat://stats")
def resource_stats() -> str:
    try:
        return json.dumps(_api_get("/v1/stats"), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.resource("threat://recent")
def resource_recent() -> str:
    try:
        return json.dumps(_api_get("/v1/threats", {"limit": 50, "min_severity": 7}), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

@mcp.prompt()
def analyze_ioc(value: str) -> str:
    """Structured prompt for analyzing a suspicious IOC."""
    return (
        f"Analyze the indicator: `{value}`\n\n"
        "1. Call lookup_ioc(value) to check the database\n"
        "2. Report severity, family, detection count if found\n"
        "3. Recommend: block / alert / monitor / allow\n"
    )


@mcp.prompt()
def threat_brief(min_severity: int = 7) -> str:
    """Generate a threat intelligence brief."""
    return (
        f"Generate a threat intel brief (min severity {min_severity}).\n"
        f"Call recent_threats(limit=50, min_severity={min_severity}), "
        f"get_stats()."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
