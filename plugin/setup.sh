#!/bin/bash
# Nullcone Claude Code Plugin — dependency installer
# The only dependency is the 'mcp' package for the MCP server.
# The security guard hook uses zero dependencies (stdlib only).

set -e

echo "Installing Nullcone Claude Code plugin dependencies..."

if command -v pip3 &>/dev/null; then
    pip3 install --quiet mcp 2>/dev/null || pip install --quiet mcp 2>/dev/null
elif command -v pip &>/dev/null; then
    pip install --quiet mcp
else
    echo "Warning: pip not found. Install 'mcp' package manually: pip install mcp"
    exit 1
fi

echo "Done. Nullcone plugin ready."
echo ""
echo "What you get:"
echo "  - Automatic IOC checking on every Bash command, WebFetch, and file write"
echo "  - Prompt injection scanning on every prompt"
echo "  - 648K+ threat signatures (IPs, domains, URLs, hashes, CVEs, AI attacks)"
echo "  - MCP tools: lookup_ioc, recent_threats, submit_ioc, and more"
echo "  - Skills: /nullcone:threat-brief, /nullcone:analyze-ioc, /nullcone:triage-alert"
echo ""
echo "Test: claude --plugin-dir $(dirname "$0")"
