#!/usr/bin/env python3
"""Verify the output of audit.ps1. Standard library only.

Runs `powershell -NoProfile -ExecutionPolicy Bypass -File audit.ps1`,
parses stdout as JSON, and validates the structure. Prints PASS/FAIL per
assertion. Exit code 0 only if every assertion passes.

Usage:
    python verify.py
    python verify.py --save out.json
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
AUDIT_PS1 = BASE_DIR / "audit.ps1"

EXPECTED_CHECKS = [
    "auto_service_stopped",
    "scheduled_task_failed",
    "reboot_pending",
    "disk_low",
    "error_events_24h",
    "port_no_owner",
]
ALLOWED_SEVERITIES = ("critical", "warning", "info")
REQUIRED_FINDING_KEYS = ("check", "severity", "detail", "evidence")

results = []


def report(name, ok, detail=""):
    """Record one assertion and print its PASS/FAIL line."""
    results.append(ok)
    status = "PASS" if ok else "FAIL"
    suffix = " -- {}".format(detail) if (detail and not ok) else ""
    print("{}: {}{}".format(status, name, suffix))


def run_audit():
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(AUDIT_PS1),
    ]
    try:
        return subprocess.run(cmd, capture_output=True, cwd=str(BASE_DIR))
    except FileNotFoundError as exc:
        return exc


def parse_json(raw):
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        pass
    return json.loads(raw.decode("mbcs", errors="replace"))


def main():
    parser = argparse.ArgumentParser(description="Validate audit.ps1 JSON output.")
    parser.add_argument("--save", metavar="FILE", help="write the parsed result to FILE")
    args = parser.parse_args()

    proc = run_audit()
    if isinstance(proc, Exception):
        report("powershell is available and audit.ps1 runs", False, str(proc))
        print("0/1 assertions passed.")
        return 1

    report("powershell exit code is 0", proc.returncode == 0,
           "exit code {}".format(proc.returncode))

    try:
        data = parse_json(proc.stdout)
        parsed = True
    except ValueError as exc:
        data = None
        parsed = False
        report("stdout is valid JSON", False, str(exc))

    if parsed:
        report("stdout is valid JSON", True)

    is_obj = isinstance(data, dict)
    if parsed:
        report("top level is a JSON object", is_obj,
               "got {}".format(type(data).__name__))

    has_keys = is_obj and all(k in data for k in ("host", "findings", "summary"))
    if parsed:
        report("top-level keys host, findings, summary present", bool(has_keys),
               "keys: {}".format(sorted(data.keys()) if is_obj else "n/a"))

    host = data.get("host") if is_obj else None
    uptime_ok = (
        isinstance(host, dict)
        and isinstance(host.get("uptime_hours"), (int, float))
        and not isinstance(host.get("uptime_hours"), bool)
    )
    report("host.uptime_hours is numeric", bool(uptime_ok),
           "value: {!r}".format(host.get("uptime_hours") if isinstance(host, dict) else None))

    meta_ok = (
        isinstance(host, dict)
        and all(isinstance(host.get(k), str) and host.get(k) for k in ("name", "os", "generated_at"))
    )
    report("host.name/os/generated_at are non-empty strings", bool(meta_ok))

    findings = data.get("findings") if is_obj else None
    checks_ok = (
        isinstance(findings, list)
        and len(findings) == len(EXPECTED_CHECKS)
        and [f.get("check") for f in findings if isinstance(f, dict)] == EXPECTED_CHECKS
    )
    report("findings list covers all 6 expected check ids in order", bool(checks_ok),
           "got {}".format([f.get("check") if isinstance(f, dict) else "?" for f in findings]
                           if isinstance(findings, list) else type(findings).__name__))

    keys_ok = False
    if isinstance(findings, list) and findings:
        keys_ok = all(
            isinstance(f, dict)
            and all(k in f for k in REQUIRED_FINDING_KEYS)
            and isinstance(f.get("check"), str)
            and isinstance(f.get("severity"), str)
            and isinstance(f.get("detail"), str)
            and isinstance(f.get("evidence"), dict)
            for f in findings
        )
    report("every finding has the required keys (check, severity, detail, evidence) with correct types",
           bool(keys_ok))

    sev_ok = False
    if isinstance(findings, list) and findings:
        sev_ok = all(
            isinstance(f, dict) and f.get("severity") in ALLOWED_SEVERITIES
            for f in findings
        )
    report("every severity is one of critical|warning|info", bool(sev_ok))

    summary_ok = False
    if isinstance(findings, list) and isinstance(data.get("summary"), dict):
        actual = {"critical": 0, "warning": 0, "info": 0}
        for f in findings:
            if isinstance(f, dict) and f.get("severity") in actual:
                actual[f["severity"]] += 1
        summary_ok = all(data["summary"].get(k) == v for k, v in actual.items())
        report("summary counts equal actual counts", bool(summary_ok),
               "summary: {} actual: {}".format(data.get("summary"), actual))
    else:
        report("summary counts equal actual counts", False, "findings or summary missing")

    if args.save:
        if parsed:
            out_path = Path(args.save)
            out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print("saved: {}".format(out_path))
        else:
            print("not saved: stdout was not valid JSON")

    passed = sum(1 for ok in results if ok)
    total = len(results)
    print("{}/{} assertions passed.".format(passed, total))
    return 0 if (passed == total and total > 0) else 1


if __name__ == "__main__":
    sys.exit(main())
