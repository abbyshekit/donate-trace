#!/usr/bin/env python3
"""
scan.py — deep secret scan for Trace Commons donations.

The deterministic scrubber (scrub.py) is a fast first pass with a
hand-maintained pattern list plus a cue-gated entropy pass. This wraps
TruffleHog (hundreds of maintained detectors) for breadth.

This scan is a REQUIRED gate, not an advisory step, because there is no
breadth scanner behind it. The ingestion server re-runs its own deterministic
redactor over submitted envelopes, but that redactor covers only event
content, structured payloads and the human-correction field, and it does not
run TruffleHog. Once a donation is merged it is public and permanent, so the
last place a missed secret can be caught is here, locally, before upload.

TruffleHog runs WITHOUT verification, so no candidate secret is ever sent to a
third party. The cost of that is false positives on high-entropy strings
(hashes, ids, base64): a finding means "confirm this is not a real secret",
not "this is definitely a secret". Confirming is a human step; proceeding
without confirming is not.

Usage:
  python scan.py --in cleaned.jsonl [--report report.json]

Exit codes:
  0  clean — no findings; safe to continue the donation flow
  2  findings — a human must confirm each before upload; do not auto-proceed
  3  unavailable — TruffleHog missing, or the scan errored/timed out; the
     breadth check did NOT run, so the donation must not proceed unattended
 64  usage error — bad arguments (argparse). Distinct from 2 on purpose: a
     caller must never read "you typed the flags wrong" as "no secrets found",
     nor the reverse. argparse exits 2 by default, which would collide.
"""

import json
import shutil
import argparse
import subprocess
import sys

EXIT_CLEAN = 0
EXIT_FINDINGS = 2
EXIT_UNAVAILABLE = 3
EXIT_USAGE = 64  # sysexits.h EX_USAGE; keeps argparse off the findings code


class _ScanArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors, which is this tool's findings code."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


INSTALL_HINT = (
    "Install once (single static binary, no toolchain):\n"
    "  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh "
    "| sh -s -- -b ~/.local/bin"
)


def scan(path):
    """Return (status, findings).

    status is one of: 'not_installed', 'clean', 'findings', 'error'.
    findings is a list of {detector, line, preview} dicts (empty unless 'findings').
    """
    if not shutil.which("trufflehog"):
        return "not_installed", []

    try:
        proc = subprocess.run(
            ["trufflehog", "filesystem", path,
             "--json", "--no-verification", "--no-update"],
            capture_output=True, text=True, timeout=180,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "error", []

    findings = []
    # A failed scan must never read as a clean one. Without this, a mistyped
    # --in path, an unreadable file or a killed process produces no stdout,
    # falls through to "clean", and exits 0 -- turning "we did not check" into
    # "we checked and it is safe", which is worse than not running at all.
    if proc.returncode != 0 and not proc.stdout.strip():
        return "error", []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = obj.get("DetectorName") or obj.get("DetectorType")
        if not detector:
            continue
        raw = obj.get("Raw") or obj.get("RawV2") or ""
        preview = (raw[:4] + "…" + raw[-3:]) if len(raw) > 9 else "***"
        loc = (
            obj.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("line")
        )
        findings.append({"detector": str(detector), "line": loc, "preview": preview})

    return ("findings" if findings else "clean"), findings


def main():
    ap = _ScanArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    status, findings = scan(args.inp)

    if status == "not_installed":
        exit_code = EXIT_UNAVAILABLE
        print("STATUS: trufflehog_not_installed")
        print("The breadth scan did NOT run. Nothing behind this step re-scans the")
        print("donation: the server's redactor covers only event content, structured")
        print("payloads and human corrections, and does not run TruffleHog.")
        print("Install it and re-run before uploading.")
        print(INSTALL_HINT)
    elif status == "error":
        exit_code = EXIT_UNAVAILABLE
        print("STATUS: scan_error")
        print("TruffleHog is installed but the scan did not complete (timeout,")
        print("execution error, or a non-zero exit with no results -- check the")
        print("--in path), so the breadth check did NOT run. Retry before")
        print("uploading; do not proceed on the scrub.py pass alone.")
    elif status == "clean":
        exit_code = EXIT_CLEAN
        print("STATUS: clean")
        print("TruffleHog found no secrets in the cleaned trace.")
    else:  # findings
        exit_code = EXIT_FINDINGS
        detectors = sorted({f["detector"] for f in findings})
        print(f"STATUS: findings ({len(findings)})")
        print("Detectors: " + ", ".join(detectors))
        print("These ran WITHOUT verification and are often false positives on")
        print("high-entropy strings. Confirm each is NOT a real secret before upload:")
        for f in findings:
            loc = f"line {f['line']}" if f["line"] else "location unknown"
            print(f"  - {f['detector']}: {f['preview']} ({loc})")

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump({"status": status, "findings": findings}, f, indent=2)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
