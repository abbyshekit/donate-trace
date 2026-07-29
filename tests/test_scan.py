#!/usr/bin/env python3
"""Tests for scripts/scan.py exit-code contract.

SKILL.md Step 3.5 branches on these codes, so they are an interface, not a
detail. TruffleHog is never invoked here: shutil.which and subprocess.run are
patched, so the suite needs no network and no scanner installed.
"""

import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

_SCAN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "scan.py"
)
_spec = importlib.util.spec_from_file_location("scan", _SCAN_PATH)
scan_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan_mod)


class _Proc:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def run_main(argv):
    """Run scan.main() with argv, returning the SystemExit code."""
    with mock.patch("sys.argv", argv), \
         mock.patch("sys.stdout", new_callable=io.StringIO), \
         mock.patch("sys.stderr", new_callable=io.StringIO):
        with unittest.TestCase().assertRaises(SystemExit) as caught:
            scan_mod.main()
    return caught.exception.code


FINDING_LINE = json.dumps({
    "DetectorName": "AWS",
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "SourceMetadata": {"Data": {"Filesystem": {"line": 4}}},
})


class TestExitCodes(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as f:
            f.write('{"t":"hello"}\n')
        self.addCleanup(os.unlink, self.path)

    def test_clean_exits_zero(self):
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", return_value=_Proc("")):
            self.assertEqual(run_main(["scan.py", "--in", self.path]), scan_mod.EXIT_CLEAN)

    def test_findings_exit_two(self):
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", return_value=_Proc(FINDING_LINE)):
            self.assertEqual(run_main(["scan.py", "--in", self.path]), scan_mod.EXIT_FINDINGS)

    def test_missing_scanner_exits_three(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(run_main(["scan.py", "--in", self.path]), scan_mod.EXIT_UNAVAILABLE)

    def test_scan_error_exits_three(self):
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(run_main(["scan.py", "--in", self.path]), scan_mod.EXIT_UNAVAILABLE)

    def test_usage_error_does_not_collide_with_findings(self):
        # argparse exits 2 by default, which is this tool's "secrets found".
        code = run_main(["scan.py"])
        self.assertEqual(code, scan_mod.EXIT_USAGE)
        self.assertNotEqual(code, scan_mod.EXIT_FINDINGS)

    def test_report_written_before_exit(self):
        report_path = self.path + ".report.json"
        self.addCleanup(lambda: os.path.exists(report_path) and os.unlink(report_path))
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", return_value=_Proc(FINDING_LINE)):
            run_main(["scan.py", "--in", self.path, "--report", report_path])
        with open(report_path) as f:
            report = json.load(f)
        self.assertEqual(report["status"], "findings")
        self.assertEqual(len(report["findings"]), 1)


class TestScanParsing(unittest.TestCase):
    def test_preview_does_not_echo_full_secret(self):
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", return_value=_Proc(FINDING_LINE)):
            status, findings = scan_mod.scan("/tmp/whatever.jsonl")
        self.assertEqual(status, "findings")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", findings[0]["preview"])

    def test_malformed_json_lines_ignored(self):
        with mock.patch("shutil.which", return_value="/usr/bin/trufflehog"), \
             mock.patch("subprocess.run", return_value=_Proc("not json\n\n" + FINDING_LINE)):
            status, findings = scan_mod.scan("/tmp/whatever.jsonl")
        self.assertEqual(status, "findings")
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
