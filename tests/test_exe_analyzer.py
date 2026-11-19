"""Unit tests for exe_analyzer.py (run from the repo root: python -m unittest discover tests)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import exe_analyzer  # noqa: E402


class ExeAnalyzerTests(unittest.TestCase):
    def _analyze_bytes(self, data):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            return exe_analyzer.analyze(path)
        finally:
            os.remove(path)

    def test_non_pe_file_flagged_as_invalid(self):
        findings = self._analyze_bytes(b"this is not an executable")
        self.assertEqual([f["rule"] for f in findings], ["Invalid PE structure"])

    def test_fake_mz_header_does_not_crash(self):
        findings = self._analyze_bytes(b"MZ" + b"\x00" * 100)
        self.assertEqual(findings[0]["rule"], "Invalid PE structure")

    def test_findings_use_shared_format(self):
        for item in self._analyze_bytes(b"garbage"):
            self.assertEqual(set(item), {"rule", "points", "reason"})
            self.assertIsInstance(item["points"], int)

    def test_suspicious_import_table_has_positive_points(self):
        self.assertTrue(all(p > 0 for p in exe_analyzer.SUSPICIOUS_IMPORTS.values()))


if __name__ == "__main__":
    unittest.main()
