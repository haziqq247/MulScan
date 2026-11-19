"""Unit tests for script_analyzer.py (run from the repo root: python -m unittest discover tests)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import script_analyzer  # noqa: E402


def scan_text(text, suffix=".ps1"):
    """Write text to a temp file, analyze it, and return the set of rule names."""
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
        f.write(text)
        path = f.name
    try:
        return {item["rule"] for item in script_analyzer.analyze(path)}
    finally:
        os.remove(path)


class ScriptAnalyzerTests(unittest.TestCase):
    def test_clean_script_has_no_findings(self):
        self.assertEqual(scan_text("Write-Host 'hello world'"), set())

    def test_download_command_flagged(self):
        self.assertIn("Download command",
                      scan_text("Invoke-WebRequest http://example.com/a.txt"))

    def test_hidden_window_and_policy_bypass_flagged(self):
        rules = scan_text("powershell -WindowStyle Hidden -ExecutionPolicy Bypass")
        self.assertIn("Hidden window", rules)
        self.assertIn("Policy bypass", rules)

    def test_encoded_command_flagged(self):
        self.assertIn("Encoded command", scan_text("powershell -enc AAAA"))

    def test_long_base64_blob_flagged(self):
        self.assertIn("Long encoded blob", scan_text("A" * 250))

    def test_matching_is_case_insensitive(self):
        self.assertIn("Download command", scan_text("INVOKE-WEBREQUEST http://x"))

    def test_is_script_by_extension(self):
        self.assertTrue(script_analyzer.is_script("run.ps1"))
        self.assertFalse(script_analyzer.is_script("photo.jpg"))

    def test_findings_use_shared_format(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False) as f:
            f.write("powershell -enc AAAA")
            path = f.name
        try:
            for item in script_analyzer.analyze(path):
                self.assertEqual(set(item), {"rule", "points", "reason"})
                self.assertIsInstance(item["points"], int)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
