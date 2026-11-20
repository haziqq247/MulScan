"""Unit tests for pdf_zip_analyzer.py (run from the repo root: python -m unittest discover tests)."""
import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pdf_zip_analyzer  # noqa: E402


def rules(findings):
    return [f["rule"] for f in findings]


class PdfAnalyzerTests(unittest.TestCase):
    def _analyze_bytes(self, data):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            return pdf_zip_analyzer.analyze_pdf(path)
        finally:
            os.remove(path)

    def test_clean_pdf_has_no_findings(self):
        self.assertEqual(self._analyze_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"), [])

    def test_javascript_launch_and_openaction_detected(self):
        data = b"%PDF-1.4\n/OpenAction << /S /JavaScript /JS (x) >>\n/Launch\n"
        self.assertEqual(
            sorted(rules(self._analyze_bytes(data))),
            ["PDF_JAVASCRIPT", "PDF_LAUNCH", "PDF_OPEN_ACTION"],
        )

    def test_non_pdf_header_is_rejected(self):
        with self.assertRaises(ValueError):
            self._analyze_bytes(b"not a pdf at all")

    def test_pdf_over_size_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            self._analyze_bytes(b"%PDF-" + b"A" * (10 * 1024 * 1024))


class ZipAnalyzerTests(unittest.TestCase):
    def _analyze_entries(self, entries, compression=zipfile.ZIP_STORED):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            path = f.name
        try:
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                for name, data in entries:
                    archive.writestr(name, data)
            return pdf_zip_analyzer.analyze_zip(path)
        finally:
            os.remove(path)

    def test_clean_zip_has_no_findings(self):
        self.assertEqual(self._analyze_entries([("notes.txt", b"hello")]), [])

    def test_double_extension_detected(self):
        found = rules(self._analyze_entries([("invoice.pdf.exe", b"harmless text")]))
        self.assertIn("ZIP_DOUBLE_EXTENSION", found)
        self.assertIn("ZIP_EXECUTABLE_EXTENSION", found)

    def test_disguised_mz_header_detected(self):
        found = rules(self._analyze_entries([("photo.jpg", b"MZ harmless text")]))
        self.assertIn("ZIP_DISGUISED_MZ", found)

    def test_real_exe_name_with_mz_header_not_flagged_as_disguised(self):
        found = rules(self._analyze_entries([("tool.exe", b"MZ harmless text")]))
        self.assertNotIn("ZIP_DISGUISED_MZ", found)

    def test_nested_archive_detected(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("note.txt", b"harmless")
        found = rules(self._analyze_entries([("inner.zip", inner.getvalue())]))
        self.assertIn("ZIP_NESTED_ARCHIVE", found)

    def test_high_compression_ratio_detected(self):
        data = b"A" * (2 * 1024 * 1024)
        found = rules(self._analyze_entries([("repeated.txt", data)], zipfile.ZIP_DEFLATED))
        self.assertIn("ZIP_HIGH_COMPRESSION", found)

    def test_corrupt_zip_raises_badzipfile(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"this is not a zip")
            path = f.name
        try:
            with self.assertRaises(zipfile.BadZipFile):
                pdf_zip_analyzer.analyze_zip(path)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()