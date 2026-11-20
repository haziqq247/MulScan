

import zipfile
import zlib
from pathlib import Path


def analyze_pdf(file_path):
    """Scan a PDF for risky action keywords and return a list of findings.

    Reads up to 10 MiB, checks the %PDF- header, then looks for /JavaScript,
    /Launch and /OpenAction. Raises ValueError for non-PDF or oversized files.
    """
    findings = []

    with open(file_path, "rb") as file:
        content = file.read(10 * 1024 * 1024 + 1)

    if len(content) > 10 * 1024 * 1024:
        raise ValueError("PDF exceeds the 10 MiB scan limit.")

    if not content.startswith(b"%PDF-"):
        raise ValueError("File does not start with a PDF header.")

    if b"/JavaScript" in content:
        findings.append({
            "rule": "PDF_JAVASCRIPT",
            "points": 20,
            "reason": "Raw JavaScript indicator detected. Evidence: /JavaScript"
        })

    if b"/Launch" in content:
        findings.append({
            "rule": "PDF_LAUNCH",
            "points": 20,
            "reason": "Raw launch action indicator detected. Evidence: /Launch"
        })

    if b"/OpenAction" in content:
        findings.append({
            "rule": "PDF_OPEN_ACTION",
            "points": 10,
            "reason": "Raw document-open action or destination indicator detected. Evidence: /OpenAction"
        })

    return findings


def analyze_zip(file_path):
    """Inspect a ZIP's entry list without extracting it and return findings.

    Refuses files above 10 MiB or with more than 1,000 entries. Checks total
    size, compression ratio, executable and double extensions, disguised MZ
    headers and nested archives.
    """
    findings = []

    if Path(file_path).stat().st_size > 10 * 1024 * 1024:
        raise ValueError("ZIP exceeds the 10 MiB scan limit.")

    with zipfile.ZipFile(file_path, "r") as archive:
        entries = archive.infolist()

        if len(entries) > 1000:
            raise ValueError("ZIP exceeds the 1000-entry scan limit.")

        total_size = sum(
            entry.file_size for entry in entries if not entry.is_dir()
        )

        if total_size > 100 * 1024 * 1024:
            findings.append({
                "rule": "ZIP_LARGE_TOTAL_SIZE",
                "points": 20,
                "reason": f"Reported total uncompressed size exceeds 100 MiB. Total: {total_size} bytes."
            })

        for entry in entries:
            if entry.is_dir():
                continue

            ratio = entry.file_size / max(entry.compress_size, 1)

            if entry.file_size > 1024 * 1024 and ratio > 100:
                findings.append({
                    "rule": "ZIP_HIGH_COMPRESSION",
                    "points": 20,
                    "reason": (
                        "Entry has a high compression ratio and may require "
                        "excessive resources when extracted. "
                        f"File: {entry.filename}, Ratio: {round(ratio, 2)}"
                    )
                })

            suffixes = Path(entry.filename).suffixes
            suffixes = [suffix.lower() for suffix in suffixes]

            if suffixes and suffixes[-1] in {
                ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1"
            }:
                findings.append({
                    "rule": "ZIP_EXECUTABLE_EXTENSION",
                    "points": 10,
                    "reason": (
                        "Archive contains a filename with an executable "
                        f"or script extension. File: {entry.filename}"
                    )
                })

            if (
                len(suffixes) >= 2
                and suffixes[-2] in {
                    ".pdf", ".doc", ".docx", ".txt", ".jpg", ".png"
                }
                and suffixes[-1] in {
                    ".exe", ".scr", ".com", ".bat", ".cmd"
                }
            ):
                findings.append({
                    "rule": "ZIP_DOUBLE_EXTENSION",
                    "points": 20,
                    "reason": (
                        "Filename has a document or image extension "
                        "followed by an executable extension. "
                        f"File: {entry.filename}"
                    )
                })

            if (
                entry.flag_bits & 1
                or entry.file_size > 1024 * 1024
                or entry.compress_type not in {
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED
                }
            ):
                findings.append({
                    "rule": "ZIP_HEADER_CHECK_SKIPPED",
                    "points": 0,
                    "reason": (
                        "Content-header check skipped: encrypted entry, "
                        "size above 1 MiB, or unsupported compression method. "
                        f"File: {entry.filename}"
                    )
                })

            else:
                try:
                    with archive.open(entry, "r") as member:
                        header = member.read(2)

                    if header == b"MZ" and (
                        not suffixes
                        or suffixes[-1] not in {
                            ".exe", ".dll", ".scr", ".com"
                        }
                    ):
                        findings.append({
                            "rule": "ZIP_DISGUISED_MZ",
                            "points": 20,
                            "reason": (
                                "MZ header indicator found under a filename "
                                "without an expected executable extension. "
                                f"File: {entry.filename}"
                            )
                        })

                except (
                    OSError, ValueError, RuntimeError,
                    zipfile.BadZipFile, EOFError, zlib.error
                ) as error:
                    findings.append({
                        "rule": "ZIP_HEADER_CHECK_FAILED",
                        "points": 0,
                        "reason": (
                            "Could not inspect the entry header. "
                            f"File: {entry.filename}, Error: {error}"
                        )
                    })

            if entry.filename.lower().endswith(".zip"):
                findings.append({
                    "rule": "ZIP_NESTED_ARCHIVE",
                    "points": 10,
                    "reason": (
                        "ZIP filename suggests a nested archive. "
                        f"File: {entry.filename}"
                    )
                })

    return findings


if __name__ == "__main__":
    print("Analyzer B Test")
    print("1. PDF")
    print("2. ZIP")

    try:
        choice = input("Choose file type (1/2): ").strip()
        file_path = input("Enter file path: ").strip().strip('"')

        if choice == "1":
            findings = analyze_pdf(file_path)
        elif choice == "2":
            findings = analyze_zip(file_path)
        else:
            raise ValueError("Please choose 1 or 2.")

        if findings:
            for number, finding in enumerate(findings, start=1):
                print(f"\nFinding {number}")
                print("Rule        :", finding["rule"])
                print("Risk Points :", finding["points"])
                print("Reason      :", finding["reason"])
        else:
            print("No indicators found by the implemented checks.")
            print("This does not prove the file is safe.")

    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"[ERROR] {error}")

    except KeyboardInterrupt:
        print("\nScan cancelled.")
