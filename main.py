import zipfile
from pathlib import Path
from datetime import datetime

from exe_analyzer import analyze as analyze_exe
from pdf_zip_analyzer import analyze_pdf, analyze_zip
from script_analyzer import analyze as analyze_script

import ethics


def display():

    print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("+\t\t\tMULSCAN\t\t\t      +")
    print("+\t   Multi-Format Static Malware Detector\t      +")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++")


def view_reports():
    """Display previously generated scan reports."""

    report_folder = Path("reports")

    print("\n========== SCAN REPORTS ==========")

    if not report_folder.exists():
        print("[INFO] No reports folder found.")
        return

    reports = sorted(
        report_folder.glob("*.txt"),
        key=lambda report: report.stat().st_mtime,
        reverse=True
    )

    if not reports:
        print("[INFO] No scan reports available.")
        return

    for number, report in enumerate(reports, start=1):
        print(f"{number}. {report.name}")

    choice = input("\nEnter report number to view (0 to return): ").strip()

    if choice == "0":
        return

    if not choice.isdigit() or not (1 <= int(choice) <= len(reports)):
        print("[ERROR] Invalid report selection.")
        return

    selected_report = reports[int(choice) - 1]

    print("\n" + "=" * 55)
    print(selected_report.read_text(encoding="utf-8"))
    print("=" * 55)


def about_mulscan():
    """Display information about MulScan."""

    print("\n========== ABOUT MULSCAN ==========")

    print("Name        : MulScan")
    print("Full Name   : Multi-Format Static Malware Detector")
    print("Purpose     : Detect suspicious indicators in files.")

    print("\nSupported File Formats:")
    print("- EXE")
    print("- DLL")
    print("- PDF")
    print("- ZIP")
    print("- Python scripts")
    print("- PowerShell scripts")
    print("- Batch scripts")
    print("- JavaScript")
    print("- VBScript")
    print("- Shell scripts")

    print("\nAnalysis Method:")
    print("- Static malware analysis")
    print("- Rule-based detection")
    print("- Heuristic risk scoring")


def detection_information():
    """Explain MulScan's detection and scoring system."""

    print("\n========== DETECTION INFORMATION ==========")

    print("\nRisk Scoring:")
    print("- 0 to 19   : LOW")
    print("- 20 to 49  : MEDIUM")
    print("- 50 to 100 : HIGH")

    print("\nDetection Method:")
    print("- Examines file structures and suspicious indicators.")
    print("- Checks suspicious API imports and script commands.")
    print("- Checks PDF actions and ZIP archive contents.")

    print("\nImportant Limitations:")
    print("- MulScan uses static analysis only.")
    print("- It does not execute scanned files.")
    print("- It cannot guarantee that a file is safe.")
    print("- Risk scores are heuristic, not malware probabilities.")
    print("- It does not confirm specific malware families.")

THREAT_CATEGORIES = {
    # EXE/DLL
    "High entropy section": "Packing / Obfuscation",
    "Unusual section name": "Suspicious Executable Structure",
    "Writable + executable section": "Code Injection Indicator",
    "Very few imports": "Packing / Obfuscation",
    "Suspicious import": "Suspicious API Usage",
    "Invalid PE structure": "Suspicious Executable Structure",

    # Scripts
    "Download command": "Payload Downloading",
    "LOLBin download": "Living-off-the-Land Technique",
    "Encoded command": "Command Obfuscation",
    "Hidden window": "Stealth Execution",
    "Policy bypass": "Security Evasion",
    "Disables security": "Defense Evasion",
    "Autorun persistence": "Persistence",
    "Scheduled task": "Persistence",
    "Dynamic execution": "Dynamic Code Execution",
    "Base64 decoding": "Obfuscation",
    "Long encoded blob": "Obfuscation",

    # PDF
    "PDF_JAVASCRIPT": "Embedded JavaScript",
    "PDF_LAUNCH": "Potential Command Execution",
    "PDF_OPEN_ACTION": "Automatic Document Action",

    # ZIP
    "ZIP_LARGE_TOTAL_SIZE": "Archive Resource Abuse",
    "ZIP_HIGH_COMPRESSION": "Potential ZIP Bomb",
    "ZIP_EXECUTABLE_EXTENSION": "Executable Content in Archive",
    "ZIP_DOUBLE_EXTENSION": "File Extension Spoofing",
    "ZIP_HEADER_CHECK_SKIPPED": "Archive Inspection Limitation",
    "ZIP_DISGUISED_MZ": "Disguised Executable",
    "ZIP_HEADER_CHECK_FAILED": "Archive Inspection Failure",
    "ZIP_NESTED_ARCHIVE": "Nested Archive",
}


def identify_threat_categories(findings):
    """Identify possible threat categories from scan findings."""

    categories = []

    for finding in findings:
        rule = finding["rule"]

        category = THREAT_CATEGORIES.get(
            rule, "Other Suspicious Activity"
        )

        if category not in categories:
            categories.append(category)

    return categories


def calculate_risk_score(findings):
    """Calculate total risk score and risk level."""

    total_score = sum(finding["points"] for finding in findings)

    total_score = min(total_score, 100)

    if total_score >= 50:
        risk_level = "HIGH"

    elif total_score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return total_score, risk_level


def display_risk_assessment(findings):

    total_score, risk_level = calculate_risk_score(findings)

    categories = identify_threat_categories(findings)

    print("\n========== FINAL RISK ASSESSMENT ==========")

    print(f"Total Risk Score : {total_score} / 100")
    print(f"Risk Level       : {risk_level}")

    print("\n========== POSSIBLE THREAT CATEGORIES ==========")

    if categories:
        for category in categories:
            print(f"- {category}")
    else:
        print("No suspicious threat indicators identified.")

    print("\n[WARNING] Static analysis cannot confirm whether a file is malware.")


def generate_report(file_path, file_type, findings):
    """Generate and save a text scan report."""

    # Get current date and time
    scan_time = datetime.now()

    # Calculate score and risk level
    total_score, risk_level = calculate_risk_score(findings)

    # Identify possible threat categories
    categories = identify_threat_categories(findings)

    # Create reports folder if it does not exist
    report_folder = Path("reports")
    report_folder.mkdir(exist_ok=True)

    # Create report filename
    timestamp = scan_time.strftime("%Y%m%d_%H%M%S")
    report_name = f"MulScan_Report_{file_path.stem}_{timestamp}.txt"

    report_path = report_folder / report_name

    # Start building report content
    report = []

    report.append("=" * 55)
    report.append("                    MULSCAN")
    report.append("       Multi-Format Static Malware Detector")
    report.append("=" * 55)

    report.append("\n========== SCAN INFORMATION ==========")
    report.append(f"File Name : {file_path.name}")
    report.append(f"File Type : {file_type}")
    report.append(f"Scan Date : {scan_time.strftime('%d-%m-%Y')}")
    report.append(f"Scan Time : {scan_time.strftime('%H:%M:%S')}")

    report.append("\n========== DETECTED INDICATORS ==========")

    if findings:
        for number, finding in enumerate(findings, start=1):
            report.append(f"\nFinding {number}")
            report.append(f"Rule        : {finding['rule']}")
            report.append(f"Risk Points : {finding['points']}")
            report.append(f"Reason      : {finding['reason']}")
    else:
        report.append("No indicators found by the implemented checks.")

    report.append("\n========== FINAL RISK ASSESSMENT ==========")
    report.append(f"Total Risk Score : {total_score} / 100")
    report.append(f"Risk Level       : {risk_level}")

    report.append("\n========== POSSIBLE THREAT CATEGORIES ==========")

    if categories:
        for category in categories:
            report.append(f"- {category}")
    else:
        report.append("No suspicious threat indicators identified.")

    report.append("\n" + "=" * 55)
    report.append("IMPORTANT NOTICE")
    report.append(
        "This report is generated using static analysis."
    )
    report.append(
        "Findings are suspicious indicators and do not confirm malware."
    )
    report.append("=" * 55)

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("\n".join(report))

    return report_path


def file_type_detection(file_path):

    with open(file_path, "rb") as file:

        header = file.read(8)

        if header.startswith(b"MZ"):
            return "EXE/DLL"

        elif header.startswith(b"%PDF-"):
            return "PDF"

        elif header.startswith(b"PK\x03\x04"):
            return "ZIP"

        elif file_path.suffix.lower() in [
            ".py", ".ps1", ".bat", ".cmd",
            ".vbs", ".js", ".sh"
        ]:
            return "Script"

        else:
            return "Unknown"


def display_findings(findings):
    """Display standardized findings returned by analyzers."""

    if not findings:
        print("\n[INFO] No indicators found by the implemented checks.")
        print("[WARNING] This does not prove the file is safe.")
        return

    print("\n========== SCAN FINDINGS ==========")

    for number, finding in enumerate(findings, start=1):

        print(f"\nFinding {number}")

        print(f"Rule        : {finding['rule']}")
        print(f"Risk Points : {finding['points']}")
        print(f"Reason      : {finding['reason']}")

def file_scan():
    print("\n--------------- FILE SCAN ---------------")

    user_path = input("\nEnter file path: ").strip()

    if not user_path:
        print("[ERROR] No file path entered!")
        return

    user_path = user_path.removeprefix("&").strip().strip("'\"")

    file_path = Path(user_path)

    if not file_path.exists():
        print("[ERROR] File does not exist!")
        return

    if not file_path.is_file():
        print("[ERROR] Selected path is not a file!")
        return

    # Ethics: file must be inside the authorized scope
    if not ethics.check_scope(file_path):
        return

    # Ethics: dry-run shows the target without analysing it
    if ethics.dry_run:
        ethics.dry_run_summary(file_path)
        return

    try:
        file_type = file_type_detection(file_path)

        print(f"\n[INFO] File selected: {file_path.name}")
        print(f"[INFO] Detected file type: {file_type}")

        print("[INFO] Starting static analysis...")

        if file_type == "EXE/DLL":
            findings = analyze_exe(file_path)

        elif file_type == "PDF":
            findings = analyze_pdf(file_path)

        elif file_type == "ZIP":
            findings = analyze_zip(file_path)

        elif file_type == "Script":
            findings = analyze_script(file_path)

        else:
            print("[ERROR] Unsupported file type!")
            return

        display_findings(findings)

        display_risk_assessment(findings)

        report_path = generate_report(file_path, file_type, findings)

        print("\n========== REPORT GENERATED ==========")
        print(f"[SUCCESS] Report saved to: {report_path}")

    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"\n[ERROR] Unable to scan file: {error}")



def main_menu():

    # Ethics: legal disclaimer, authorization, kill switch and scope
    ethics.show_disclaimer()
    ethics.require_confirmation()
    ethics.install_kill_switch()
    ethics.set_scope()

    while True:
        display()

        print("\n================ MAIN MENU ================")
        print("1. Scan a File")
        print("2. View Scan Reports")
        print("3. About MulScan")
        print("4. Detection Information")
        print(f"5. Toggle Dry-Run (currently {'ON' if ethics.dry_run else 'OFF'})")
        print("6. Exit")
        print("============================================")

        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == "1":
            file_scan()

        elif choice == "2":
            view_reports()

        elif choice == "3":
            about_mulscan()

        elif choice == "4":
            detection_information()

        elif choice == "5":
            ethics.toggle_dry_run()

        elif choice == "6":
            print("\nThank you for using MulScan!")
            print("Exiting application...\n")
            break

        else:
            print("\n[ERROR] Invalid choice. Please select 1-6.")

        input("\nPress Enter to return to the main menu...")


if __name__ == "__main__":
    main_menu()
