# MulScan

**Multi-Format Static Malware Detector**

MulScan is a command-line tool that statically analyses files (EXE/DLL, scripts, PDF and ZIP) and reports how suspicious they look, **without ever executing them**. It was developed as a team project for **IKB31603 Ethical Hacking** (UniKL MIIT, October 2026).

- **Attack category:** Malware (static malware analyzer)
- **Language:** Python 3.9+
- **License:** MIT

---

## Legal Disclaimer

MulScan is intended for **educational and authorized use only**.

Under the **Computer Crimes Act 1997 (Malaysia)**, accessing computer material without authorization is an offence. Only analyse files that you own or have **written permission** to analyse. The authors accept no responsibility for misuse of this tool.

On startup, MulScan displays this disclaimer and requires the user to type `I AGREE` before continuing.

<img width="907" height="357" alt="image" src="https://github.com/user-attachments/assets/62ddc5c6-109c-43b1-b210-dd737c312482" />


---

## Features

| Module | File | What it does |
|---|---|---|
| Core engine | `main.py` | Menu, file type detection (magic bytes), risk scoring, threat categories, text reports |
| Ethics module | `ethics.py` | Legal disclaimer, authorization prompt, scope control, kill switch, dry-run |
| Analyzer A: EXE/DLL | `exe_analyzer.py` | Section entropy, unusual section names, writable + executable sections, very few imports, suspicious API imports (uses `pefile`) |
| Analyzer A: Scripts | `script_analyzer.py` | PowerShell/batch/VBS/JS/Python/shell patterns: download commands, LOLBins, encoded commands, hidden windows, policy bypass, disabling security tools, autorun persistence, scheduled tasks, dynamic execution, Base64 decoding, long encoded blobs |
| Analyzer B: PDF | `pdf_zip_analyzer.py` | Embedded JavaScript, launch actions, open actions |
| Analyzer B: ZIP | `pdf_zip_analyzer.py` | Large total size, high compression ratio (possible zip bomb), executable extensions, double extensions, disguised `MZ` headers, nested archives |

**Risk scoring:** every finding carries points. The total is capped at 100.

| Score | Risk level |
|---|---|
| 0 to 19 | LOW |
| 20 to 49 | MEDIUM |
| 50 to 100 | HIGH |

Findings are also grouped into threat categories (for example "Persistence", "Embedded JavaScript", "File Extension Spoofing").

---

## Attack Lifecycle Mapping

MulScan is a defensive/analysis tool, so it maps to the lifecycle stages as follows:

| Lifecycle stage | MulScan equivalent |
|---|---|
| Reconnaissance | File identification using magic bytes (EXE/DLL, PDF, ZIP) and extension for scripts |
| Scanning / Enumeration | Format-specific analysis: PE sections and imports, script patterns, PDF actions, ZIP entries |
| Vulnerability Analysis | Matching indicators against detection rules, risk scoring (LOW / MEDIUM / HIGH) and threat categories |
| Reporting | Text report saved to the local `reports/` folder and viewable from the menu |

MulScan does **not** perform exploitation, persistence or data exfiltration.

---

## Installation

```bash
git clone https://github.com/haziqq247/MulScan.git
cd MulScan
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

Requirements: Python 3.9 or newer. The only third-party library is `pefile`.

---

## Usage

```bash
python main.py
```

On start, MulScan will:

1. Show the legal disclaimer
2. Ask you to type `I AGREE`
3. Activate the kill switch (Ctrl+C)
4. Ask you to confirm the authorized scan scope (default: `samples/`)
5. Show the main menu

| Menu option | Action |
|---|---|
| 1. Scan a File | Enter a file path; MulScan detects the type, analyses it, shows the risk assessment and saves a report |
| 2. View Scan Reports | List and read saved reports from `reports/` |
| 3. About MulScan | Supported formats and analysis method |
| 4. Detection Information | Scoring bands and limitations |
| 5. Toggle Dry-Run | When ON, shows which file would be scanned without analysing it |
| 6. Exit | Quit MulScan |

**Example scan (a harmless test PDF containing PDF action keywords):**

<img width="1190" height="800" alt="image" src="https://github.com/user-attachments/assets/512ac24b-6009-4b01-a7b3-b41d7bc809e5" />


If the chosen file is outside the authorized scope, MulScan warns you and requires you to type `YES` to confirm authorization; otherwise the scan is blocked.

### Generating safe test samples

The `tests/` folder holds small scripts that create harmless sample archives (plain text only, never real malware). Run them from inside `samples/` so the generated files stay in the authorized scope and are ignored by git:

```bash
cd samples
python ../tests/header.py        # ZIP with a text file named photo.jpg that starts with "MZ"
python ../tests/zip_sample.py    # ZIP with 2 MiB of repeated text (high compression ratio)
cd ..
python main.py
```

---

## Ethical Considerations

| Safeguard | Implementation | Why |
|---|---|---|
| Legal disclaimer | Shown at startup, references the Computer Crimes Act 1997 | Makes users aware of the law before using the tool |
| Explicit authorization | User must type `I AGREE` | Creates a conscious confirmation of permission |
| Authorized scope | Default scope is the local `samples/` folder; files outside scope need an extra `YES` confirmation or are blocked | Prevents accidental scanning of files the user is not authorized to analyse |
| Never executes files | Analyzers only read bytes and parse structures | Analysing malware must not infect the analyst's machine |
| ZIP entries are not extracted | Only the first 2 bytes of an entry are read to check for an `MZ` header | Avoids zip bombs and writing untrusted files to disk |
| Safety limits | PDF and ZIP files above 10 MiB, ZIP files above 1000 entries are refused; scripts are read only up to 5 MB | Prevents resource exhaustion on the analyst's machine |
| Dry-run mode | Shows which file would be scanned without analysing it | Lets users verify the target before running a real scan |
| Kill switch | Ctrl+C aborts cleanly | Gives the user a way to stop at any time |
| No data exfiltration | MulScan makes no network connections | Analysed files may contain sensitive data |

---

## Rules of Engagement (RoE)

**Authorized scope**
- Files that you own, or files for which you hold written permission to analyse
- Files placed inside the `samples/` folder (default scope) or another folder you explicitly authorize at startup
- Analysis is performed on your own local machine only

**Time windows**
- Use only during the course assessment and lab period (October 2026) or any period agreed in writing with the file owner

**Permitted techniques**
- Static analysis only: reading file bytes, parsing headers and structures, entropy calculation, string and pattern matching
- Saving analysis reports to the local `reports/` folder

**Prohibited actions**
- Executing, opening or detonating any analysed file
- Scanning files without authorization
- Using MulScan to create, modify, spread or improve malware
- Uploading analysed files or reports to third parties without the owner's permission
- Committing real malware samples to this repository
- Bypassing the disclaimer, scope check or kill switch

**Emergency stop procedure**
1. Press **Ctrl+C**: the kill switch stops MulScan immediately and safely
2. If the terminal is unresponsive, close the terminal window
3. Delete the `reports/` folder if sensitive results were created by mistake
4. Report the incident to your lecturer or the file owner

---

## Data Handling

- MulScan does not transmit any data over the network
- Reports are plain text files stored locally in `reports/`, named `MulScan_Report_<filename>_<date>_<time>.txt`
- A report contains the file name, detected type, scan date and time, findings, risk score and threat categories; it does **not** contain the contents of the scanned file
- `reports/` is listed in `.gitignore` so that reports are not committed by accident
- Delete `reports/` when you no longer need the reports

---

## Responsible Disclosure

**If you find a security issue in MulScan itself**
- **Who:** the MulScan maintainers (GitHub repository owner)
- **How:** send a private message to the repository owner, or open a GitHub issue that does not include exploit details
- **When:** please report as soon as possible; the team aims to acknowledge within 7 days and fix within 90 days

**If you discover malware in a file that belongs to someone else**
- **Who:** the file's owner, then the relevant national CERT. In Malaysia this is **MyCERT (CyberSecurity Malaysia)**. Check their official website for current contact details
- **How:** share the report and file hash, not the file itself unless asked, and do not publish details publicly
- **When:** promptly, so the owner can contain the threat before details become public

---

## Limitations

- Static analysis only: it cannot observe runtime behaviour
- Packed, encrypted or heavily obfuscated files may evade detection
- Risk scores are heuristic and may produce false positives and false negatives; a HIGH score does not prove a file is malware, and LOW does not prove it is safe
- Script detection is pattern matching on text; legitimate scripts using `eval(`, `exec(` or Base64 may be flagged
- File type detection uses magic bytes for EXE/DLL, PDF and ZIP, and the file extension for scripts
- PDF checks are raw keyword searches (`/JavaScript`, `/Launch`, `/OpenAction`); PDFs that hide these names or keep them inside compressed streams can be missed
- ZIP checks rely on sizes reported in the archive headers, which can be falsified; nested archives are detected by file name only and their contents are not inspected
- Files above the size limits (10 MiB for PDF and ZIP) are not scanned
- MulScan is not a replacement for a commercial antivirus or a sandbox

---

## Project Structure

```
MulScan/
├── main.py                # Core engine and menu
├── ethics.py              # Ethical safeguards
├── exe_analyzer.py        # EXE/DLL analyzer (pefile)
├── script_analyzer.py     # Script analyzer
├── pdf_zip_analyzer.py    # PDF and ZIP analyzer
├── tests/                 # Harmless sample generators
├── samples/               # Default authorized scan scope (ignored by git)
├── reports/               # Local scan reports (ignored by git)
├── docs/screenshots/      # Screenshots used in this README
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Team

| Role | Member |
|---|---|
| Core Engine & CLI Lead | _TODO_ |
| Analyzer A: EXE/DLL & Scripts | _TODO_ |
| Analyzer B: PDF & ZIP | _TODO_ |
| Ethics, Repo & Documentation Lead | _TODO_ |

---

## License

Released under the [MIT License](LICENSE).
