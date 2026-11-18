# MulScan

**Multi-Format Static Malware Detector**

MulScan is a command-line tool that statically analyses files (EXE/DLL, scripts, PDF and ZIP) and reports how suspicious they look, **without ever executing them**. It was developed as a team project for **IKB31603 Ethical Hacking** (UniKL MIIT, October 2026).

- **Attack category:** Malware (static malware analyzer)
- **License:** MIT
- **Language:** Python 3

> **Status:** Work in progress. Sections marked `TODO` will be completed once all modules are merged.

---

## Legal Disclaimer

MulScan is intended for **educational and authorized use only**.

Under the **Computer Crimes Act 1997 (Malaysia)**, accessing computer material without authorization is an offence. Only analyse files that you own or have **written permission** to analyse. The authors accept no responsibility for misuse of this tool.

On startup, MulScan displays this disclaimer and requires the user to type `I AGREE` before continuing.

---

## Features

| Module | What it does | Owner |
|---|---|---|
| Core engine | Menu, file type detection (magic bytes), risk scoring, report output | Core Engine Lead |
| Analyzer A | PE header checks, entropy, suspicious imports, script patterns | Analyzer A |
| Analyzer B | PDF (embedded JavaScript, auto-launch actions), ZIP (double extensions, nested archives, zip bombs, hidden executables) | Analyzer B |
| Ethics module (`ethics.py`) | Legal disclaimer, authorization prompt, scope control, kill switch, dry-run | Ethics Lead |

_TODO: update this table when analyzers are merged._

---

## Attack Lifecycle Mapping

MulScan is a defensive/analysis tool, so it maps to the lifecycle stages as follows:

| Lifecycle stage | MulScan equivalent |
|---|---|
| Reconnaissance | File identification using magic bytes (EXE, DLL, PDF, ZIP, script) |
| Scanning / Enumeration | Format-specific analysis: PE headers, imports, entropy, PDF objects, ZIP structure, script patterns |
| Vulnerability Analysis | Matching indicators against suspicious-behaviour rules and risk scoring (low / medium / high) |
| Reporting | Human-readable and structured report saved to the local `output/` folder |

MulScan does **not** perform exploitation, persistence or data exfiltration.

_TODO: refine after the final workflow is confirmed with the team._

---

## Installation

```bash
git clone https://github.com/<haziqq247>/MulScan.git
cd MulScan
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

_TODO: confirm `requirements.txt` contents with Analyzer A and B (for example `pefile`)._

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

_TODO: add usage examples and screenshots after all modules are merged._

---

## Ethical Considerations

| Safeguard | Implementation | Why |
|---|---|---|
| Legal disclaimer | Shown at startup, references the Computer Crimes Act 1997 | Makes users aware of the law before using the tool |
| Explicit authorization | User must type `I AGREE` | Creates a conscious confirmation of permission |
| Authorized scope | Default scope is the local `samples/` folder; files outside scope need extra confirmation or are blocked | Prevents accidental scanning of files the user is not authorized to analyse |
| Safe by design | Files are only read, never executed or modified | Analysing malware must not infect the analyst's machine |
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
- _TODO: team to confirm or adjust the exact window_

**Permitted techniques**
- Static analysis only: reading file bytes, parsing headers and structures, entropy calculation, string and pattern matching
- Saving analysis reports to the local `output/` folder

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
3. Delete the `output/` folder if sensitive results were created by mistake
4. Report the incident to your lecturer or the file owner

---

## Data Handling

- MulScan does not transmit any data over the network
- Reports are stored locally in the `output/` folder
- `output/` is listed in `.gitignore` so that reports are not committed by accident
- Delete `output/` when you no longer need the reports

_TODO: confirm report file naming and labelling with the Core Engine Lead._

---

## Responsible Disclosure

**If you find a security issue in MulScan itself**
- **Who:** the MulScan maintainers (GitHub repository owner)
- **How:** open a private message to the repository owner or a GitHub issue that does not include exploit details
- **When:** please report as soon as possible; the team aims to acknowledge within 7 days and fix within 90 days

**If you discover malware in a file that belongs to someone else**
- **Who:** the file's owner, then the relevant national CERT. In Malaysia this is **MyCERT (CyberSecurity Malaysia)**. Check their official website for current contact details
- **How:** share the report and file hash, not the file itself unless asked, and do not publish details publicly
- **When:** promptly, so the owner can contain the threat before details become public

---

## Limitations

- Static analysis only: it cannot observe runtime behaviour
- Packed, encrypted or heavily obfuscated files may evade detection
- Risk scores are heuristic and may produce false positives and false negatives
- MulScan is not a replacement for a commercial antivirus or a sandbox
- File type detection depends on magic bytes and file extension for scripts

_TODO: add analyzer-specific limitations after Analyzer A and B finish._

---

## Project Structure

```
MulScan/
├── main.py            # Core engine and menu
├── ethics.py          # Ethical safeguards
├── samples/           # Default authorized scan scope
├── output/            # Local reports (ignored by git)
├── requirements.txt
├── LICENSE
└── README.md
```

_TODO: update when analyzer modules are added._

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
