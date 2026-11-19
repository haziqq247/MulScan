"""Script analyzer for MulScan (static only, never executes the file).

Checks PowerShell, batch, VBS, JS, Python and shell scripts for suspicious
patterns. Returns a list of findings: {"rule", "points", "reason"}.
"""
import re
from pathlib import Path

SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}
MAX_READ_BYTES = 5 * 1024 * 1024  # safety cap: only read the first 5 MB

# (regex, points, rule name, reason). Add a new rule by adding one line.
RULES = [
    (r"invoke-webrequest|\biwr\b|downloadstring|downloadfile|net\.webclient",
     20, "Download command", "Script downloads content from the internet"),
    (r"certutil.*-urlcache|bitsadmin.*/transfer",
     25, "LOLBin download", "Uses a built-in Windows tool to fetch files"),
    (r"-enc(odedcommand)?\s",
     25, "Encoded command", "Runs an encoded PowerShell command to hide intent"),
    (r"-windowstyle\s+hidden|-w\s+hidden",
     15, "Hidden window", "Runs with a hidden window"),
    (r"-executionpolicy\s+bypass|-ep\s+bypass",
     15, "Policy bypass", "Bypasses PowerShell execution policy"),
    (r"set-mppreference|disable.{0,20}defender|advfirewall.{0,40}off",
     30, "Disables security", "Tries to turn off antivirus or firewall"),
    (r"currentversion\\run",
     20, "Autorun persistence", "Writes to a registry autorun key"),
    (r"schtasks\s+/create",
     15, "Scheduled task", "Creates a scheduled task (possible persistence)"),
    (r"invoke-expression|\biex\b|\beval\(|\bexec\(",
     15, "Dynamic execution", "Executes code built at runtime"),
    (r"frombase64string|b64decode|\batob\(",
     15, "Base64 decoding", "Decodes Base64 data at runtime"),
]

LONG_BLOB = re.compile(r"[A-Za-z0-9+/=]{200,}")


def is_script(path):
    return Path(path).suffix.lower() in SCRIPT_EXTENSIONS


def analyze(path):
    """Return a list of findings for one script file."""
    findings = []
    with open(path, "rb") as f:
        text = f.read(MAX_READ_BYTES).decode("utf-8", errors="ignore").lower()

    for pattern, points, rule, reason in RULES:
        if re.search(pattern, text):
            findings.append({"rule": rule, "points": points, "reason": reason})

    if LONG_BLOB.search(text):
        findings.append({"rule": "Long encoded blob", "points": 15,
                         "reason": "Contains a very long Base64-like string"})
    return findings


if __name__ == "__main__":
    import sys
    for item in analyze(sys.argv[1]):
        print(item)
