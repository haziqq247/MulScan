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
    (r"vssadmin\s+delete\s+shadows",
     30, "Shadow copy deletion", "Deletes Windows backup copies (common in ransomware)"),
    (r"net\s+user\s+\S+\s+\S+\s+/add",
     25, "Creates user account", "Creates a new local account (possible backdoor)"),
    (r"bash\s+-i\s+>&\s*/dev/tcp",
     35, "Reverse shell", "Opens an interactive shell to a remote machine"),
    (r"attrib\s+\+h",
     10, "Hides files", "Marks files as hidden"),
    (r"eicar-standard-antivirus-test-file",
     50, "EICAR test signature", "Standard antivirus test string (harmless, not real malware)"),
]

# Full-line comment markers per file type. A suspicious word that only appears
# in a comment is not executable code, so those lines are skipped.
COMMENT_PREFIXES = {
    ".ps1": ("#",), ".py": ("#",), ".sh": ("#",),
    ".bat": ("rem ", "::"), ".cmd": ("rem ", "::"),
    ".js": ("//",), ".vbs": ("'", "rem "),
}


def strip_comment_lines(text, suffix):
    """Remove lines that are entirely a comment (text is already lowercase)."""
    prefixes = COMMENT_PREFIXES.get(suffix)
    if not prefixes:
        return text
    kept = [line for line in text.splitlines()
            if not line.lstrip().startswith(prefixes)]
    return "\n".join(kept)


LONG_BLOB = re.compile(r"[A-Za-z0-9+/=]{200,}")


def is_script(path):
    return Path(path).suffix.lower() in SCRIPT_EXTENSIONS


def analyze(path):
    """Return a list of findings for one script file."""
    findings = []
    try:
        with open(path, "rb") as f:
            text = f.read(MAX_READ_BYTES).decode("utf-8", errors="ignore").lower()
    except OSError as err:
        # A read failure is a scan problem, not a suspicious file: 0 points.
        return [{"rule": "Scan error", "points": 0,
                 "reason": f"Could not read file: {err.strerror}"}]

    text = strip_comment_lines(text, Path(path).suffix.lower())

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
