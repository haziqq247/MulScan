"""EXE/DLL analyzer for MulScan (static only, uses pefile, never executes).

Returns a list of findings: {"rule", "points", "reason"}.
"""
import pefile

STANDARD_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata",
                     ".edata", ".pdata", ".bss", ".tls", ".crt", ".didat",
                     ".gfids", ".00cfg", ".retplne", "fothk", "CPADinfo",
                     "_RDATA", "minATL"}

# API name -> points. These are commonly abused for injection, spying, dropping.
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": 15, "WriteProcessMemory": 20, "CreateRemoteThread": 25,
    "SetWindowsHookExA": 15, "SetWindowsHookExW": 15, "GetAsyncKeyState": 15,
    "URLDownloadToFileA": 20, "URLDownloadToFileW": 20,
    "IsDebuggerPresent": 10, "WinExec": 10,
}

ENTROPY_THRESHOLD = 7.2   # above this, a section looks packed or encrypted
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def analyze(path):
    """Return a list of findings for one EXE/DLL file."""
    findings = []
    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError:
        return [{"rule": "Invalid PE structure", "points": 10,
                 "reason": "File is not a valid Windows executable"}]

    try:
        # 1. Section checks
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
            entropy = section.get_entropy()
            if entropy > ENTROPY_THRESHOLD:
                findings.append({"rule": "High entropy section", "points": 20,
                                 "reason": f"Section {name} entropy {entropy:.2f} (possibly packed)"})
            if name not in STANDARD_SECTIONS:
                findings.append({"rule": "Unusual section name", "points": 10,
                                 "reason": f"Non-standard section name: {name!r}"})
            flags = section.Characteristics
            if flags & IMAGE_SCN_MEM_EXECUTE and flags & IMAGE_SCN_MEM_WRITE:
                findings.append({"rule": "Writable + executable section", "points": 15,
                                 "reason": f"Section {name} is both writable and executable"})

        # 2. Import checks
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode("utf-8", errors="ignore"))

        if len(imports) < 5:
            findings.append({"rule": "Very few imports", "points": 15,
                             "reason": f"Only {len(imports)} imports (common in packed files)"})
        for api in imports:
            if api in SUSPICIOUS_IMPORTS:
                findings.append({"rule": "Suspicious import", "points": SUSPICIOUS_IMPORTS[api],
                                "reason": f"Imports {api}, a Windows API sometimes abused by malware"})
    finally:
        pe.close()
    return findings


if __name__ == "__main__":
    import sys
    for item in analyze(sys.argv[1]):
        print(item)
