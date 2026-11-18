"""
ethics.py - Ethical safeguards for MulScan
Provides: legal disclaimer, authorization confirmation, kill switch,
scope control and dry-run mode.
"""

import signal
import sys
from pathlib import Path

# Default scope: sample/test folder only
DEFAULT_SCOPE = Path("samples")
allowed_scope = DEFAULT_SCOPE
dry_run = False


def show_disclaimer():

    print("\n=========================================================")
    print("                    LEGAL DISCLAIMER")
    print("=========================================================")
    print("MulScan is for EDUCATIONAL and AUTHORIZED use only.")
    print("")
    print("Under the Computer Crimes Act 1997 (Malaysia), accessing")
    print("computer material without authorization is an offence.")
    print("Only scan files that you own or have WRITTEN permission")
    print("to analyse. Misuse is the sole responsibility of the user.")
    print("=========================================================")


def require_confirmation():

    answer = input("\nDo you have authorization to scan the files? Type 'I AGREE' to continue: ").strip()

    if answer != "I AGREE":
        print("\n[!] Authorization not confirmed. Exiting MulScan.\n")
        sys.exit(0)

    print("[+] Authorization confirmed.")


def kill_switch_handler(signum, frame):

    print("\n\n[!] KILL SWITCH activated (Ctrl+C). Aborting safely...")
    print("[!] No data was modified. Goodbye.\n")
    sys.exit(0)


def install_kill_switch():

    signal.signal(signal.SIGINT, kill_switch_handler)
    print("[+] Kill switch active: press Ctrl+C at any time to abort.")


def set_scope():

    global allowed_scope

    print(f"\nDefault scan scope: {DEFAULT_SCOPE.resolve()}")
    user_scope = input("Press Enter to keep default, or type another folder: ").strip()

    if user_scope:
        user_scope = user_scope.strip("'\"")
        scope_path = Path(user_scope)

        if scope_path.is_dir():
            allowed_scope = scope_path
        else:
            print("[ERROR] Folder not found. Using default scope.")

    allowed_scope.mkdir(exist_ok=True)
    print(f"[+] Authorized scope set to: {allowed_scope.resolve()}")


def check_scope(file_path):

    try:
        file_path.resolve().relative_to(allowed_scope.resolve())
        return True

    except ValueError:
        print("\n[WARNING] This file is OUTSIDE the authorized scope!")
        print(f"          Scope: {allowed_scope.resolve()}")

        answer = input("Type 'YES' to confirm you are authorized to scan it: ").strip()

        if answer == "YES":
            return True

        print("[!] Scan blocked.")
        return False


def toggle_dry_run():

    global dry_run

    dry_run = not dry_run
    status = "ON" if dry_run else "OFF"
    print(f"\n[+] Dry-run mode is now {status}.")


def dry_run_summary(file_path):

    print("\n========== DRY-RUN SUMMARY ==========")
    print(f"File to scan : {file_path.name}")
    print(f"Full path    : {file_path.resolve()}")
    print(f"File size    : {file_path.stat().st_size} bytes")
    print("Action       : No analysis performed (dry-run)")
    print("=====================================")
