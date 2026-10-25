"""Interactive Part 1 demo: type a username and password and see what src/auth.c decides.

Run from the SEF folder:
    .venv\\Scripts\\python.exe demos\\auth_interactive.py

Users are stored in demos\\passwd, which stays between runs (option 7 clears it).
Every OK/ERROR result comes from the C code in sefs.dll. When the C code returns
an error, the "why" lines are only a Python explanation of the rules in
src/sefs_config.h, to help you see which rule was broken.
"""
import ctypes
import getpass
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DLL_DIR = ROOT / "build" / "Debug"
os.add_dll_directory(str(DLL_DIR))
lib = ctypes.CDLL(str(DLL_DIR / "sefs.dll"))

PASSWD = ROOT / "demos" / "passwd"
P = str(PASSWD).encode()

# Mirrors src/sefs_config.h; used only to explain errors
USER_MIN, USER_MAX = 6, 31
PASS_MIN, PASS_MAX = 9, 31
PASS_EXTRA = "@#$%&*()-+="


def shown(chars):
    return " ".join("(space)" if c == " " else c for c in chars)


def username_problems(u):
    problems = []
    if not USER_MIN <= len(u) <= USER_MAX:
        problems.append(f"username must be {USER_MIN}-{USER_MAX} characters (you typed {len(u)})")
    bad = sorted(set(c for c in u if not (c.isascii() and c.isalnum())))
    if bad:
        problems.append(f"username may only contain letters and digits; not allowed: {shown(bad)}")
    return problems


def password_problems(p, label="password"):
    problems = []
    if not PASS_MIN <= len(p) <= PASS_MAX:
        problems.append(f"{label} must be {PASS_MIN}-{PASS_MAX} characters (you typed {len(p)})")
    bad = sorted(set(c for c in p if not ((c.isascii() and c.isalnum()) or c in PASS_EXTRA)))
    if bad:
        problems.append(f"{label} may only contain letters, digits and {PASS_EXTRA}; not allowed: {shown(bad)}")
    return problems


def ask(prompt):
    return input(prompt).strip().lstrip("﻿")


def ask_password(prompt):
    # Hidden typing in a real terminal; plain input when piped (e.g. automated runs)
    if sys.stdin.isatty():
        return getpass.getpass(prompt + " (hidden) ")
    return input(prompt + " ")


def user_exists(u):
    return lib.is_user_valid(u.encode(), P) == 1


def report(ok, success, failure, reasons=()):
    if ok:
        print(f"\n  [OK]    {success}\n")
    else:
        print(f"\n  [ERROR] {failure}")
        for r in reasons:
            print(f"          - {r}")
        print()


def do_register():
    u = ask("Username: ")
    p = ask_password("Password:")
    ok = lib.register_user(u.encode(), p.encode(), P) == 1
    reasons = username_problems(u) + password_problems(p)
    if not ok and not reasons and user_exists(u):
        reasons = [f"user '{u}' already exists"]
    report(ok, f"user '{u}' registered (salt + PBKDF2 hash written to passwd)",
           "registration rejected", reasons)


def do_login():
    u = ask("Username: ")
    p = ask_password("Password:")
    ok = lib.match_user(u.encode(), p.encode(), P) == 1
    reasons = username_problems(u) + password_problems(p)
    if not ok and not reasons:
        reasons = ["no such user" if not user_exists(u) else "wrong password"]
    report(ok, f"login successful, password matches for '{u}'", "login failed", reasons)


def do_check():
    u = ask("Username: ")
    ok = lib.is_user_valid(u.encode(), P) == 1
    reasons = username_problems(u) or ["not found in passwd"]
    report(ok, f"user '{u}' exists", f"user '{u}' is not valid", reasons)


def do_change():
    u = ask("Username: ")
    p = ask_password("Current password:")
    pn = ask_password("New password:")
    ok = lib.change_user_password(u.encode(), p.encode(), pn.encode(), P) == 1
    reasons = password_problems(pn, "new password")
    if not ok and not reasons:
        reasons = ["no such user" if not user_exists(u) else "current password is wrong"]
    report(ok, f"password changed for '{u}' (new salt and hash)", "password change rejected", reasons)


def do_delete():
    u = ask("Username: ")
    p = ask_password("Password:")
    ok = lib.delete_user(u.encode(), p.encode(), P) == 1
    reasons = [] if ok else ["no such user" if not user_exists(u) else "wrong password"]
    report(ok, f"user '{u}' deleted", "delete rejected", reasons)


def do_show():
    lines = PASSWD.read_text().splitlines() if PASSWD.exists() else []
    print()
    if not lines:
        print("  passwd is empty\n")
        return
    print(f"  {'username':<20} {'salt (first 16 hex)':<22} hash (first 16 hex)")
    for line in lines:
        name, salt, digest = (line.split(":") + ["", ""])[:3]
        print(f"  {name:<20} {salt[:16] + '...':<22} {digest[:16]}...")
    print()


def do_clear():
    PASSWD.unlink(missing_ok=True)
    print("\n  [OK]    passwd cleared\n")


MENU = {
    "1": ("Register a new user", do_register),
    "2": ("Log in (match_user)", do_login),
    "3": ("Check a username exists (is_user_valid)", do_check),
    "4": ("Change password", do_change),
    "5": ("Delete a user", do_delete),
    "6": ("Show passwd file", do_show),
    "7": ("Clear all users", do_clear),
    "0": ("Quit", None),
}


def main():
    print("SEFS Part 1: user authentication")
    print(f"Rules: username {USER_MIN}-{USER_MAX} letters/digits; "
          f"password {PASS_MIN}-{PASS_MAX} letters/digits/{PASS_EXTRA}")
    while True:
        print("-" * 50)
        for key, (label, _) in MENU.items():
            print(f"  {key}. {label}")
        try:
            choice = ask("Choose: ")
        except EOFError:
            break
        if choice == "0":
            break
        action = MENU.get(choice)
        if action is None:
            print("\n  Please choose 0-7.\n")
            continue
        try:
            action[1]()
        except EOFError:
            break
    print("Bye.")


if __name__ == "__main__":
    main()
