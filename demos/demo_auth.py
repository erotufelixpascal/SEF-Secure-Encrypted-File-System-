"""Part 1 demonstration: calls every function in src/auth.c through sefs.dll.

Run from the SEF folder:
    .venv\\Scripts\\python.exe demos\\demo_auth.py

Uses a throwaway password file (demos\\demo_passwd) and deletes it at the end.
"""
import ctypes
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DLL_DIR = ROOT / "build" / "Debug"
os.add_dll_directory(str(DLL_DIR))
lib = ctypes.CDLL(str(DLL_DIR / "sefs.dll"))

PASSWD = ROOT / "demos" / "demo_passwd"
P = str(PASSWD).encode()


def show(label, result, expected):
    mark = "OK " if result == expected else "!! "
    print(f"{mark} {label:<55} -> {result:>2}   (expected {expected})")


def show_file():
    text = PASSWD.read_text() if PASSWD.exists() else ""
    print("     passwd file:", text.strip() or "(empty)")
    print()


if PASSWD.exists():
    PASSWD.unlink()

print("=== register_user ===")
show("register alice01 / Passw0rd#1", lib.register_user(b"alice01", b"Passw0rd#1", P), 1)
show("register alice01 again (duplicate)", lib.register_user(b"alice01", b"Passw0rd#1", P), -1)
show("register 'bob' (username too short, 3 chars)", lib.register_user(b"bob", b"Passw0rd#1", P), -1)
show("register carol01 / 'short' (password too short)", lib.register_user(b"carol01", b"short", P), -1)
show("register bob_01 ('_' not allowed)", lib.register_user(b"bob_01", b"Passw0rd#1", P), -1)
show_file()

print("=== is_user_valid ===")
show("alice01 exists", lib.is_user_valid(b"alice01", P), 1)
show("nobody99 exists", lib.is_user_valid(b"nobody99", P), -1)
print()

print("=== match_user (login) ===")
show("alice01 with correct password", lib.match_user(b"alice01", b"Passw0rd#1", P), 1)
show("alice01 with wrong password", lib.match_user(b"alice01", b"WrongPass#1", P), -1)
print()

print("=== change_user_password ===")
show("change with wrong old password", lib.change_user_password(b"alice01", b"WrongPass#1", b"NewPassw0rd=", P), -1)
show("change to NewPassw0rd=", lib.change_user_password(b"alice01", b"Passw0rd#1", b"NewPassw0rd=", P), 1)
show("old password no longer works", lib.match_user(b"alice01", b"Passw0rd#1", P), -1)
show("new password works", lib.match_user(b"alice01", b"NewPassw0rd=", P), 1)
show_file()

print("=== delete_user ===")
show("delete with wrong password", lib.delete_user(b"alice01", b"WrongPass#1", P), -1)
show("delete with correct password", lib.delete_user(b"alice01", b"NewPassw0rd=", P), 1)
show("alice01 still exists?", lib.is_user_valid(b"alice01", P), -1)
show_file()

PASSWD.unlink(missing_ok=True)
