"""Shared ctypes bindings and fixtures for every test suite (acceptance, manual, ai).

The `sefs` fixture gives each test a fresh working directory holding a throwaway
master.key, so passwd, chunks/, *.meta and masterlist never leak between tests.

Set SEFS_DLL_DIR to test another build (e.g. build-asan\\Debug).
"""
import ctypes
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DLL_DIR = Path(os.environ.get("SEFS_DLL_DIR", ROOT / "build" / "Debug"))  # sefs.dll + libcrypto-3-x64.dll
os.add_dll_directory(str(DLL_DIR))
lib = ctypes.CDLL(str(DLL_DIR / "sefs.dll"))

_s, _i = ctypes.c_char_p, ctypes.c_int
for _name, _args in {
    "register_user": [_s, _s, _s],
    "delete_user": [_s, _s, _s],
    "is_user_valid": [_s, _s],
    "match_user": [_s, _s, _s],
    "change_user_password": [_s, _s, _s, _s],
    "create_file": [_s, _s, _s],
    "encrypt_file": [_s, _s, _s],
    "decrypt_file": [_s, _s, _s, _s],
    "write_to_file": [_s, _i, _s, _s, _s],
    "file_integrity_check": [_s, _s, _s],
    "delete_file": [_s, _s, _s],
    "system_health_check": [_s, _s],
}.items():
    getattr(lib, _name).argtypes = _args
    getattr(lib, _name).restype = _i
lib.file_size.argtypes = [_s, _s, _s]
lib.file_size.restype = ctypes.c_long
# c_void_p (not c_char_p) so we keep the pointer, copy the bytes and free it inside the DLL
lib.read_from_file.argtypes = [_s, _i, _i, _s, _s]
lib.read_from_file.restype = ctypes.c_void_p
lib.sefs_free.argtypes = [ctypes.c_void_p]
lib.sefs_free.restype = None

CHUNK_SIZE = 1024
PASSWD = "passwd"


def _b(x):
    return x.encode() if isinstance(x, str) else x


class Sefs:
    """Thin wrapper: str or bytes in, the C return value out. read_from_file returns bytes or None."""

    def __init__(self, workdir: Path):
        self.lib = lib
        self.dir = workdir

    # Part 1
    def register_user(self, u, p, pfile=PASSWD):
        return lib.register_user(_b(u), _b(p), _b(pfile))

    def delete_user(self, u, p, pfile=PASSWD):
        return lib.delete_user(_b(u), _b(p), _b(pfile))

    def is_user_valid(self, u, pfile=PASSWD):
        return lib.is_user_valid(_b(u), _b(pfile))

    def match_user(self, u, p, pfile=PASSWD):
        return lib.match_user(_b(u), _b(p), _b(pfile))

    def change_user_password(self, u, p, pn, pfile=PASSWD):
        return lib.change_user_password(_b(u), _b(p), _b(pn), _b(pfile))

    # Parts 2-3
    def create_file(self, f, u, p):
        return lib.create_file(_b(f), _b(u), _b(p))

    def encrypt_file(self, f, u, p):
        return lib.encrypt_file(_b(f), _b(u), _b(p))

    def decrypt_file(self, f, pf, u, p):
        return lib.decrypt_file(_b(f), _b(pf), _b(u), _b(p))

    def read_from_file(self, f, pos, length, u, p):
        ptr = lib.read_from_file(_b(f), pos, length, _b(u), _b(p))
        if not ptr:
            return None
        try:
            return ctypes.string_at(ptr, length)
        finally:
            lib.sefs_free(ptr)

    def write_to_file(self, f, pos, content, u, p):
        return lib.write_to_file(_b(f), pos, _b(content), _b(u), _b(p))

    def file_size(self, f, u, p):
        return lib.file_size(_b(f), _b(u), _b(p))

    def file_integrity_check(self, f, u, p):
        return lib.file_integrity_check(_b(f), _b(u), _b(p))

    def delete_file(self, f, u, p):
        return lib.delete_file(_b(f), _b(u), _b(p))

    def system_health_check(self, u, p):
        return lib.system_health_check(_b(u), _b(p))

    # Helpers for inspecting on-disk state
    def chunk_files(self):
        d = self.dir / "chunks"
        return sorted(d.iterdir()) if d.exists() else []

    def write_plain(self, name, data: bytes):
        (self.dir / name).write_bytes(data)


@pytest.fixture
def sefs(tmp_path, monkeypatch):
    (tmp_path / "master.key").write_bytes(os.urandom(32))  # throwaway test key
    monkeypatch.chdir(tmp_path)
    return Sefs(tmp_path)


@pytest.fixture
def user(sefs):
    """A registered user (username, password)."""
    u, p = "alice01", "Passw0rd#1"
    assert sefs.register_user(u, p) == 1
    return u, p
