"""Step 6 acceptance checklist: proves sefs-v1.0 works. Not one of the experiment arms."""
import os

CHUNK = 1024


# ---- Part 1: authentication ----

def test_register_and_match(sefs):
    assert sefs.register_user("alice01", "Passw0rd#1") == 1
    assert sefs.is_user_valid("alice01") == 1
    assert sefs.match_user("alice01", "Passw0rd#1") == 1
    assert sefs.match_user("alice01", "Passw0rd#2") == -1
    assert sefs.register_user("alice01", "Other0ne#9") == -1  # duplicate


def test_passwd_line_format(sefs, user):
    line = (sefs.dir / "passwd").read_bytes()
    assert line.endswith(b"\n") and b"\r" not in line
    name, salt, digest = line.strip().split(b":")
    assert name == b"alice01" and len(salt) == 64 and len(digest) == 40


def test_input_validation_boundaries(sefs):
    assert sefs.register_user("a" * 5, "Passw0rd#1") == -1
    assert sefs.register_user("a" * 6, "Passw0rd#1") == 1
    assert sefs.register_user("b" * 31, "Passw0rd#1") == 1
    assert sefs.register_user("c" * 32, "Passw0rd#1") == -1
    assert sefs.register_user("bob_01", "Passw0rd#1") == -1  # '_' not allowed
    assert sefs.register_user("bobby1", "p" * 8) == -1
    assert sefs.register_user("bobby1", "p" * 9) == 1
    assert sefs.register_user("bobby2", "p" * 32) == -1


def test_change_password(sefs, user):
    u, p = user
    assert sefs.change_user_password(u, "WrongPass#1", "NewPassw0rd!") == -1
    assert sefs.change_user_password(u, p, "short") == -1
    assert sefs.change_user_password(u, p, "NewPassw0rd=") == 1
    assert sefs.match_user(u, p) == -1
    assert sefs.match_user(u, "NewPassw0rd=") == 1


def test_delete_user_removes_only_that_line(sefs, user):
    u, p = user
    assert sefs.register_user("bobby01", "Bobpass#99") == 1
    assert sefs.delete_user(u, "WrongPass#1") == -1
    assert sefs.delete_user(u, p) == 1
    assert sefs.is_user_valid(u) == -1
    assert sefs.match_user("bobby01", "Bobpass#99") == 1


# ---- Part 2: simplified SEFS ----

def test_create_empty_file(sefs, user):
    assert sefs.create_file("notes", *user) == 1
    assert sefs.create_file("notes", *user) == -1
    assert sefs.file_size("notes", *user) == 0
    assert len(sefs.chunk_files()) == 1
    assert sefs.file_integrity_check("notes", *user) == 1


def test_encrypt_decrypt_read(sefs, user):
    data = b"hello SEFS world"
    sefs.write_plain("doc1", data)
    assert sefs.encrypt_file("doc1", *user) == 1
    assert data not in sefs.chunk_files()[0].read_bytes()
    assert sefs.file_size("doc1", *user) == len(data)
    assert sefs.read_from_file("doc1", 6, 4, *user) == b"SEFS"
    assert sefs.read_from_file("doc1", 10, 100, *user) is None  # past the end
    assert sefs.decrypt_file("doc1", "out.txt", *user) == 1
    assert (sefs.dir / "out.txt").read_bytes() == data


def test_write_inserts(sefs, user):
    assert sefs.create_file("memo", *user) == 1
    assert sefs.write_to_file("memo", 0, "helloworld", *user) == 1
    assert sefs.write_to_file("memo", 5, ", ", *user) == 1
    assert sefs.read_from_file("memo", 0, 12, *user) == b"hello, world"
    assert sefs.write_to_file("memo", 13, "x", *user) == -1  # beyond end


def test_non_owner_denied(sefs, user):
    assert sefs.register_user("mallory", "Mall0ry#pw") == 1
    assert sefs.create_file("secret", *user) == 1
    assert sefs.read_from_file("secret", 0, 0, "mallory", "Mall0ry#pw") is None
    assert sefs.delete_file("secret", "mallory", "Mall0ry#pw") == -1
    assert sefs.file_size("secret", "mallory", "Mall0ry#pw") == -1


def test_delete_file(sefs, user):
    sefs.write_plain("gone", b"x" * 3000)
    assert sefs.encrypt_file("gone", *user) == 1
    assert sefs.delete_file("gone", *user) == 1
    assert sefs.chunk_files() == []
    assert not (sefs.dir / "gone.meta").exists()
    assert sefs.file_size("gone", *user) == -1


# ---- Part 3: multi-chunk ----

def test_three_chunk_round_trip(sefs, user):
    data = os.urandom(2 * CHUNK + 500)
    sefs.write_plain("big", data)
    assert sefs.encrypt_file("big", *user) == 1
    assert len(sefs.chunk_files()) == 3
    assert sefs.read_from_file("big", CHUNK - 10, 20, *user) == data[CHUNK - 10:CHUNK + 10]
    assert sefs.decrypt_file("big", "big.out", *user) == 1
    assert (sefs.dir / "big.out").read_bytes() == data


def test_append_to_partial_chunk_stays_one_chunk(sefs, user):
    sefs.write_plain("part", b"a" * 512)
    assert sefs.encrypt_file("part", *user) == 1
    assert sefs.write_to_file("part", 512, "b" * 200, *user) == 1
    assert sefs.file_size("part", *user) == 712
    assert len(sefs.chunk_files()) == 1


def test_insert_spills_into_new_chunk(sefs, user):
    sefs.write_plain("grow", b"a" * CHUNK)
    assert sefs.encrypt_file("grow", *user) == 1
    assert len(sefs.chunk_files()) == 1
    assert sefs.write_to_file("grow", 10, "XYZ", *user) == 1
    assert len(sefs.chunk_files()) == 2
    assert sefs.read_from_file("grow", 8, 7, *user) == b"aaXYZaa"


# ---- Tamper handling ----

def test_tampered_chunk_detected(sefs, user):
    sefs.write_plain("t", os.urandom(3000))
    assert sefs.encrypt_file("t", *user) == 1
    assert sefs.system_health_check(*user) == 1
    victim = sefs.chunk_files()[1]
    raw = bytearray(victim.read_bytes())
    raw[100] ^= 0x01
    victim.write_bytes(bytes(raw))
    assert sefs.file_integrity_check("t", *user) == -1
    assert sefs.read_from_file("t", 0, 10, *user) is None
    assert sefs.system_health_check(*user) == -1


def test_tampered_meta_detected(sefs, user):
    assert sefs.create_file("m", *user) == 1
    meta = sefs.dir / "m.meta"
    raw = bytearray(meta.read_bytes())
    raw[0] ^= 0x01
    meta.write_bytes(bytes(raw))
    assert sefs.file_integrity_check("m", *user) == -1
