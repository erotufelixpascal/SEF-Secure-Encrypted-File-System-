# Part 2: Simplified SEFS (30 marks)

**Code:** [`src/sefs.c`](../src/sefs.c), [`src/chunk.c`](../src/chunk.c), [`src/meta.c`](../src/meta.c), [`src/crypto.c`](../src/crypto.c), [`src/util.c`](../src/util.c) · **Settings:** [`src/sefs_config.h`](../src/sefs_config.h) · **Status:** implemented, tests passing

---

## 1. What Part 2 must do

In the simplified version, each file becomes **one meta file plus one encrypted chunk**. Nine functions work on these files. Each one first checks the user's password (Part 1) and that the user owns the file.

> **How this relates to Part 3:** the code is written once for the general multi-chunk case. A file of 1,024 bytes or less uses exactly one chunk, which *is* the simplified SEFS. Demonstrate Part 2 with files of 1,024 bytes or less; Part 3 uses the same functions with larger files.

---

## 2. Building blocks

### 2.1 Crypto helpers ([`crypto.c`](../src/crypto.c))

| Function | Line | Purpose |
|---|---|---|
| `gen_random(buf, n)` | [9](../src/crypto.c#L9) | `RAND_bytes`: 128-bit chunk keys, IVs, random chunk names |
| `aes128_ctr(key, iv, in, len, out)` | [14](../src/crypto.c#L14) | AES-128 in CTR mode. Encrypting and decrypting are the same operation |
| `hmac_sha256(key, data, len, out)` | [27](../src/crypto.c#L27) | Tamper-detection tag for each chunk |
| `sha256(data, len, out)` | [35](../src/crypto.c#L35) | Digest of each meta file for the Master File List |

### 2.2 Master key and IV
- `build\Debug\keygen.exe master.key` writes 16 random key bytes followed by 16 random IV bytes ([`tools/keygen.c`](../tools/keygen.c)).
- `load_master_key` ([`util.c:134`](../src/util.c#L134)) reads it whenever a meta file is read or written. It is never hard-coded and never committed (`.gitignore`).

---

## 3. The file format

### 3.1 Chunk file: `chunks\<32 random hex chars>`
Exactly 1,076 bytes:

```
┌────────────┬────────────── AES-128-CTR with this chunk's own key ──────────────┐
│ IV (16 B)  │ next chunk name (32 B) │ size (4 B) │ content padded to 1,024 B │
│ plaintext  │ "NULL"+zeros if last   │ big-endian │ padding byte = 0x00       │
└────────────┴─────────────────────────────────────────────────────────────────┘
HMAC-SHA256(chunk key, whole file) is stored in the meta file
```

### 3.2 Meta file: `<filename>.meta`
Encrypted with the master key and IV. Plaintext layout:

```
alice01                                   ← owner
1                                         ← number of chunks
16                                        ← file size in bytes
3fa9…  (start chunk name)
3fa9…  (end chunk name; same as start when there is one chunk)
3fa9… <chunk key hex> <chunk HMAC hex>    ← one line per chunk
```

### 3.3 Master File List: `masterlist`
One plain line per file: `filename sha256-of-the-stored-meta-file`. Editing a meta file changes its SHA-256, so the edit is detected.

---

## 4. Internal steps every function relies on

| Helper | Where | What it does |
|---|---|---|
| `valid_filename` | [`sefs.c:13`](../src/sefs.c#L13) | Letters and digits only, 1–20 characters |
| `authorize` | [`sefs.c:48`](../src/sefs.c#L48) | `match_user` → Master File List entry exists → meta loads → (optionally) meta digest matches the list → user is the owner |
| `chunk_write` | [`chunk.c:43`](../src/chunk.c#L43) | Builds the body, **new random key and IV**, encrypts, computes the HMAC, saves via temp file |
| `chunk_read` | [`chunk.c:76`](../src/chunk.c#L76) | Checks the file length, **checks the HMAC before decrypting**, decrypts, validates the next-name field and padding |
| `meta_save` / `meta_load` | [`meta.c:124`](../src/meta.c#L124), [`meta.c:90`](../src/meta.c#L90) | Encrypt/decrypt and parse the meta file; `meta_save` also updates the Master File List digest |
| `verify_chain` | [`sefs.c:60`](../src/sefs.c#L60) | Reads every chunk listed in the meta file, verifies it, and returns the whole plaintext |
| `store_plaintext` | [`sefs.c:107`](../src/sefs.c#L107) | Splits data into chunks, writes them, saves the meta file, then deletes old chunks |

---

## 5. The nine functions

| Function | Line | Steps |
|---|---|---|
| `create_file(f, u, p)` | [156](../src/sefs.c#L156) | Validate name → check password → refuse if `f` already exists → store an empty file (one chunk, size 0) → add to Master File List |
| `encrypt_file(f, u, p)` | [169](../src/sefs.c#L169) | Read the plaintext file `f` from disk → new key, IV, chunk name → encrypt → HMAC → write chunk and meta → update digest. If `f` already exists in SEFS, only its owner may replace it |
| `decrypt_file(f, pf, u, p)` | [201](../src/sefs.c#L201) | `authorize` with digest check → **integrity check first** (`verify_chain`) → write plaintext to `pf` |
| `read_from_file(f, pos, len, u, p)` | [221](../src/sefs.c#L221) | Verify → return `len` bytes from `pos` as a new `char *` (free with `sefs_free`). `NULL` on any error, including reading past the end |
| `write_to_file(f, pos, text, u, p)` | [246](../src/sefs.c#L246) | Verify and decrypt → insert `text` at `pos` → re-encrypt with a **fresh IV** and new key → new HMAC → update meta and digest. `pos` beyond the end is rejected |
| `file_size(f, u, p)` | [281](../src/sefs.c#L281) | Read the size from the meta file (after checking the digest) |
| `file_integrity_check(f, u, p)` | [293](../src/sefs.c#L293) | Recompute the meta digest and every chunk HMAC; compare with stored values |
| `delete_file(f, u, p)` | [309](../src/sefs.c#L309) | Owner only → remove chunks, meta file and Master File List entry |
| `system_health_check(u, p)` | [326](../src/sefs.c#L326) | Run the integrity check on every file in the Master File List; -1 if any fails |

---

## 6. Rules respected

| Rule from the brief | How |
|---|---|
| Fresh IV whenever a chunk is re-encrypted | `chunk_write` always generates a new key and IV |
| Integrity before decryption | `chunk_read` verifies the HMAC before calling AES |
| Check every return value | Every OpenSSL, file and helper call is checked |
| Free every pointer | Buffers freed (and secrets wiped with `OPENSSL_cleanse`) on every path |
| Validate every input | File names, NULL pointers, negative or out-of-range positions and lengths |
| Binary file mode | All files opened with `"rb"` / `"wb"` |
| Crash-safe updates | Temp file then `MoveFileExA` for chunks, meta and Master File List |

---

## 7. Demonstration

Use a separate demo folder so the real project stays clean:

```powershell
cd SEF
.venv\Scripts\Activate.ps1
mkdir demo; cd demo
..\build\Debug\keygen.exe master.key
"hello SEFS world" | Out-File -NoNewline -Encoding ascii doc1
python
```

```python
import os, ctypes
D = os.path.abspath(r"..\build\Debug"); os.add_dll_directory(D)
lib = ctypes.CDLL(os.path.join(D, "sefs.dll"))
lib.read_from_file.restype = ctypes.c_void_p
lib.read_from_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
lib.sefs_free.argtypes = [ctypes.c_void_p]
def read(f, pos, n, u, p):
    ptr = lib.read_from_file(f, pos, n, u, p)
    if not ptr: return None
    data = ctypes.string_at(ptr, n); lib.sefs_free(ptr); return data

U, PW = b"alice01", b"Passw0rd#1"
lib.register_user(U, PW, b"passwd")                    # 1

lib.create_file(b"notes", U, PW)                       # 1   empty file, one chunk
lib.file_size(b"notes", U, PW)                         # 0
lib.write_to_file(b"notes", 0, b"helloworld", U, PW)   # 1
lib.write_to_file(b"notes", 5, b", ", U, PW)           # 1   insert in the middle
read(b"notes", 0, 12, U, PW)                           # b'hello, world'

lib.encrypt_file(b"doc1", U, PW)                       # 1   doc1 → doc1.meta + 1 chunk
read(b"doc1", 6, 4, U, PW)                             # b'SEFS'
read(b"doc1", 10, 100, U, PW)                          # None  past the end
lib.decrypt_file(b"doc1", b"doc1_out.txt", U, PW)      # 1
lib.file_integrity_check(b"doc1", U, PW)               # 1
lib.system_health_check(U, PW)                         # 1

lib.register_user(b"mallory", b"Mall0ry#pw", b"passwd")
lib.delete_file(b"doc1", b"mallory", b"Mall0ry#pw")    # -1  not the owner
lib.delete_file(b"doc1", U, PW)                        # 1
```

**Show the encryption:** open a file in `demo\chunks\` in a hex viewer (or Notepad). The text "hello SEFS world" does not appear. Delete the `demo` folder afterwards.

**Automated tests:** `python -m pytest tests\acceptance -k "create or encrypt_decrypt or write_inserts or non_owner or delete_file" -v`

---

## 8. Open points to confirm with the lecturer

| # | Question | Current setting |
|---|---|---|
| Q1 | Padding: byte `0x00` or character `'0'` | `0x00` (`SEFS_PAD_BYTE`) |
| Q3 | HMAC over ciphertext or plaintext; which key | Chunk key, over IV + ciphertext |
| Q4 | Meta file encryption, field order, separators | Master key + IV; layout in §3.2; spaces between fields; `\n` endings |
| Q5 | Chunk name length and characters | 32 lowercase hex characters |
| Q6 | Master File List encrypted? what is hashed? | Not encrypted; SHA-256 of the stored (encrypted) meta file |
| Q7 | Integrity before decryption; return on failure | Yes; `read_from_file` returns `NULL` |
| — | Should `encrypt_file` delete the plaintext? | No (`SEFS_REMOVE_PLAINTEXT 0`) |
| — | Exact function signatures | See [`src/sefs.h`](../src/sefs.h) |

**Spec weakness to raise:** encrypting every meta file with the same master key *and* IV in CTR mode reuses the keystream. XORing two meta files reveals the XOR of their plaintexts. Implemented as specified; discuss it under limitations.

---

## 9. Marking checklist

- [x] Crypto helpers wrapping OpenSSL
- [x] Master key and IV loaded from a file, never hard-coded
- [x] Meta file, chunk file and Master File List formats implemented
- [x] All nine functions implemented with password and ownership checks
- [x] Fresh IV on every re-encryption
- [x] Integrity checked before decryption
- [x] Input validation, return-value checks, memory cleanup
- [ ] Confirm Q1, Q3–Q7 with the lecturer
- [ ] Record the demonstration output in `logs\`
