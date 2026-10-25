# Part 3: Full Multi-Chunk SEFS (45 marks)

**Code:** [`src/sefs.c`](../src/sefs.c) (mainly `store_plaintext` and `verify_chain`), [`src/chunk.c`](../src/chunk.c), [`src/meta.c`](../src/meta.c) · **Status:** implemented, tests passing

---

## 1. What Part 3 must do

Generalise Part 2 so one file can span **many chunks**, each holding at most 1,024 bytes of plaintext and linked together like a chain. The same nine functions from Part 2 must work across chunk boundaries.

```
report.meta  (start = A, end = C, 3 chunks, size 2,548)
     │
     ▼
 ┌─────────┐ next  ┌─────────┐ next  ┌─────────┐ next
 │ chunk A │──────►│ chunk B │──────►│ chunk C │──────► NULL
 │ 1,024 B │       │ 1,024 B │       │  500 B  │
 └─────────┘       └─────────┘       │+ padding│
                                     └─────────┘
```

Each chunk has its **own** random key, IV and name. The meta file lists them in order with each chunk's key and HMAC.

---

## 2. The rules and how each is met

### 2.1 Chunk count rule
> A file of size S uses exactly **max(1, ⌈S / 1024⌉)** chunks. Never create a new chunk while the last chunk has free space.

| File size | Chunks |
|---|---|
| 0 | 1 (empty) |
| 1 – 1,024 | 1 |
| 1,025 – 2,048 | 2 |
| 2,049 – 3,072 | 3 |

`store_plaintext` ([`sefs.c:107`](../src/sefs.c#L107)) computes `n = len == 0 ? 1 : (len + 1023) / 1024`. `verify_chain` ([`sefs.c:60`](../src/sefs.c#L60)) rejects any meta file whose chunk count breaks this rule.

### 2.2 Splitting on encrypt
`store_plaintext`:
1. Generates all `n` random chunk names first, so every chunk knows the name of the next one.
2. For each 1,024-byte block `i`: new key, new IV, record the size, pad the last block with the padding byte, set `next = name[i+1]`, or `NULL` for the last chunk.
3. Writes each chunk with `chunk_write` ([`chunk.c:43`](../src/chunk.c#L43)).
4. Builds the meta file (count, size, start, end, one line per chunk) and saves it with `meta_save`, which also updates the Master File List digest.
5. **Only then** deletes the old chunks. If anything fails before this, the new chunks are removed and the old file is untouched.

### 2.3 Position mapping
A byte position maps to `chunk index = position / 1024` and `offset = position % 1024`. For example, position 2,050 is chunk 2, offset 2.

`verify_chain` decrypts the chain from the start chunk into one continuous buffer, in chain order. Every position therefore maps to the right chunk and offset automatically, with no separate lookup that could be off by one.

### 2.4 Reading across chunks
`read_from_file` ([`sefs.c:221`](../src/sefs.c#L221)) may start in one chunk and end in another, e.g. reading 20 bytes from position 1,014 takes 10 bytes from chunk A and 10 from chunk B. **Every chunk's HMAC is verified before its plaintext is used** (`chunk_read` checks it before decrypting).

### 2.5 Writing and inserting
The slides warn that you can't simply overwrite in the middle of a file in C. `write_to_file` ([`sefs.c:246`](../src/sefs.c#L246)) uses the simplest correct approach:

1. Verify and decrypt the whole chain.
2. Build the new plaintext: `old[0:pos] + new text + old[pos:]`, so later content shifts forward.
3. Re-split into the **minimum** number of chunks (§2.2), with fresh keys and IVs for all of them.
4. Update the meta file and Master File List, then delete the old chunks.

### 2.6 Appending to a partial chunk
Example from the slides: a chunk holding 512 bytes plus a 200-byte write at the end must stay **one chunk of 712 bytes**, not become two. This works automatically because re-splitting always uses ⌈712 / 1024⌉ = 1 chunk.

### 2.7 Updating the meta file consistently
Chunk count, file size, start and end chunk names, and every chunk's key and HMAC line are all rebuilt together in one `sefs_meta` structure and saved in one write. That write goes to `F.meta.tmp`, then `MoveFileExA` replaces the old meta file ([`util.c:58`](../src/util.c#L58)).

### 2.8 Removing orphans
Old chunk files are deleted only after the new meta file is safely saved (end of `store_plaintext`). `delete_file` removes every chunk listed in the meta file.

### 2.9 Integrity across the chain
`file_integrity_check` ([`sefs.c:293`](../src/sefs.c#L293)) → `verify_chain` detects:

| Attack | How it is detected |
|---|---|
| **Modified** chunk (any byte flipped) | HMAC mismatch |
| **Missing** chunk (file deleted) | Chunk file can't be read |
| **Swapped** chunks (two files renamed) | Each is checked with the other's key → HMAC mismatch |
| **Extra** chunk inserted into the chain | Changing a next link means editing a chunk → HMAC mismatch; the count and size checks also fail |
| **Broken next-chunk link** | Decrypted next name ≠ next name in the meta file |
| Wrong chunk count / size in meta | Count must equal ⌈size/1024⌉; sizes must add up; all chunks except the last must be full |
| **Edited meta file** | SHA-256 no longer matches the Master File List |
| Start/end names wrong | Must equal the first and last chunk in the list |

`system_health_check` ([`sefs.c:326`](../src/sefs.c#L326)) runs this on every file in the Master File List.

### 2.10 Memory and errors
Every allocation is freed on every path, and plaintext buffers are wiped with `OPENSSL_cleanse` before being freed. The code compiles with no warnings at `/W4`.

---

## 3. Demonstration

Set up a demo folder (same as Part 2):

```powershell
cd SEF
.venv\Scripts\Activate.ps1
mkdir demo; cd demo
..\build\Debug\keygen.exe master.key
python
```

```python
import os, ctypes, glob
D = os.path.abspath(r"..\build\Debug"); os.add_dll_directory(D)
lib = ctypes.CDLL(os.path.join(D, "sefs.dll"))
lib.read_from_file.restype = ctypes.c_void_p
lib.read_from_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
lib.sefs_free.argtypes = [ctypes.c_void_p]
def read(f, pos, n, u, p):
    ptr = lib.read_from_file(f, pos, n, u, p)
    if not ptr: return None
    data = ctypes.string_at(ptr, n); lib.sefs_free(ptr); return data
chunks = lambda: len(glob.glob("chunks/*"))

U, PW = b"alice01", b"Passw0rd#1"
lib.register_user(U, PW, b"passwd")

# 1. Multi-chunk encrypt: 2,548 bytes → 3 chunks
data = b"A" * 1024 + b"B" * 1024 + b"C" * 500
open("report", "wb").write(data)
lib.encrypt_file(b"report", U, PW)        # 1
chunks()                                  # 3
lib.file_size(b"report", U, PW)           # 2548

# 2. Read across a chunk boundary (positions 1,019–1,028)
read(b"report", 1019, 10, U, PW)          # b'AAAAABBBBB'

# 3. Insert in the middle of chunk A: content shifts, file grows to 2,551 bytes, still 3 chunks
lib.write_to_file(b"report", 10, b"xyz", U, PW)
read(b"report", 8, 7, U, PW)              # b'AAxyzAA'
chunks()                                  # 3

# 4. Append to a partial chunk stays one chunk (512 + 200 = 712)
open("small", "wb").write(b"s" * 512)
lib.encrypt_file(b"small", U, PW)
lib.write_to_file(b"small", 512, b"t" * 200, U, PW)
lib.file_size(b"small", U, PW)            # 712
chunks()                                  # 4  (3 for report + 1 for small)

# 5. Tamper: flip one byte in a chunk → detected
lib.system_health_check(U, PW)            # 1
victim = sorted(glob.glob("chunks/*"))[0]
raw = bytearray(open(victim, "rb").read()); raw[100] ^= 1
open(victim, "wb").write(raw)
lib.system_health_check(U, PW)            # -1  something was tampered with
```

Then test which file was hit with `lib.file_integrity_check(b"report", U, PW)` and `lib.file_integrity_check(b"small", U, PW)`: the tampered one returns -1, and reading from it returns `None`. Try deleting or swapping chunk files too. Delete the `demo` folder when finished.

**Automated tests:** `python -m pytest tests\acceptance -k "three_chunk or append or spills or tamper" -v`

---

## 4. Still to do for full marks

| Task | Command / note |
|---|---|
| AddressSanitizer run | `cmake -B build-asan -S . -DSEFS_ASAN=ON -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake`, `cmake --build build-asan --config Debug`, then `$env:SEFS_DLL_DIR="build-asan\Debug"; python -m pytest tests\acceptance` |
| Leak check | Install Dr. Memory, then `drmemory -- python -m pytest tests -q` |
| Larger files | Optionally add tests at sizes 1,023 / 1,024 / 1,025 / 2,048 / 3,073 (your Step 8 manual suite will cover these) |
| Record demo | Save the output in `logs\` |

---

## 5. Marking checklist

- [x] Files span a linked list of chunks, at most 1,024 bytes each
- [x] Exactly max(1, ⌈S/1024⌉) chunks; no new chunk while the last has space
- [x] Splitting with a new key, IV and random name per chunk; last chunk padded; `NULL` next link
- [x] Reads across chunk boundaries, HMAC verified first
- [x] Insert in the middle shifts later content; re-split to the minimum chunks
- [x] Append to a partial chunk stays in that chunk
- [x] Meta file updated consistently and atomically
- [x] Old chunks removed only after the new ones are safely written
- [x] Detects modified, missing, swapped and extra chunks, and broken links
- [ ] AddressSanitizer and Dr. Memory runs clean
- [ ] Demonstration recorded
