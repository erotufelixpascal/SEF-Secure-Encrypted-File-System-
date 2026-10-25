# Cross-Group Interoperability (5 marks)

**Log:** [`logs/interop_log.csv`](../logs/interop_log.csv) · **Format settings:** [`src/sefs_config.h`](../src/sefs_config.h) · **Status:** not started. Needs the lecturer's answers and other groups.

---

## 1. What interoperability means

Every group writes its own SEFS, but all must use the **same lecturer-approved file format**. Then:

- your code can **decrypt files created by another group**;
- another group's code can **decrypt files you created**;
- `passwd` entries created by one implementation **verify** in the other.

If any single detail differs (padding byte, hex case, a separator, the order of fields), the files are unreadable to the other group. That's why the guide says not to finalise the file format until the lecturer answers the Step 2 questions.

---

## 2. Everything that must match between groups

Every one of these is a constant in `src/sefs_config.h` or part of the format code. The current values are **placeholders**.

| Area | Detail | Current placeholder | Where in code |
|---|---|---|---|
| **passwd** | Line format | `username:salthex:hashhex\n` | `make_entry`, [`auth.c:92`](../src/auth.c#L92) |
| | Salt length | 32 bytes | `SEFS_SALT_LEN` |
| | Hash function / iterations | PBKDF2-HMAC-SHA1, 20,000 | `hash_password`, [`auth.c:41`](../src/auth.c#L41) |
| | Hash length (Q2) | 20 bytes | `SEFS_HASH_LEN` |
| | Hex case (Q2) | lowercase written, both read | `SEFS_HEX_UPPER` |
| **Master key** | Key file format | 16-byte key then 16-byte IV | `load_master_key`, [`util.c:134`](../src/util.c#L134) |
| **Chunk** | Name (Q5) | 32 lowercase hex characters | `SEFS_CHUNK_NAME_BYTES` |
| | Layout | IV (16) ‖ AES-CTR( next name (32) ‖ size (4, big-endian) ‖ content (1,024) ) | `chunk_write`, [`chunk.c:43`](../src/chunk.c#L43) |
| | Last-chunk marker | `"NULL"` + zero bytes | `SEFS_NULL_NAME` |
| | Padding (Q1) | `0x00` | `SEFS_PAD_BYTE` |
| | HMAC (Q3) | HMAC-SHA256, chunk key, over IV ‖ ciphertext | `chunk_write` |
| | Folder | `chunks\` | `SEFS_CHUNK_DIR` |
| **Meta** | Encryption (Q4) | AES-128-CTR, master key + master IV | `meta_save`, [`meta.c:124`](../src/meta.c#L124) |
| | Field order (Q4) | owner, count, size, start, end, then `name key hmac` per chunk | `meta_save` |
| | Separators / endings (Q4) | single space; `\n` | `meta_save` |
| | File name | `<filename>.meta` | `SEFS_META_EXT` |
| **Master File List** | Encrypted? (Q6) | No | `masterlist_put`, [`meta.c:193`](../src/meta.c#L193) |
| | What is hashed (Q6) | SHA-256 of the stored meta file | `meta_save` |
| | Line format | `filename sha256hex\n` | `masterlist_put` |
| **General** | Line endings | `\n` only, binary mode | everywhere |

---

## 3. Step-by-step procedure

### Step 1: Get the agreed format
1. Read `SEFS_Lecturer_Technical_Clarifications.md` (not yet in the project folder).
2. Email the lecturer any questions it doesn't settle (Q1–Q9 in `README.md`).
3. Record each answer in the `README.md` table.

### Step 2: Update the code to match
1. Change the constants in `src/sefs_config.h`. For layout changes (field order, separators), edit `chunk_write`/`chunk_read` or `meta_save`/`meta_parse`.
2. Rebuild in **Developer PowerShell for VS 2022**: `cmake --build build --config Debug`
3. Rerun `python -m pytest tests\acceptance -v`. It must still pass 15/15.

### Step 3: Agree the exchange with the other groups (Q9)
Decide together:
- **Test master key:** a shared, throwaway `master.key` used **only** for interop testing. Never your real one.
- **Test users:** e.g. `group6user` / `Interop#2026`.
- **Test files:** a small set covering the edge cases, for example:

| File | Size | Why |
|---|---|---|
| `empty` | 0 B | one empty chunk |
| `small` | 100 B | single chunk with padding |
| `exact` | 1,024 B | exactly full, must be 1 chunk |
| `twochunk` | 1,025 B | spills by 1 byte |
| `multi` | 3,000 B | 3 chunks |
| `binary` | 2,000 random bytes, including 0x00 and 0x1A | catches text-mode bugs |

- **How to swap files:** a shared folder or zip containing `passwd`, `masterlist`, the `*.meta` files and the `chunks\` folder, plus the original plaintexts so results can be compared.

### Step 4: Produce your files
In an empty folder holding the shared test `master.key`:
```python
# after the same ctypes setup as in PART2/PART3 docs
lib.register_user(b"group6user", b"Interop#2026", b"passwd")
for name in [b"empty", b"small", b"exact", b"twochunk", b"multi", b"binary"]:
    lib.encrypt_file(name, b"group6user", b"Interop#2026")   # plaintext files prepared beforehand
```
Zip `passwd`, `masterlist`, `*.meta` and `chunks\` and send them.

### Step 5: Test the other group's files (incoming)
In a fresh folder with their files and the shared key:

| Check | Call | Expected |
|---|---|---|
| Their passwd verifies with your code | `match_user(their_user, their_pw, b"passwd")` | 1 |
| Their files pass integrity | `file_integrity_check(name, …)` and `system_health_check(…)` | 1 |
| Sizes match | `file_size(name, …)` | original size |
| Content matches | `decrypt_file(name, b"out", …)`, then compare `out` with their original byte for byte | identical |
| Reading across a boundary works | `read_from_file(b"multi", 1020, 10, …)` | matches original bytes 1,020–1,029 |

### Step 6: They test your files (outgoing)
Ask them to run the same checks with their code on your files, and to report the results.

### Step 7: Log everything
Add one row to `logs\interop_log.csv` per check:

```
date,group,direction,file_or_entry,result,mismatch,resolution
2026-11-05,Group 3,incoming,multi,pass,,
2026-11-05,Group 3,incoming,passwd,fail,hash written in uppercase hex,both sides now accept either case
2026-11-05,Group 3,outgoing,binary,pass,,
```

`direction` is `incoming` (you read their files) or `outgoing` (they read yours). Log every mismatch and how it was resolved; the brief asks for this.

---

## 4. When something doesn't match: debugging order

Check from the outermost layer inwards:

1. **passwd fails?** Compare one line by eye: hex case, salt length (64 hex), hash length (40 or 64 hex), separators.
2. **Master File List digest fails?** Their meta file bytes differ from what they hashed, or one side hashes the plaintext meta.
3. **Meta won't decrypt or parse?** Different master key/IV, different field order, separators, or `\r\n` endings. Decrypt it by hand with the shared key and look at the text.
4. **Chunk HMAC fails?** HMAC computed over different data (plaintext vs ciphertext, with or without the IV) or with a different key.
5. **Content wrong but HMAC passes?** Different padding byte, size-field byte order, or next-name field width.

Fixing a mismatch usually means changing one constant in `src/sefs_config.h`. If both groups are unsure who is right, ask the lecturer, and log the decision.

---

## 5. Windows-specific traps

| Trap | Protection already in place |
|---|---|
| Text mode turns `\n` into `\r\n` and treats byte 0x1A as end-of-file | Every file opened in binary mode |
| Git converting line endings | `git config core.autocrlf false` and `.gitattributes` `* -text` |
| 32-bit vs 64-bit mismatch | Everything built and run as x64 |

---

## 6. Marking checklist

- [ ] Lecturer's answers to Q1–Q9 recorded in `README.md`
- [ ] `src/sefs_config.h` updated to the agreed format; tests still pass
- [ ] Shared test key, users and file set agreed with at least one other group
- [ ] Their files decrypt correctly with our code (incoming)
- [ ] Our files decrypt correctly with their code (outgoing)
- [ ] `passwd` entries verify across implementations, both directions
- [ ] Every check and mismatch logged in `logs\interop_log.csv`
- [ ] Demonstration ready for the final assessment
