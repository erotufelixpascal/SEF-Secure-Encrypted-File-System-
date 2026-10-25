# SEFS Project Guide: What Is in Each Folder and How It Works

This file explains every folder and file in the `SEF` project, what each one does, and how the pieces fit together. For build and run commands, see `README.md`.

---

## The big picture

```
 You / tests (Python)                     C library (sefs.dll)                   Files on disk
 ─────────────────────                    ─────────────────────                  ─────────────
 tests\conftest.py  ──── ctypes ────►     sefs.c   (file functions)  ──────►     notes.meta
   (calls the DLL)                        auth.c   (users/passwords) ──────►     passwd
                                          meta.c   (meta + master list) ───►     masterlist
                                          chunk.c  (encrypted chunks) ─────►     chunks\<random name>
                                          crypto.c (OpenSSL wrappers)
                                          util.c   (file + hex helpers)
```

1. The C code in `src\` is compiled by CMake into `build\Debug\sefs.dll`.
2. Python tests in `tests\` load that DLL and call its functions.
3. The DLL reads and writes `passwd`, `*.meta`, `masterlist` and `chunks\` in the current working directory. During tests, each test gets its own temporary folder, so your real project folder stays clean.
4. For the experiment, `run_mutants.ps1` injects deliberate bugs, rebuilds and reruns a test suite. `analysis\analyze.py` then turns the results into tables and statistics.

---

## Top-level files

| File | What it is | How it works |
|---|---|---|
| `README.md` | Main project readme | Build steps, how to run tests, the open lecturer questions (Step 2) with the placeholders used, log formats, AI usage disclosure |
| `FOLDERS_README.md` | This file | Explains the folders and how the system works |
| `CMakeLists.txt` | Build recipe | Tells CMake to compile every `.c` file in `src\` into `sefs.dll`, link OpenSSL's `libcrypto`, and also build `keygen.exe`. `-DSEFS_ASAN=ON` makes an AddressSanitizer build for finding memory bugs |
| `pytest.ini` | pytest settings | Looks for tests in `tests\`; `--import-mode=importlib` lets `tests\manual` and `tests\ai\run1` both have files called `test_auth.py` without clashing |
| `run_mutants.ps1` | Fault-scoring script (Steps 7 and 10) | For each `.patch` in `mutants\`: apply the bug, rebuild, run the chosen test folder, record `detected` (a test failed) or `missed` (all passed), undo the bug. Writes `analysis\mutants_<suite>.csv` |
| `.gitignore` | Files Git must never store | Keys (`master.key`), `passwd`, encrypted data (`*.meta`, `chunks\`, `masterlist`), build output, `.venv`, and the hidden fault patches |
| `.gitattributes` | Line-ending rule | `* -text` stops Git converting `\n` to `\r\n`, so files stay byte-identical for other groups' Linux builds and patches apply cleanly |

---

## `src\`: the SEFS implementation (C)

This is the actual encrypted file system. Each module has a `.c` file (the code) and a `.h` file (its function list).

### `sefs_config.h`: every format decision in one place
Holds all constants: file names, salt and hash lengths, 20,000 PBKDF2 iterations, username and password length limits, 1,024-byte chunk size, padding byte, chunk name length, and the chunk file layout.

**Important:** values marked `TODO-confirm` are guesses for questions the lecturer has not answered yet. When the answers arrive, change them here and rebuild; no other file needs editing.

### `sefs_api.h`: making functions visible to Python
A Windows DLL exports nothing by default. This header defines `SEFS_API` (`__declspec(dllexport)`), which is placed in front of every public function so Python can call it.

### `auth.c` / `auth.h`: Part 1, user authentication
| Function | What it does |
|---|---|
| `register_user` | Validates the username (6–31 letters/digits) and password (9–31 of `a-zA-Z0-9@#$%&*()-+=`), rejects duplicates, creates a random 32-byte salt, hashes the password with PBKDF2-HMAC-SHA1 (20,000 iterations), and appends `username:salthex:hashhex` to `passwd` |
| `match_user` | Looks up the user's salt, re-hashes the given password, compares with `CRYPTO_memcmp` (constant time, so timing can't leak information) |
| `is_user_valid` | Returns 1 if the username exists |
| `delete_user` | Checks the password, then removes only that user's line |
| `change_user_password` | Checks the old password, validates the new one, writes a new salt and hash |

Deleting and changing write to `passwd.tmp` first, then swap it in with `MoveFileExA`, so a crash halfway never corrupts `passwd`.

### `crypto.c` / `crypto.h`: OpenSSL wrappers
Four small functions used everywhere else:
- `gen_random`: secure random bytes (keys, IVs, salts, chunk names)
- `aes128_ctr`: AES-128 in counter mode (encrypting and decrypting are the same operation)
- `hmac_sha256`: tamper-detection tag for a chunk
- `sha256`: digest of a meta file for the Master File List

### `chunk.c` / `chunk.h`: one encrypted chunk
A file's content is stored in chunk files inside `chunks\`, each with a random 32-character name. Each chunk file is exactly 1,076 bytes:

```
┌────────────┬──────────────────────── encrypted with the chunk's own key ────────────────────────┐
│ IV (16 B)  │ next chunk name (32 B, "NULL" if last) │ size (4 B) │ content padded to 1,024 B │
└────────────┴────────────────────────────────────────────────────────────────────────────────────┘
```

- `chunk_write` creates a **fresh random key and IV every time**, encrypts, computes the HMAC over the whole file, and saves it.
- `chunk_read` checks the HMAC **before** decrypting; if anything was changed, it refuses. It also checks the next-name field and that the padding is correct.
- `chunk_delete` removes a chunk file.

### `meta.c` / `meta.h`: the meta file and the Master File List
**Meta file (`<filename>.meta`)**: the "table of contents" for one file, encrypted with the master key:
```
owner
number of chunks
file size
first chunk name
last chunk name
<chunk name> <chunk key> <chunk HMAC>     ← one line per chunk, in order
```

**Master File List (`masterlist`)**: one line per file: `filename sha256-of-its-meta-file`. If someone edits a meta file, its SHA-256 no longer matches, so the change is detected.

`meta_load` / `meta_save` read and write meta files; `masterlist_get` / `masterlist_put` / `masterlist_names` manage the list.

### `sefs.c` / `sefs.h`: Parts 2 and 3, the file functions
Every function first checks the username and password, and that the user owns the file.

| Function | What it does |
|---|---|
| `create_file` | Validates the name (letters/digits, max 20), creates an empty file (one empty chunk), adds it to the Master File List |
| `encrypt_file` | Reads a normal file from disk and stores it encrypted, split into chunks |
| `decrypt_file` | Verifies everything, decrypts, and writes the plaintext to a new file |
| `read_from_file` | Verifies, then returns `len` bytes starting at `position` |
| `write_to_file` | Inserts text at `position` (later content shifts forward) |
| `file_size` | Returns the size recorded in the meta file |
| `file_integrity_check` | Verifies the meta digest, every chunk's HMAC, every next-chunk link, the chunk count and the total size |
| `delete_file` | Removes all chunks, the meta file and the list entry |
| `system_health_check` | Runs the integrity check on every file in the Master File List |
| `sefs_free` | Frees memory returned by `read_from_file` (must be freed inside the DLL) |

**How a file is stored:** a file of size S uses exactly max(1, ⌈S / 1024⌉) chunks, linked in a chain:
```
notes.meta ──► chunk A ──next──► chunk B ──next──► chunk C ──next──► NULL
               (1,024 B)         (1,024 B)         (500 B + padding)
```

**How a write works:** decrypt the whole chain → insert the new text → re-split into the minimum number of chunks → encrypt each with a new key and IV → save the new meta file and list entry → only then delete the old chunks. If something fails midway, the old version is still intact.

### `util.c` / `util.h`: helpers
Reading whole files in binary mode, safe "write to temp then replace" saving, hex conversion, loading `master.key`, and building file paths.

---

## `tools\`

| File | What it does |
|---|---|
| `keygen.c` | Builds into `keygen.exe`. Writes `master.key`: 16 random key bytes followed by 16 random IV bytes. Run `build\Debug\keygen.exe master.key` once. Never commit the key |

---

## `build\` (generated, not in Git)

Created by `cmake -B build`. After `cmake --build build --config Debug`, `build\Debug\` contains:

| File | What it is |
|---|---|
| `sefs.dll` | The compiled SEFS library the tests load |
| `libcrypto-3-x64.dll` | OpenSSL, copied here automatically by vcpkg so `sefs.dll` can find it |
| `keygen.exe` | The master key generator |
| `*.pdb`, `*.lib`, `*.exp` | Debug symbols and link files |

You can delete `build\` at any time and rebuild it.

---

## `tests\`: Python test suites

### `conftest.py`: the bridge between Python and C
pytest loads this automatically before any test. It:
1. Loads `build\Debug\sefs.dll` with `ctypes` (set `SEFS_DLL_DIR` to use another build, e.g. the AddressSanitizer one).
2. Declares each C function's argument and return types.
3. Wraps them in a `Sefs` class so tests can pass normal Python strings and get Python values back (`read_from_file` returns `bytes` or `None`).
4. Provides two **fixtures** (ready-made setups tests can ask for):
   - `sefs`: creates a fresh temporary folder with a throwaway `master.key` and switches into it, so every test starts clean.
   - `user`: also registers a user (`alice01` / `Passw0rd#1`) and gives the test its username and password.

Example test:
```python
def test_round_trip(sefs, user):
    sefs.write_plain("doc", b"hello")
    assert sefs.encrypt_file("doc", *user) == 1
    assert sefs.read_from_file("doc", 0, 5, *user) == b"hello"
```

### `acceptance\`: Step 6 proof that SEFS works
`test_acceptance.py` has 15 tests: every login function and its boundaries, single-chunk file operations, a 3-chunk round trip, an append that must stay in one chunk, an insert that must spill into a second chunk, non-owner access refused, and tampered chunk and meta files detected. **These are not part of the experiment.** All 15 currently pass.

### `manual\`: Step 8 manual test arm (empty)
Tests written by hand **without any AI help**, within the fixed time budget. Suggested files: `test_auth.py`, `test_roundtrip.py`, `test_chunks.py`, `test_tamper.py`.

### `ai\run1\` (and later `run2`, `run3`): Step 9 AI-assisted arm (empty)
Tests proposed by an AI assistant and checked by you. Every accepted test gets a comment such as `# source: P-014 (edited)` linking it to the prompt log. Each fresh AI session goes in its own `runN` folder.

---

## `mutants\`: Step 7 seeded faults (the hidden answer key)

Deliberate bugs used to measure which test suite finds more defects.

| Item | What it is |
|---|---|
| `README.md` | How to make a fault patch and the `catalogue.csv` format |
| `Mnn_name.patch` (you create these) | One small bug each, e.g. `M07_iv_reuse.patch`. Git-ignored so test writers can't see them |
| `catalogue.csv` (you create this) | `id, area, file, line, description, severity` for each fault |

**How it works:** `run_mutants.ps1` applies one patch to `src\`, rebuilds, runs a test suite, and checks whether any test failed. A failing test means the suite **detected** the bug. Then it undoes the patch and moves to the next one.

The person writing tests must not see these until Step 10, or the experiment is invalid.

---

## `logs\`: evidence the brief requires

All are CSV files (open in Excel). Only the header rows exist so far.

| File | Fill in when | Columns |
|---|---|---|
| `time_log.csv` | Every work session | date, student, arm (`manual`, `ai/run1`, `build`…), activity, minutes |
| `ai_prompt_log.csv` | Every AI prompt in Step 9 | prompt_id, timestamp, run, tool_version, area, prompt_text, tests_proposed, accepted, edited, rejected, rejection_reason, review_minutes |
| `defect_log.csv` | A test fails on the clean code | defect_id, date, student, arm, test, function, description, classification (`real_defect` or `false_positive`), resolution |
| `interop_log.csv` | Exchanging files with other groups | date, group, direction, file_or_entry, result, mismatch, resolution |

Also save demo screenshots or terminal output here (Step 6).

---

## `analysis\`: Step 10 results

### `analyze.py`
Reads the outputs of `run_mutants.ps1`, the fault catalogue, the logs and optional coverage files, then produces:

| Output | Contents |
|---|---|
| `results_table.csv` | Per suite: faults detected, mutation score %, real defects, line coverage %, false positives, minutes spent, defects per hour, AI prompts/tests accepted |
| `statistics.csv` | Manual vs each AI run: McNemar's test p-value (are the detection differences significant?) and 95% bootstrap confidence intervals for the difference in mutation score and coverage |
| `results_by_area.csv` | Detection rate split by authentication, round trip, chunk boundaries, tamper |
| `fig_detection_by_area.png` | Bar chart of the above, for the report and slides |
| `results.md` | All of the above as readable tables |

Run it after scoring every suite:
```powershell
python analysis\analyze.py --cov manual=cov_manual.xml --cov ai/run1=cov_ai1.xml
```

---

## `.vscode\`

| File | What it does |
|---|---|
| `settings.json` | Tells VS Code's CMake Tools to use vcpkg's OpenSSL, uses the project's `.venv` Python, and turns on the pytest test panel |

---

## `.venv\` (not in Git)

The project's private Python installation with pytest, hypothesis, pandas, scipy, statsmodels, matplotlib and tabulate. Activate it with `.venv\Scripts\Activate.ps1`.

---

## Files SEFS creates at runtime (never commit these)

| File | Created by | Contents |
|---|---|---|
| `master.key` | `keygen.exe` | 16-byte master key + 16-byte master IV |
| `passwd` | `register_user` | One `username:salt:hash` line per user |
| `<name>.meta` | file functions | Encrypted table of contents for one file |
| `masterlist` | file functions | `filename sha256` per file |
| `chunks\` | file functions | The encrypted chunk files |

---

## Workflow through the guide's steps

| Step | Folder(s) used | Status |
|---|---|---|
| 1. Setup | top-level files, `.vscode\` | Done |
| 2. Lecturer questions | `src\sefs_config.h`, `README.md` | Waiting for answers; placeholders in use |
| 3–5. Parts 1–3 | `src\`, `tools\` | Done, builds with no warnings |
| 6. Acceptance & interop | `tests\acceptance\`, `logs\interop_log.csv` | 15/15 pass; demos, interop exchange and `sefs-v1.0` tag still to do |
| 7. Seeded faults | `mutants\` | To do (by you, without AI) |
| 8. Manual arm | `tests\manual\`, `logs\` | To do (by you, without AI) |
| 9. AI arm | `tests\ai\runN\`, `logs\ai_prompt_log.csv` | To do |
| 10. Analysis | `run_mutants.ps1`, `analysis\` | Tooling ready |
| 11. Write-up | (report, manuscript, slides) | To do |
