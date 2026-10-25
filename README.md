# SEFS: Secure Encrypted File System (Group 6)

C implementation of the SEFS assignment (Parts 1–3) built as `sefs.dll`, with pytest suites for the Group 6 extension: *AI-assisted test generation vs. manual tests under a fixed time budget*.

## Status of the open specification points (Step 2)

**None of these are confirmed yet.** Each placeholder lives in `src/sefs_config.h` (marked `TODO-confirm`) so one edit and a rebuild applies the lecturer's answer. Record the answer and date in the last column.

| # | Question | Placeholder used now | Lecturer's answer |
|---|---|---|---|
| 1 | Padding "ASCII character 0": `0x00` or `'0'` (0x30)? | `0x00` (`SEFS_PAD_BYTE`) | |
| 2 | PBKDF2 output length; hex case | 20 bytes; lowercase written, either case read | |
| 3 | HMAC over ciphertext or plaintext; which key | HMAC-SHA256 with the chunk key over IV ‖ ciphertext (whole chunk file) | |
| 4 | Meta encrypted with master key+IV? field order, separators, line endings | AES-128-CTR(master key, master IV); `owner\ncount\nsize\nstart\nend\n` then `name keyhex hmachex\n` per chunk | |
| 5 | Chunk name length and character set | 32 lowercase hex chars (16 random bytes); next-name field 32 bytes, `NULL` + zeros for the last chunk; size as 4-byte big-endian | |
| 6 | Master File List encrypted? what is hashed? | Plaintext, `filename sha256hex\n`, digest over the stored (encrypted) meta bytes | |
| 7 | Integrity before decryption; `read_from_file` on failure | Yes, HMAC checked before decrypting; returns `NULL` | |
| 8 | Username/password bounds | Username `[A-Za-z0-9]{6,31}`; password `[A-Za-z0-9@#$%&*()-+=]{9,31}` | |
| 9 | Interoperability test files and exchange procedure | Not yet agreed; log exchanges in `logs/interop_log.csv` | |

Other assumptions to confirm: the Part 2/3 function signatures in `src/sefs.h`; `write_to_file` *inserts* (later content shifts forward) and takes a NUL-terminated string; `read_from_file` fails if `position + len` passes the end of file; `encrypt_file` keeps the plaintext (`SEFS_REMOVE_PLAINTEXT 0`); `master.key` is 16 key bytes then 16 IV bytes.

**Security note for the report:** encrypting every meta file with the same master key *and* IV in CTR mode reuses the keystream, so XORing two meta files leaks the XOR of their plaintexts. The code does what the spec describes; raise this with the lecturer and discuss it under limitations.

## Layout

For a detailed explanation of every folder and how the system works, see [FOLDERS_README.md](FOLDERS_README.md).

Step-by-step guides for each marked part (100 marks):

| Part | Marks | Guide |
|---|---|---|
| 1. User authentication | 20 | [docs/PART1_USER_AUTHENTICATION.md](docs/PART1_USER_AUTHENTICATION.md) |
| 2. Simplified SEFS | 30 | [docs/PART2_SIMPLIFIED_SEFS.md](docs/PART2_SIMPLIFIED_SEFS.md) |
| 3. Full multi-chunk SEFS | 45 | [docs/PART3_FULL_SEFS.md](docs/PART3_FULL_SEFS.md) |
| 4. Cross-group interoperability | 5 | [docs/PART4_INTEROPERABILITY.md](docs/PART4_INTEROPERABILITY.md) |

```
src/            auth.c crypto.c chunk.c meta.c sefs.c util.c  (+ headers, sefs_config.h)
tools/keygen.c  master key/IV generator
tests/conftest.py      ctypes bindings and the `sefs` fixture (fresh temp dir per test)
tests/acceptance/      Step 6 acceptance checklist
tests/manual/          Step 8 manual arm (no AI)
tests/ai/runN/         Step 9 AI-assisted arm, one folder per run
mutants/               Step 7 seeded faults (patches git-ignored; see mutants/README.md)
logs/                  time, AI prompt/review, defect and interoperability logs
analysis/analyze.py    Step 10 results table, McNemar test, bootstrap CIs, per-area chart
run_mutants.ps1        scores one suite against every fault
```

## Build (Developer PowerShell for VS 2022)

```powershell
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Debug          # build\Debug\sefs.dll, keygen.exe, libcrypto-3-x64.dll
build\Debug\keygen.exe master.key           # real master key; never commit it
```

AddressSanitizer build: `cmake -B build-asan -S . -DSEFS_ASAN=ON -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake` then `cmake --build build-asan --config Debug`, and run tests with `$env:SEFS_DLL_DIR="build-asan\Debug"`.

## Run the tests

```powershell
.venv\Scripts\Activate.ps1
python -m pytest tests\acceptance -v       # Step 6 acceptance
python -m pytest tests\manual -q           # manual arm
python -m pytest tests\ai\run1 -q          # AI arm, run 1
```

Each test gets a fresh temporary directory with a throwaway `master.key`; use the `sefs` fixture (and `user` for a registered user). Strings or bytes go in; `read_from_file` returns `bytes` or `None`.

## Run the seeded faults and analysis (Step 10)

```powershell
.\run_mutants.ps1 -Tests tests\manual
.\run_mutants.ps1 -Tests tests\ai\run1
OpenCppCoverage --sources "$PWD\src" --modules sefs.dll --export_type cobertura:cov_manual.xml -- python -m pytest tests\manual -q
OpenCppCoverage --sources "$PWD\src" --modules sefs.dll --export_type cobertura:cov_ai1.xml -- python -m pytest tests\ai\run1 -q
python analysis\analyze.py --cov manual=cov_manual.xml --cov ai/run1=cov_ai1.xml
```

Results go to `analysis/results.md`, `results_table.csv`, `statistics.csv`, `results_by_area.csv` and `fig_detection_by_area.png`.

## Log formats

| File | Columns |
|---|---|
| `logs/time_log.csv` | date, student, arm (`manual`, `ai/run1`, `build`…), activity, minutes |
| `logs/ai_prompt_log.csv` | prompt_id, timestamp, run (`ai/run1`), tool_version, area, prompt_text, tests_proposed, accepted, edited, rejected, rejection_reason, review_minutes |
| `logs/defect_log.csv` | defect_id, date, student, arm, test, function, description, classification (`real_defect` / `false_positive`), resolution |
| `logs/interop_log.csv` | date, group, direction, file_or_entry, result, mismatch, resolution |

## AI usage disclosure

The SEFS implementation scaffold, acceptance tests, `run_mutants.ps1` and `analysis/analyze.py` were drafted with Claude Code (Anthropic) and reviewed by the group. The seeded faults (Step 7) and the manual arm (Step 8) must be written without AI; the AI arm (Step 9) is logged prompt by prompt in `logs/ai_prompt_log.csv`.
