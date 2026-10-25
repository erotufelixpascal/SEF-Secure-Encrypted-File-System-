# Part 1: User Authentication (20 marks)

**Code:** [`src/auth.c`](../src/auth.c), [`src/auth.h`](../src/auth.h) · **Settings:** [`src/sefs_config.h`](../src/sefs_config.h) · **Status:** implemented, tests passing

---

## 1. What Part 1 must do

Five functions manage users in a password file (`passwd`). Each returns **1** (OKAY) or **-1** (ERROR).

| Function | Purpose |
|---|---|
| `register_user(u, p, pFile)` | Add a new user |
| `delete_user(u, p, pFile)` | Remove a user, only with the correct password |
| `is_user_valid(u, pFile)` | Does this username exist? |
| `match_user(u, p, pFile)` | Is this the right password? (the login) |
| `change_user_password(u, p, pn, pFile)` | Replace the password, only with the correct old one |

---

## 2. The core idea: never store passwords

The `passwd` file holds one line per user:

```
alice01:9f3a…(64 hex chars)…:c81e…(40 hex chars)…
└─user─┘ └──── salt (32 B) ───┘ └── hash (20 B) ──┘
```

| Term | Meaning | Why |
|---|---|---|
| **Salt** | 32 random bytes, unique per user, made with `RAND_bytes` | Two users with the same password get different hashes; pre-computed "rainbow tables" are useless |
| **Hash** | `PBKDF2-HMAC-SHA1(password, salt, 20,000 iterations)` | One-way: the password can't be recovered from it. 20,000 rounds make each guess slow for an attacker |

**Login** = hash the password the user typed with their stored salt, and compare it with the stored hash.

---

## 3. Input rules

Checked first in every function by `valid_string` ([`auth.c:15`](../src/auth.c#L15)):

| Field | Allowed characters | Length | Config constant |
|---|---|---|---|
| Username | `a-z A-Z 0-9` | 6–31 | `SEFS_USER_MIN`, `SEFS_USER_MAX` |
| Password | `a-z A-Z 0-9 @ # $ % & * ( ) - + =` | 9–31 | `SEFS_PASS_MIN`, `SEFS_PASS_MAX`, `SEFS_PASS_EXTRA` |

`NULL` and empty strings are always rejected. The slides say ">5 and >8" (slide 6) and "≥6 and ≥9" (slide 16); these mean the same thing.

---

## 4. How each function works

### Helper functions

| Helper | Line | What it does |
|---|---|---|
| `valid_username` / `valid_password` | [31](../src/auth.c#L31), [36](../src/auth.c#L36) | Apply the rules above |
| `hash_password` | [41](../src/auth.c#L41) | One call: `PKCS5_PBKDF2_HMAC_SHA1(p, strlen(p), salt, 32, 20000, 20, hash)`; return value checked |
| `find_user` | [63](../src/auth.c#L63) | Opens `passwd` in binary mode, finds the line whose name before `:` **exactly** equals `u`, decodes salt and hash from hex. Returns 1 found / 0 not found / -1 damaged line |
| `make_entry` | [92](../src/auth.c#L92) | New random salt + hash → builds `u:salthex:hashhex\n` |
| `rewrite_user` | [109](../src/auth.c#L109) | Copies `passwd` to `passwd.tmp`, replacing or dropping one user's line, then swaps the file in with `MoveFileExA` |

### `register_user` ([line 145](../src/auth.c#L145))
1. Validate username and password.
2. `find_user`: if the user already exists, return -1.
3. `make_entry`: generate the salt, hash the password, format the line.
4. Append the line to `passwd` (binary append mode, `\n` endings).
5. Return 1.

### `match_user` ([line 174](../src/auth.c#L174))
1. Validate both inputs.
2. `find_user` gets the stored salt and hash; an unknown user returns -1.
3. Hash the given password with the **stored** salt.
4. Compare with `CRYPTO_memcmp` (constant time). Not `strcmp`, because:
   - its run time reveals how many leading bytes matched (a timing leak);
   - it stops at a `0x00` byte, which raw hashes can contain.
5. Wipe the buffers with `OPENSSL_cleanse` and return 1 on a match.

### `is_user_valid` ([line 166](../src/auth.c#L166))
Validate the username; return 1 if `find_user` finds it.

### `delete_user` ([line 190](../src/auth.c#L190))
1. `match_user` must succeed.
2. `rewrite_user(u, NULL, …)` drops only that user's line.

### `change_user_password` ([line 197](../src/auth.c#L197))
1. Validate the new password.
2. `match_user` with the old password must succeed.
3. `make_entry` creates a **fresh salt** and the new hash.
4. `rewrite_user` replaces only that line.

---

## 5. Safety rules applied

| Rule | How |
|---|---|
| Crash-safe updates | Write `passwd.tmp`, then `MoveFileExA(…, MOVEFILE_REPLACE_EXISTING)`. The original is never half-written |
| Interoperable files | Binary mode (`"rb"`, `"ab"`, `"wb"`) and `\n` only, so Linux groups can read the file |
| Constant-time comparison | `CRYPTO_memcmp` |
| No secrets left in memory | `OPENSSL_cleanse` on hash and line buffers |
| Every OpenSSL call checked | `RAND_bytes` and PBKDF2 failures return -1 |

---

## 6. Demonstration (for the final assessment)

From the `SEF` folder:

```powershell
.venv\Scripts\Activate.ps1
python
```

```python
import os, ctypes
os.add_dll_directory(os.path.abspath(r"build\Debug"))
lib = ctypes.CDLL(r"build\Debug\sefs.dll")
P = b"demo_passwd"

lib.register_user(b"alice01", b"Passw0rd#1", P)        #  1  registered
lib.register_user(b"alice01", b"Passw0rd#1", P)        # -1  duplicate
lib.register_user(b"bob", b"Passw0rd#1", P)            # -1  username too short
lib.register_user(b"carol01", b"short", P)             # -1  password too short
lib.is_user_valid(b"alice01", P)                       #  1
lib.match_user(b"alice01", b"Passw0rd#1", P)           #  1  correct password
lib.match_user(b"alice01", b"WrongPass#1", P)          # -1  wrong password
lib.change_user_password(b"alice01", b"Passw0rd#1", b"NewPassw0rd=", P)  # 1
lib.match_user(b"alice01", b"Passw0rd#1", P)           # -1  old password no longer works
lib.match_user(b"alice01", b"NewPassw0rd=", P)         #  1
lib.delete_user(b"alice01", b"NewPassw0rd=", P)        #  1
lib.is_user_valid(b"alice01", P)                       # -1  gone
```

Open `demo_passwd` in Notepad between calls to show the line being added, changed (new salt and hash) and removed. Delete it afterwards.

**Automated tests:** `python -m pytest tests\acceptance -k "register or passwd or validation or change or delete_user" -v` runs five tests, all passing.

---

## 7. Open points to confirm with the lecturer

| # | Question | Current setting |
|---|---|---|
| Q2 | PBKDF2 output length; hex upper or lower case | 20 bytes (`SEFS_HASH_LEN`); writes lowercase (`SEFS_HEX_UPPER 0`), reads either |
| Q8 | Upper length limit for username and password | 31 (`SEFS_USER_MAX`, `SEFS_PASS_MAX`) |

Change the value in `src/sefs_config.h`, rebuild, and rerun the tests.

---

## 8. Marking checklist

- [x] All five functions implemented and returning 1 / -1
- [x] Input validation for usernames and passwords, including boundaries
- [x] 32-byte random salt with `RAND_bytes`
- [x] PBKDF2-HMAC-SHA1, 20,000 iterations
- [x] Constant-time hash comparison
- [x] Crash-safe rewrite for delete and change
- [x] Memory and file cleanup
- [ ] Run once under Dr. Memory to confirm no leaks (Dr. Memory not installed yet)
- [ ] Record the demonstration output in `logs\`
