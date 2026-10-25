# Seeded faults (Step 7)

This folder is the held-out evaluation set. **Whoever writes tests (Steps 8 and 9) must not open it** until Step 10. `*.patch` is git-ignored: the fault author keeps the patches encrypted or with the supervisor and copies them here only for scoring.

Each fault is one small patch against `sefs-v1.0`, named `Mnn_short_name.patch` (e.g. `M07_iv_reuse.patch`). Make one from a clean tree:

```powershell
# edit src\..., then
git diff -- src > mutants\M07_iv_reuse.patch
git checkout -- src
```

## catalogue.csv

| Column | Meaning |
|---|---|
| id | Patch base name, e.g. `M07_iv_reuse` (must match the file name) |
| area | One of `authentication`, `round_trip`, `chunk_boundaries`, `tamper` |
| file | Source file changed, e.g. `src/chunk.c` |
| line | Line number of the change in `sefs-v1.0` |
| description | What the fault does, in one sentence |
| severity | `low`, `medium` or `high` |

Header line: `id,area,file,line,description,severity`
