"""Step 10: build the results table, statistics and per-area breakdown.

Inputs (all relative to the repository root):
  analysis/mutants_*.csv     from run_mutants.ps1 (fault, suite, result, seconds)
  mutants/catalogue.csv      fault areas (id, area, ...)
  logs/time_log.csv          minutes per arm (arm = manual, ai/run1, ...)
  logs/defect_log.csv        classification = real_defect | false_positive
  logs/ai_prompt_log.csv     tests proposed / accepted / edited / rejected per run
  --cov ARM=FILE.xml         OpenCppCoverage cobertura export per arm (optional)

Outputs: analysis/results_table.csv, analysis/results_by_area.csv,
         analysis/statistics.csv, analysis/results.md, analysis/fig_detection_by_area.png

Usage:
  python analysis/analyze.py --cov manual=cov_manual.xml --cov ai/run1=cov_ai1.xml
"""
import argparse
import glob
import os
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd
from statsmodels.stats.contingency_tables import mcnemar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "analysis")
BASELINE = "manual"
RNG = np.random.default_rng(20261020)
N_BOOT = 10_000


def arm_name(suite: str) -> str:
    """tests\\ai\\run1 -> ai/run1, tests\\manual -> manual."""
    parts = [p for p in suite.replace("\\", "/").split("/") if p and p != "tests"]
    return "/".join(parts)


def read_csv(rel, **kw):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path, **kw)


def load_detection():
    frames = [pd.read_csv(f) for f in glob.glob(os.path.join(OUT, "mutants_*.csv"))]
    if not frames:
        raise SystemExit("No analysis/mutants_*.csv files. Run run_mutants.ps1 for each suite first.")
    df = pd.concat(frames, ignore_index=True)
    df["arm"] = df["suite"].map(arm_name)
    bad = df[~df["result"].isin(["detected", "missed"])]
    if not bad.empty:
        print("WARNING: excluding broken faults (fix and rerun them):")
        print(bad[["fault", "arm", "result"]].to_string(index=False))
    # A fault only counts if it ran cleanly for every arm, so all arms share one denominator
    broken = set(bad["fault"])
    df = df[~df["fault"].isin(broken)].copy()
    df["detected"] = (df["result"] == "detected").astype(int)
    return df.pivot_table(index="fault", columns="arm", values="detected", aggfunc="max")


def parse_cobertura(path):
    """Returns {(file, line): hit 0/1} for every executable line."""
    lines = {}
    for cls in ET.parse(path).getroot().iter("class"):
        fname = cls.get("filename", "")
        for ln in cls.iter("line"):
            lines[(fname, int(ln.get("number")))] = int(int(ln.get("hits", "0")) > 0)
    return lines


def bootstrap_diff(a, b):
    """95% percentile CI of mean(b) - mean(a) for paired 0/1 vectors."""
    a, b = np.asarray(a), np.asarray(b)
    idx = RNG.integers(0, len(a), size=(N_BOOT, len(a)))
    diffs = b[idx].mean(axis=1) - a[idx].mean(axis=1)
    return float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cov", action="append", default=[], help="ARM=cobertura.xml")
    args = ap.parse_args()

    det = load_detection()
    arms = [BASELINE] + sorted(a for a in det.columns if a != BASELINE)
    arms = [a for a in arms if a in det.columns]
    n_faults = len(det)

    cov = {}
    for item in args.cov:
        arm, path = item.split("=", 1)
        cov[arm] = parse_cobertura(os.path.join(ROOT, path) if not os.path.isabs(path) else path)

    time_log = read_csv("logs/time_log.csv")
    defects = read_csv("logs/defect_log.csv")
    prompts = read_csv("logs/ai_prompt_log.csv")

    rows = []
    for arm in arms:
        minutes = time_log.loc[time_log["arm"] == arm, "minutes"].sum() if not time_log.empty else np.nan
        d = defects[defects["arm"] == arm] if not defects.empty else defects
        real = int((d["classification"] == "real_defect").sum()) if not d.empty else 0
        fp = int((d["classification"] == "false_positive").sum()) if not d.empty else 0
        found = int(det[arm].sum())
        row = {
            "arm": arm,
            "seeded_faults_detected": found,
            "seeded_faults_total": n_faults,
            "mutation_score_pct": round(100 * found / n_faults, 1),
            "real_defects_found": real,
            "line_coverage_pct": round(100 * np.mean(list(cov[arm].values())), 1) if arm in cov else np.nan,
            "false_positive_failures": fp,
            "time_spent_min": minutes,
            "defects_per_hour": round((found + real) / (minutes / 60), 2) if minutes else np.nan,
        }
        if arm != BASELINE and not prompts.empty:
            p = prompts[prompts["run"] == arm]
            row["prompts"] = len(p)
            row["tests_proposed"] = int(p["tests_proposed"].sum())
            row["tests_accepted"] = int(p["accepted"].sum() + p["edited"].sum())
            row["review_minutes"] = p["review_minutes"].sum()
        rows.append(row)
    table = pd.DataFrame(rows).set_index("arm")
    table.to_csv(os.path.join(OUT, "results_table.csv"))

    stats = []
    for arm in arms[1:]:
        m, a = det[BASELINE].values, det[arm].values
        b = int(((m == 1) & (a == 0)).sum())  # manual only
        c = int(((m == 0) & (a == 1)).sum())  # AI only
        test = mcnemar([[int(((m == 1) & (a == 1)).sum()), b], [c, int(((m == 0) & (a == 0)).sum())]], exact=True)
        lo, hi = bootstrap_diff(m, a)
        s = {"comparison": f"{arm} vs {BASELINE}", "manual_only": b, "ai_only": c,
             "mcnemar_p": round(float(test.pvalue), 4),
             "mutation_score_diff_pct": round(100 * (a.mean() - m.mean()), 1),
             "mutation_ci95_low_pct": round(100 * lo, 1), "mutation_ci95_high_pct": round(100 * hi, 1)}
        if BASELINE in cov and arm in cov:
            keys = sorted(set(cov[BASELINE]) | set(cov[arm]))
            cm = [cov[BASELINE].get(k, 0) for k in keys]
            ca = [cov[arm].get(k, 0) for k in keys]
            clo, chi = bootstrap_diff(cm, ca)
            s.update(coverage_diff_pct=round(100 * (np.mean(ca) - np.mean(cm)), 1),
                     coverage_ci95_low_pct=round(100 * clo, 1), coverage_ci95_high_pct=round(100 * chi, 1))
        stats.append(s)
    stats = pd.DataFrame(stats)
    stats.to_csv(os.path.join(OUT, "statistics.csv"), index=False)

    catalogue = read_csv("mutants/catalogue.csv")
    by_area = pd.DataFrame()
    if not catalogue.empty:
        merged = det.join(catalogue.set_index("id")["area"], how="left").fillna({"area": "unknown"})
        by_area = merged.groupby("area")[arms].agg(["sum", "count"])
        by_area = pd.DataFrame({arm: (100 * by_area[(arm, "sum")] / by_area[(arm, "count")]).round(1)
                                for arm in arms})
        by_area.insert(0, "faults", merged.groupby("area").size())
        by_area.to_csv(os.path.join(OUT, "results_by_area.csv"))
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            ax = by_area[arms].plot.bar(figsize=(8, 4.5), rot=0)
            ax.set_ylabel("Seeded faults detected (%)")
            ax.set_xlabel("")
            ax.set_ylim(0, 100)
            ax.set_title("Detection rate by fault area")
            plt.tight_layout()
            plt.savefig(os.path.join(OUT, "fig_detection_by_area.png"), dpi=200)
        except ImportError:
            pass

    with open(os.path.join(OUT, "results.md"), "w", encoding="utf-8") as f:
        f.write(f"# Results\n\nFaults scored: {n_faults}\n\n")
        f.write(table.T.to_markdown() + "\n\n")
        if not stats.empty:
            f.write("## Paired comparison (McNemar exact, bootstrap 95% CI)\n\n" + stats.to_markdown(index=False) + "\n\n")
        if not by_area.empty:
            f.write("## Detection rate by area (%)\n\n" + by_area.to_markdown() + "\n")
    print(table.T.to_string())
    if not stats.empty:
        print()
        print(stats.to_string(index=False))
    print(f"\nWrote results to {OUT}")


if __name__ == "__main__":
    main()
