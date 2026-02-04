#!/usr/bin/env python3
import csv, time, subprocess, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]   # repo root

UID = "AABBCCDD"
KEY = "4F4E4D494B52"

N_VALUES = [4, 6, 8, 10, 12, 16, 20, 24, 32]
T_VALUES = [200000, 400000, 800000, 1200000, 2000000, 3000000]
TRIALS = 50

nonce_file = ROOT / "data" / "grid" / "nonces.txt"
SIM = ["python3", str(ROOT / "hitag2_simulation.py"),
       "--key", KEY, "--uid", UID, "-n", "32", "-o", str(nonce_file)]
CRACK = [str(ROOT / "ht2crack4"), "-u", UID, "-n", str(nonce_file)]

win_re = re.compile(r"WIN!!!")
key_re = re.compile(r"key\s*=\s*([0-9A-Fa-f]{12})")

def run_once(n, t, seed):
    # 1) generate dataset
    sim_cmd = SIM + ["--seed", str(seed)]
    subprocess.run(sim_cmd, check=True, stdout=subprocess.DEVNULL)

    # 2) crack
    cmd = CRACK + ["-N", str(n), "-t", str(t)]
    start = time.time()
    p = subprocess.run(cmd, text=True, capture_output=True)
    elapsed = time.time() - start

    out = (p.stdout or "") + "\n" + (p.stderr or "")
    success = 1 if win_re.search(out) else 0

    recovered = ""
    m = key_re.search(out)
    if m:
        recovered = m.group(1).upper()

    return success, elapsed, recovered, p.returncode

def main():
    out_csv = ROOT / "data" / "grid" / "grid_results.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["trial", "seed", "N", "T", "success", "runtime_s", "recovered_key", "returncode"])

        trial_id = 0
        for t in T_VALUES:
            for n in N_VALUES:
                for r in range(TRIALS):
                    trial_id += 1
                    seed = 100000 * t + 1000 * n + r  # deterministic
                    success, rt, rec, rc = run_once(n, t, seed)
                    w.writerow([trial_id, seed, n, t, success, f"{rt:.3f}", rec, rc])
                    print(f"T={t:7d} N={n:2d} r={r:2d}  success={success}  time={rt:.1f}s  key={rec}")

    print("\nSaved grid_results.csv")

if __name__ == "__main__":
    main()
