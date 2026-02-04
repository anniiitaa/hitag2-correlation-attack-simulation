#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
make_plots.py
-------------
Reads data/grid/grid_results.csv and generates:

A) 3D + color (4D): axes = (N, T, runtime_mean), color = success_rate
B) Heatmap: Success rate vs (T, N) with numbers inside cells
C) 2D plot: Runtime (y) vs T (x), one curve per N
D) Pareto Trade-off (N={6, 8, 16, 20}): Success rate vs Mean runtime

Outputs to figures/ as PNG (+ optional PDF).
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless-safe
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
from matplotlib.ticker import FuncFormatter

# ----------------------------
# Helpers
# ----------------------------

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def save_fig(fig, outpath: Path, pdf: bool):
    fig.tight_layout()
    fig.savefig(outpath.with_suffix(".png"), dpi=240)
    if pdf:
        fig.savefig(outpath.with_suffix(".pdf"))
    plt.close(fig)

def read_grid_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["N"] = df["N"].astype(int)
    df["T"] = df["T"].astype(int)
    df["success"] = df["success"].astype(int)
    df["runtime_s"] = df["runtime_s"].astype(float)
    return df

def aggregate_by_NT(df: pd.DataFrame) -> pd.DataFrame:
    g = (df.groupby(["N", "T"], as_index=False)
           .agg(success_rate=("success", "mean"),
                runtime_mean=("runtime_s", "mean"),
                runtime_std=("runtime_s", "std"),
                trials=("success", "size")))
    g["runtime_std"] = g["runtime_std"].fillna(0.0)
    return g

def annotate_heatmap(ax, data, fmt="{:.2f}", textsize=8):
    """
    Put numbers inside each cell.
    data: 2D numpy array (may contain NaN)
    """
    nrows, ncols = data.shape
    for i in range(nrows):
        for j in range(ncols):
            val = data[i, j]
            if np.isnan(val):
                continue
            ax.text(j, i, fmt.format(val), ha="center", va="center", fontsize=textsize)

def set_ticklabels(ax, xticklabels, yticklabels):
    ax.set_xticks(np.arange(len(xticklabels)))
    ax.set_xticklabels(xticklabels)
    ax.set_yticks(np.arange(len(yticklabels)))
    ax.set_yticklabels(yticklabels)


# ----------------------------
# Plot A: 3D + color (4D)
# ----------------------------

def plot_3d_4d_overview(g: pd.DataFrame, outdir: Path, pdf: bool):
    fig = plt.figure(figsize=(11, 7))
    ax = fig.add_subplot(111, projection="3d")

    x = g["N"].to_numpy()
    y = g["T"].to_numpy()
    z = g["runtime_mean"].to_numpy()
    c = g["success_rate"].to_numpy()

    sc = ax.scatter(x, y, z, c=c, s=40)

    ax.set_title("4D Overview: N vs T vs Runtime (color = Success rate)")
    ax.set_xlabel("N (pairs used)")
    ax.set_ylabel("T (table size)")
    ax.set_zlabel("Mean runtime (s)")

    cbar = fig.colorbar(sc, ax=ax, pad=0.08, shrink=0.75)
    cbar.set_label("Success rate")

    ax.view_init(elev=22, azim=-55)

    save_fig(fig, outdir / "3d_overview_N_T_runtime_color_success", pdf)
    print(f"[OK] Saved figures/3d_overview_N_T_runtime_color_success.png")


# ----------------------------
# Plot B: Heatmap Success vs (T, N) with values
# ----------------------------

def plot_heatmap_success_T_N(g: pd.DataFrame, outdir: Path, pdf: bool):
    pivot = g.pivot(index="T", columns="N", values="success_rate").sort_index()
    mat = pivot.to_numpy()

    fig = plt.figure(figsize=(10, 6))
    ax = fig.add_subplot(111)

    im = ax.imshow(mat, aspect="auto", origin="lower")

    ax.set_title("Heatmap: Success rate vs (T, N)")
    ax.set_xlabel("N (pairs used)")
    ax.set_ylabel("T (table size)")

    set_ticklabels(ax, pivot.columns.to_list(), pivot.index.to_list())

    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.set_label("Success rate")

    annotate_heatmap(ax, mat, fmt="{:.2f}", textsize=8)

    save_fig(fig, outdir / "heatmap_success_T_vs_N_annotated", pdf)
    print(f"[OK] Saved figures/heatmap_success_T_vs_N_annotated.png")


# ----------------------------
# Plot C: 2D Runtime(y) vs T(x), one curve per N
# ----------------------------

def plot_runtime_vs_T_by_N_with_model(df: pd.DataFrame,
                                      outdir,
                                      pdf=False,
                                      model_N=32,
                                      filename="runtime_vs_T_by_N_with_model"):
    """
    Runtime vs T (log scale), one curve per N + linear model for a reference N.
    """

    outdir = str(outdir)
    df2 = df.copy()

    # --- Detect whether df is raw or aggregated ---
    is_raw = "runtime_s" in df2.columns
    is_agg = ("runtime_mean" in df2.columns) and ("runtime_std" in df2.columns)

    if not (is_raw or is_agg):
        raise ValueError(
            "Input df must contain either 'runtime_s' (raw) OR "
            "'runtime_mean'/'runtime_std' (aggregated). "
            f"Columns are: {list(df2.columns)}"
        )

    # --- Ensure numeric columns ---
    df2["T"] = pd.to_numeric(df2["T"])
    df2["N"] = pd.to_numeric(df2["N"])

    # --- Aggregate if needed ---
    if is_raw:
        df2["runtime_s"] = pd.to_numeric(df2["runtime_s"])
        g = (df2.groupby(["N", "T"], as_index=False)
                 .agg(runtime_mean=("runtime_s", "mean"),
                      runtime_std=("runtime_s", "std")))
    else:
        # Already aggregated
        df2["runtime_mean"] = pd.to_numeric(df2["runtime_mean"])
        df2["runtime_std"] = pd.to_numeric(df2["runtime_std"])
        g = df2

    Ts = sorted(g["T"].unique())

    fig, ax = plt.subplots(figsize=(10, 6))

    # ---- Curves per N ----
    for N in sorted(g["N"].unique()):
        sub = g[g["N"] == N].sort_values("T")
        x = sub["T"].to_numpy()
        y = sub["runtime_mean"].to_numpy()
        s = sub["runtime_std"].fillna(0.0).to_numpy()

        ax.plot(x, y, marker="o", label=f"N={int(N)}")
        ax.fill_between(x, y - s, y + s, alpha=0.15)

    # ---- Linear model for a reference N ----
    ref = g[g["N"] == model_N].sort_values("T")
    if len(ref) >= 2:
        x = ref["T"].to_numpy()
        y = ref["runtime_mean"].to_numpy()

        a, b = np.polyfit(x, y, 1)
        y_hat = a * x + b

        ss_res = np.sum((y - y_hat) ** 2)
        ss_tot = np.sum((y - np.mean(y)) ** 2)
        r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0

        ax.plot(
            x, y_hat,
            linestyle="--",
            linewidth=2,
            color="black",
            label=f"Linear model (N={model_N}), $R^2$={r2:.3f}"
        )

    # ---- Axis formatting ----
    ax.set_xscale("log")
    ax.set_xticks(Ts)

    def fmt_T(x, pos):
        if x in Ts:
            return f"{int(x):,}".replace(",", " ")
        return ""

    ax.xaxis.set_major_formatter(FuncFormatter(fmt_T))
    ax.xaxis.set_minor_formatter(FuncFormatter(lambda x, pos: ""))

    ax.set_xlabel("Table size T (log scale)")
    ax.set_ylabel("Runtime (seconds)")
    ax.set_title("Runtime vs Table Size T")
    ax.grid(True, which="both", linestyle="--", alpha=0.4)
    ax.legend(ncols=2, fontsize=9)

    fig.tight_layout()

    png_path = f"{outdir}/{filename}.png"
    fig.savefig(png_path, dpi=250)
    if pdf:
        fig.savefig(f"{outdir}/{filename}.pdf")

    plt.close(fig)
    print(f"[OK] Saved {png_path}")

# ----------------------------
# Plot D: Heatmap Runtime(color) vs (Success rate bin, T) with values
# Lower runtime is better; we keep the label explicit.
# ----------------------------

def pareto_front(points):
    """
    points: list of (runtime, success, T)
    Pareto-optimal for: minimize runtime, maximize success
    Returns list sorted by runtime ascending.
    """
    pts = sorted(points, key=lambda x: x[0])  # sort by runtime
    front = []
    best_success = -1.0
    for rt, sr, T in pts:
        if sr > best_success + 1e-12:
            front.append((rt, sr, T))
            best_success = sr
    return front

def plot_pareto_tradeoff_success_vs_runtime(df: pd.DataFrame,
                                            outdir: Path,
                                            pdf: bool,
                                            filename_prefix="pareto_success_vs_runtime"):
    """
    For each N:
      - aggregate per T: mean runtime, success_rate
      - scatter: x=mean runtime, y=success_rate, label each point with T
      - overlay Pareto front
    """

    # aggregate raw df -> per (N,T)
    g = (df.groupby(["N", "T"], as_index=False)
           .agg(success_rate=("success", "mean"),
                runtime_mean=("runtime_s", "mean"),
                runtime_std=("runtime_s", "std"),
                trials=("success", "size")))
    g["runtime_std"] = g["runtime_std"].fillna(0.0)

    Ns_to_plot = [6, 8, 16, 20]

    for N in Ns_to_plot:
        if N not in g["N"].values:
            continue

        sub = g[g["N"] == N].sort_values("runtime_mean")

        # build pareto
        pts = [(float(r.runtime_mean), float(r.success_rate), int(r.T)) for r in sub.itertuples()]
        front = pareto_front(pts)

        fig, ax = plt.subplots(figsize=(11, 7))

        # scatter all T
        ax.scatter(sub["runtime_mean"], sub["success_rate"],
                s=120, alpha=0.85,
                edgecolors="black", linewidths=0.6)

        # annotate T
        for r in sub.itertuples():
            ax.annotate(
                f"T={int(r.T):,}".replace(",", " "),
                (r.runtime_mean, r.success_rate),
                textcoords="offset points",
                xytext=(6, 6),
                fontsize=9
            )

        # draw pareto front
        if len(front) >= 2:
            fx = [p[0] for p in front]
            fy = [p[1] for p in front]
            ax.plot(fx, fy, linewidth=2.5, linestyle="--")
        elif len(front) == 1:
            ax.scatter([front[0][0]], [front[0][1]], s=220, marker="X")

        ax.set_title(
            f"Pareto Trade-off (N={int(N)}): Success rate vs Mean runtime"
        )
        ax.set_xlabel("Mean runtime (s)  ↓ better")
        ax.set_ylabel("Success rate  ↑ better")

        ax.set_ylim(-0.02, 1.02)
        ax.grid(True, linestyle="--", alpha=0.5)

        save_fig(fig, outdir / f"{filename_prefix}_N{int(N)}", pdf)
        print(f"[OK] Saved figures/{filename_prefix}_N{int(N)}.png")

# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="data/grid/grid_results.csv", help="Path to grid_results.csv")
    ap.add_argument("--outdir", default="figures", help="Output directory for figures")
    ap.add_argument("--pdf", action="store_true", help="Also save PDF versions")
    ap.add_argument("--success-bin", type=float, default=0.1, help="Bin width for success rate heatmap (default 0.1)")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    outdir = Path(args.outdir)
    ensure_dir(outdir)

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    df = read_grid_csv(csv_path)
    g = aggregate_by_NT(df)

    # A) 3D 4D overview (kept)
    plot_3d_4d_overview(g, outdir, args.pdf)

    # B) Heatmap success vs (T,N) with values
    plot_heatmap_success_T_N(g, outdir, args.pdf)

    # C) Runtime vs T curves by N
    plot_runtime_vs_T_by_N_with_model(g, outdir, args.pdf)

    # D) Pareto Trade-off (N={6, 8, 16, 20}): Success rate vs Mean runtime
    plot_pareto_tradeoff_success_vs_runtime(df, outdir, args.pdf)

    print(f"Saved figures to: {outdir.resolve()}")

if __name__ == "__main__":
    main()
