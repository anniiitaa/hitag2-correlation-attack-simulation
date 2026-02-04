# HiTag2 Correlation Attack Simulation

A university project demonstrating the fast correlation attack on the HiTag2 cipher, as described by Garcia et al. in their 2016 USENIX Security paper "Lock It and Still Lose It – On the (In)Security of Automotive Remote Keyless Entry Systems".

## Overview

This project consists of two main components:

1. **hitag2_simulation.py** – A Python implementation of the HiTag2 cipher that generates simulated encrypted nonce/keystream pairs (simulating eavesdropped RKE transmissions)

2. **ht2crack4** – A C implementation of the fast correlation attack that recovers the 48-bit secret key from captured data

## Requirements

- Python 3.x
- GCC compiler
- pthread library (usually pre-installed on Linux)

## Building ht2crack4

```bash
# Build the attack tool
make

# Or rebuild from scratch
make fresh

# Clean build files
make clean
```

This compiles `ht2crack4` from the source files: `ht2crack4.c`, `hitagcrypto.c`, `ht2crack2utils.c`, and `utilpart.c`.

## Usage (single attack)

### Step 1: Generate Nonce Pairs

Use the Python script to generate simulated encrypted nonce/keystream pairs:

```bash
# Basic usage (uses default key,UID and filename)
python3 hitag2_simulation.py

# Custom key and UID with 16 nonce pairs (uses filename)
python3 hitag2_simulation.py --key 4F4E4D494B52 --uid AABBCCDD -n 16

# Specify output file
python3 hitag2_simulation.py --key 4F4E4D494B52 --uid AABBCCDD -n 16 -o nonces.txt

# Run verification tests only
python3 hitag2_simulation.py --verify
```

**Python Script Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--key` | 48-bit key (12 hex chars) | `4F4E4D494B52` |
| `--uid` | 32-bit UID (8 hex chars) | `AABBCCDD` |
| `-n, --num-nonces` | Number of nonce pairs to generate | `16` |
| `-o, --output` | Output filename | `nonces.txt` |
| `--seed` | Random seed for reproducibility | `42` |
| `--verify` | Run MIKRON test vector only | - |

### Step 2: Recover the Key

Use the ht2crack4 tool to perform the correlation attack:

```bash
./ht2crack4 -u AABBCCDD -n nonces.txt -N 16 -t 2000000
```

**ht2crack4 Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `-u` | UID (required) | - |
| `-n` | Nonce file path (required) | - |
| `-N` | Number of nonce pairs to use | all in file |
| `-t` | Table size (max candidates kept) | `800000` |

**Table Size Recommendations:**
- Start with `-t 500000` (~30s, may fail)
- Use `-t 2000000` (~60s, reliable)
- Use `-t 3000000` (~4min, high success rate)

### Complete Example

```bash
# 1. Generate 16 nonce pairs with a known key
python3 hitag2_simulation.py --key 4F4E4D494B52 --uid AABBCCDD -n 16

# 2. Run the correlation attack to recover the key
./ht2crack4 -u AABBCCDD -n nonces.txt -N 16 -t 2000000

# Expected output:
# WIN!!! :)
# key = 4F4E4D494B52
```

## File Format

The nonce file (`nonces.txt`) contains one IV/keystream pair per line:

```
B99E8DC5 FF7DFEF3
EA4A1662 9C8B9E17
7B6A249C E98EEDDD
...
```

Each line: `<IV_hex> <authenticator_hex>` (authenticator = inverted keystream)

## Experimental Evaluation (multiple attacks)

We reuse the original Python simulator and the `ht2crack4` implementation to **automatically run the attack multiple times** while varying key parameters such as:
- the number of nonce pairs used (`N`),
- the table size (`T`),
- and the random seed (to capture probabilistic effects).

This allows us to study **success rate**, **runtime** and their trade-offs in a statistically meaningful way.

### Experimental Scale

The main grid experiment explores:
- 9 values of `N`: `N={4, 6, 8, 10, 12, 16, 20, 24, 32}`,
- 6 values of `T`: `T={200000, 400000, 800000, 1200000, 2000000, 3000000}`,
- 50 trials per configuration.

This results in **2700 independent attack runs (~30h of computing)**, logged to a CSV file for post-processing and plotting.

---

## Running the Experiments

### 1. Virtual environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Grid Experiment (N, T, trials → CSV)

```bash
python3 scripts/run_grid.py
```
*Output: data/grid/grid_results.csv*

### 3. Plot Generation
```bash
python3 scripts/make_plots.py
```
*Output: figures/*

## Project Structure

```
├── hitag2_simulation.py          # Python HiTag2 cipher simulation
├── ht2crack4.c                   # Main correlation attack implementation
├── hitagcrypto.c/h               # HiTag2 crypto primitives
├── ht2crack2utils.c/h            # Utility functions
├── utilpart.c                    # Byte-order conversion utilities
├── util.h                        # Bit reversal macros
├── Makefile                      # Build configuration
├── nonces.txt                    # Generated nonce pairs (output)
│
├── scripts/
│   ├── run_grid.py               # Runs the full (N,T,trials) experiment grid
│   └── make_plots.py             # Generates all figures from CSV data
│
├── data/
│   └── grid/
│       └── grid_results.csv      # Raw experimental results (=2700 runs)
│
├── figures/                      # Generated plots (PNG)
│
├── requirements.txt              # Python dependencies for experiments
└── README.md                     # This file
```

## References

- Garcia, F.D., Oswald, D., Kasper, T., Pavlidès, P. (2016). *Lock It and Still Lose It – On the (In)Security of Automotive Remote Keyless Entry Systems*. 25th USENIX Security Symposium.
- [RFIDler Project](https://github.com/ApertureLabsLtd/RFIDler) – Original source of ht2crack4
