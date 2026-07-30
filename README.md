# An Algebra for Two-Layer Cloud Filtering — Reference Implementation

Reference implementation and experiment harness for the paper
**"An Algebra for Two-Layer Cloud Filtering: Detecting Redundancy, Shadowing,
and Dominance Anomalies across Stateless Network ACLs and Stateful Security
Groups."**

The code computes the composed admitted region `Phi = A(N) ∩ A(G)` of an AWS
Network ACL (ordered, first-match, allow/deny) and a Security Group (unordered,
allow-only union), and detects the cross-layer anomalies defined in the paper
(dead SG rule, Phi-redundant SG rule, Phi-ineffective NACL allow, layer
disagreement). Everything is exact: rules are axis-parallel boxes, regions are
unions of disjoint boxes, and every check is an emptiness or containment test.

## Requirements

- Python 3.8 or newer.
- **Standard library only** — no third-party packages, no network access.
  (The figure script additionally needs `matplotlib`; see below.)

## Contents

| File | Purpose | Paper artifact |
|------|---------|----------------|
| `two_layer_experiments.py`     | Main harness, `d = 4` header space (proto, src, dst, dport). Correctness, scaling, anomaly + injection experiments. | Tables 3, 4; Figure 4 |
| `two_layer_experiments_ext.py` | Dimension-generic companion. Re-runs correctness + scaling for IPv6 (128-bit) and ICMP (`d = 6`). | Table 5 |
| `figures/fig_worked_example.py` | Draws the worked example of Section 7 to scale (1200-dpi PNG + vector PDF; needs `matplotlib`). | Figure 3 |
| `results/`                     | Saved console output from the exact runs reported in the paper (see below). | — |

### Archived run logs (`results/`)

| File | Run | Paper artifact |
|------|-----|----------------|
| `results_thorough_seed20060626_*.txt` | Main harness, `--preset thorough --seed 20060626` | Tables 3, 4; Figure 4 |
| `results_thorough_seed2_*.txt`        | Main harness, `--preset thorough --seed 2` (confirmation) | Section 8 text |
| `results_quick_seed20060626_*.txt`    | Main harness, `--preset quick` (smoke test) | — |
| `run_ext_windows_seed20060626.txt`    | Extension harness, IPv4/IPv6/ICMP profiles | Table 5 |

All four logs were produced on Windows 11, CPython 3.12.8. The box counts in
these logs match the paper exactly; only the build-time column varies between
runs, as timing is environment-dependent.

## Reproducing the results

### Main experiments (Tables 3, 4; Figure 4 data)

```bash
# Quick smoke test (a few seconds)
python3 two_layer_experiments.py

# Full run used in the paper (~20 min); reproduces Tables 3 and 4
python3 two_layer_experiments.py --preset thorough --seed 20060626

# Second seed for confirmation
python3 two_layer_experiments.py --preset thorough --seed 2
```

Each run prints paper-ready tables and also writes a timestamped results file.
Correctness (`mismatches = 0`) and the box counts are deterministic for a fixed
seed; wall-clock timing is environment-specific.

### Header-space extensions (Table 5)

```bash
# IPv6 (128-bit addresses) and ICMP (d = 6), plus an IPv4 baseline
python3 two_layer_experiments_ext.py

# A single profile
python3 two_layer_experiments_ext.py --profile ipv6
python3 two_layer_experiments_ext.py --profile icmp --sizes 8 16 24 32 --reps 4
```

This harness is **dimension-generic**: the header space is given as a list of
axes, so widening `src`/`dst` to 128-bit integers (IPv6) or adding
`icmp_type`/`icmp_code` axes (ICMP) requires no change to the region algebra —
only the value of `d`. Each profile is validated against an independent
brute-force oracle.

### Figures

Figure 3 of the paper (the Section 7 worked example, drawn to scale) is fully
reproducible from this repository:

```bash
cd figures && python3 fig_worked_example.py   # writes worked_example.png (1200 dpi) and worked_example.pdf
```

Figure 4 (the scaling plot) is a log–log rendering of exactly the Table 3 data
recorded in `results/results_thorough_seed20060626_*.txt`; Figures 1–2 are
schematic illustrations whose full construction is described in their captions.

## Environment used in the paper

- Main scaling/anomaly tables: Windows 11, CPython 3.12.8.
- IPv6/ICMP extension table (Table 5): Windows 11, CPython 3.12.8 (same machine).
- Default seed: `20060626`; confirmation seed: `2`.

Because the algorithm is exact, the correctness outcome (zero mismatches) and
the box counts reproduce on any platform; only timing varies.

## Citing

If you use this code, please cite the paper. Repository: https://github.com/thawatchai2799/Algebra_20260617_1340
A permanent archive is on Zenodo: DOI 10.5281/zenodo.20733876 (release tag v1.0).
The tag pins the exact code and archived logs behind every number reported in
the paper; the build-time column of Table 3 in the revised manuscript matches
`results/results_thorough_seed20060626_20260617-042039.txt` exactly.

## License

Released under the MIT License — see `LICENSE`.
