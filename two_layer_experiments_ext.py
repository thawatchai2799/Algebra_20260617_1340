#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
two_layer_experiments_ext.py
============================

Extension harness for "An Algebra for Two-Layer Cloud Filtering" (NACL intersect SG).

The main harness (two_layer_experiments.py) fixes the header space to
d = 4 dimensions (proto, src, dst, dport). This companion harness is
DIMENSION-GENERIC: it takes a list of axes and runs the same region
algebra over any d. We use it to show that the model and every theorem
carry over unchanged to two enlarged header spaces:

  * IPv6  : src/dst widened from 32-bit to 128-bit integers   (d = 4)
  * ICMP  : two extra axes, icmp_type and icmp_code (0..255)   (d = 6)

For each profile it runs:
  EXP A  Correctness vs a brute-force oracle  (validates Thm 1 & Thm 5)
         - exhaustive over a small sub-domain
         - random sampling over the full (possibly 128-bit) domain
  EXP B  Box-count / scaling                  (validates Thm 2)

Pure standard library, Python 3. Numbers printed are real measurements
from this run; record machine + Python version when citing them.

USAGE
    python3 two_layer_experiments_ext.py                  # all profiles
    python3 two_layer_experiments_ext.py --seed 7
    python3 two_layer_experiments_ext.py --profile ipv6
"""

from __future__ import annotations

import argparse
import platform
import random
import sys
import time
from typing import List, Sequence, Tuple

Interval = Tuple[int, int]
Box = Tuple[Interval, ...]          # one closed integer interval per axis
Region = List[Box]                  # kept pairwise-disjoint by construction


# ---------------------------------------------------------------------------
# Box calculus  (Lemma 1)
# ---------------------------------------------------------------------------
def box_intersect(a: Box, b: Box) -> Box | None:
    out = []
    for (alo, ahi), (blo, bhi) in zip(a, b):
        lo, hi = max(alo, blo), min(ahi, bhi)
        if lo > hi:
            return None
        out.append((lo, hi))
    return tuple(out)


def box_minus(a: Box, b: Box) -> Region:
    """a \\ b  ->  up to 2d disjoint boxes (guillotine peel)."""
    inter = box_intersect(a, b)
    if inter is None:
        return [a]
    pieces: Region = []
    cur = list(a)  # earlier dims get clamped to the intersection as we go
    d = len(a)
    for i in range(d):
        alo, ahi = a[i]
        ilo, ihi = inter[i]
        if alo < ilo:                                   # slab below
            piece = list(cur)
            piece[i] = (alo, ilo - 1)
            pieces.append(tuple(piece))
        if ihi < ahi:                                   # slab above
            piece = list(cur)
            piece[i] = (ihi + 1, ahi)
            pieces.append(tuple(piece))
        cur[i] = (ilo, ihi)                             # clamp and recurse
    return pieces


def box_size(a: Box) -> int:
    n = 1
    for lo, hi in a:
        n *= (hi - lo + 1)
    return n


# ---------------------------------------------------------------------------
# Region calculus  (Lemma 2): disjoint box lists
# ---------------------------------------------------------------------------
def region_add(reg: Region, b: Box) -> Region:
    """Add box b to a disjoint region, subtracting overlaps first."""
    parts = [b]
    for r in reg:
        nxt: Region = []
        for p in parts:
            nxt.extend(box_minus(p, r))
        parts = nxt
    return reg + parts


def region_union(boxes: Sequence[Box]) -> Region:
    reg: Region = []
    for b in boxes:
        reg = region_add(reg, b)
    return reg


def region_intersect(r1: Region, r2: Region) -> Region:
    out: Region = []
    for a in r1:
        for b in r2:
            c = box_intersect(a, b)
            if c is not None:
                out.append(c)            # disjoint because r1, r2 are disjoint
    return out


def region_minus(r1: Region, r2: Region) -> Region:
    cur = list(r1)
    for b in r2:
        nxt: Region = []
        for a in cur:
            nxt.extend(box_minus(a, b))
        cur = nxt
    return cur


def region_empty(reg: Region) -> bool:
    return len(reg) == 0


def point_in_region(pt: Tuple[int, ...], reg: Region) -> bool:
    for box in reg:
        if all(lo <= pt[i] <= hi for i, (lo, hi) in enumerate(box)):
            return True
    return False


# ---------------------------------------------------------------------------
# Two layers  (Definitions 5-7)
# ---------------------------------------------------------------------------
def accept_nacl(rules: Sequence[Tuple[Box, str]], top: Box):
    """First-match bucket: returns (A(N) region, list of effective regions E_i)."""
    carried: Region = [top]
    accept: Region = []
    effs: List[Region] = []
    for (box, act) in rules:
        eff = region_intersect(carried, [box])
        effs.append(eff)
        if act == "allow":
            for e in eff:
                accept = region_add(accept, e)
        carried = region_minus(carried, [box])
    return accept, effs


def accept_sg(boxes: Sequence[Box]) -> Region:
    return region_union(boxes)


def phi(an: Region, ag: Region) -> Region:
    return region_intersect(an, ag)


# ---------------------------------------------------------------------------
# Brute-force oracle (independent of the region engine)
# ---------------------------------------------------------------------------
def oracle_admits(pt, nacl, sg) -> bool:
    admit_n = False
    for (box, act) in nacl:
        if all(lo <= pt[i] <= hi for i, (lo, hi) in enumerate(box)):
            admit_n = (act == "allow")
            break
    if not admit_n:
        return False
    for box in sg:
        if all(lo <= pt[i] <= hi for i, (lo, hi) in enumerate(box)):
            return True
    return False


# ---------------------------------------------------------------------------
# Profiles: the axes of the header space
# ---------------------------------------------------------------------------
class Profile:
    def __init__(self, name, axes, small):
        self.name = name
        self.axes = axes              # list of (label, lo, hi) full domain
        self.small = small            # list of (label, lo, hi) tiny exhaustive box
        self.d = len(axes)

    def top(self) -> Box:
        return tuple((lo, hi) for (_, lo, hi) in self.axes)

    def small_box(self) -> Box:
        return tuple((lo, hi) for (_, lo, hi) in self.small)


IP4 = (1 << 32) - 1
IP6 = (1 << 128) - 1

PROFILES = {
    # IPv4 baseline (sanity check that the generic engine agrees with the model)
    "ipv4": Profile(
        "ipv4",
        [("proto", 0, 255), ("src", 0, IP4), ("dst", 0, IP4), ("dport", 0, 65535)],
        [("proto", 6, 7), ("src", 0, 7), ("dst", 0, 7), ("dport", 0, 7)],
    ),
    # IPv6: src/dst widened to 128-bit
    "ipv6": Profile(
        "ipv6",
        [("proto", 0, 255), ("src", 0, IP6), ("dst", 0, IP6), ("dport", 0, 65535)],
        [("proto", 6, 7), ("src", 0, 7), ("dst", 0, 7), ("dport", 0, 7)],
    ),
    # ICMP: two extra axes (type, code); d = 6
    "icmp": Profile(
        "icmp",
        [("proto", 0, 255), ("src", 0, IP4), ("dst", 0, IP4),
         ("dport", 0, 65535), ("itype", 0, 255), ("icode", 0, 255)],
        [("proto", 1, 2), ("src", 0, 3), ("dst", 0, 3),
         ("dport", 0, 3), ("itype", 0, 3), ("icode", 0, 3)],
    ),
}


# ---------------------------------------------------------------------------
# Random generators over a profile
# ---------------------------------------------------------------------------
def rand_box(rng: random.Random, axes, full_prob=0.45) -> Box:
    out = []
    for (_, lo, hi) in axes:
        if rng.random() < full_prob:
            out.append((lo, hi))                       # "any" on this axis
        else:
            a = rng.randint(lo, hi)
            b = rng.randint(lo, hi)
            if a > b:
                a, b = b, a
            # bias toward narrower ranges on huge axes
            if hi - lo > 1000 and rng.random() < 0.5:
                span = rng.randint(0, 255)
                a = rng.randint(lo, hi - span) if hi - span > lo else lo
                b = min(hi, a + span)
            out.append((a, b))
    return tuple(out)


def gen_nacl(rng, axes, k):
    return [(rand_box(rng, axes), "allow" if rng.random() < 0.6 else "deny")
            for _ in range(k)]


def gen_sg(rng, axes, t):
    return [rand_box(rng, axes) for _ in range(t)]


def small_axes_for_exhaustive(prof: Profile):
    return prof.small


def enumerate_points(axes):
    ranges = [range(lo, hi + 1) for (_, lo, hi) in axes]
    def rec(i, acc):
        if i == len(ranges):
            yield tuple(acc)
            return
        for v in ranges[i]:
            acc.append(v)
            yield from rec(i + 1, acc)
            acc.pop()
    yield from rec(0, [])


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------
def exp_correctness(prof: Profile, rng, configs, rnd_samples):
    top = prof.top()
    small = prof.small
    small_box = prof.small_box()
    exh_mism = rnd_mism = total_exh = total_rnd = 0
    for _ in range(configs):
        k = rng.randint(4, 9)
        t = rng.randint(4, 9)
        # generate rules confined to the small box for the exhaustive part,
        # plus full-domain rules for the random part
        nacl_small = [(box_intersect(rand_box(rng, small), small_box) or small_box,
                       "allow" if rng.random() < 0.6 else "deny") for _ in range(k)]
        sg_small = [box_intersect(rand_box(rng, small), small_box) or small_box
                    for _ in range(t)]
        an, _ = accept_nacl(nacl_small, small_box)
        ag = accept_sg(sg_small)
        ph = phi(an, ag)
        for pt in enumerate_points(small):
            total_exh += 1
            if point_in_region(pt, ph) != oracle_admits(pt, nacl_small, sg_small):
                exh_mism += 1
        # full domain random sampling
        nacl = gen_nacl(rng, prof.axes, k)
        sg = gen_sg(rng, prof.axes, t)
        an, _ = accept_nacl(nacl, top)
        ag = accept_sg(sg)
        ph = phi(an, ag)
        for _ in range(rnd_samples):
            pt = tuple(rng.randint(lo, hi) for (_, lo, hi) in prof.axes)
            total_rnd += 1
            if point_in_region(pt, ph) != oracle_admits(pt, nacl, sg):
                rnd_mism += 1
    return total_exh, total_rnd, exh_mism, rnd_mism


def exp_scaling(prof: Profile, rng, sizes, reps):
    top = prof.top()
    rows = []
    for n in sizes:
        k = t = n // 2
        phis = []
        ans = []
        ags = []
        t0 = time.perf_counter()
        for _ in range(reps):
            nacl = gen_nacl(rng, prof.axes, k)
            sg = gen_sg(rng, prof.axes, t)
            an, _ = accept_nacl(nacl, top)
            ag = accept_sg(sg)
            ph = phi(an, ag)
            phis.append(len(ph)); ans.append(len(an)); ags.append(len(ag))
        ms = (time.perf_counter() - t0) * 1000.0 / reps
        grid = (2 * (k + t)) ** prof.d
        rows.append((n, sum(ans) // reps, sum(ags) // reps,
                     sum(phis) // reps, max(phis), grid, ms))
    return rows


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def run_profile(name, seed, configs, rnd_samples, sizes, reps):
    prof = PROFILES[name]
    rng = random.Random(seed)
    addr_bits = 128 if name == "ipv6" else 32
    print("=" * 74)
    print("PROFILE %-6s  d=%d  address=%d-bit  axes=%s"
          % (name, prof.d, addr_bits, tuple(a[0] for a in prof.axes)))
    print("=" * 74)

    te, tr, em, rm = exp_correctness(prof, rng, configs, rnd_samples)
    print("EXP A  Correctness vs brute force")
    print("  exhaustive checks = %d   random checks = %d" % (te, tr))
    print("  exhaustive mismatches = %d   random mismatches = %d   (expected 0 / 0)"
          % (em, rm))
    print()

    print("EXP B  Box-count and scaling (FULL domain), reps=%d" % reps)
    print("rules  k   t   |A(N)|  |A(G)|  |Phi|avg  |Phi|max  grid bound  build ms")
    print("-" * 72)
    for (n, na, ga, pa, pm, grid, ms) in exp_scaling(prof, rng, sizes, reps):
        print("%-5d  %-3d %-3d %-7d %-7d %-9d %-9d %-11.1e %.1f"
              % (n, n // 2, n // 2, na, ga, pa, pm, float(grid), ms))
    print()
    return (name, prof.d, addr_bits, te + tr, em + rm)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20060626)
    ap.add_argument("--profile", choices=list(PROFILES) + ["all"], default="all")
    ap.add_argument("--configs", type=int, default=60)
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--sizes", type=int, nargs="+", default=[8, 16, 24, 32, 40, 48])
    ap.add_argument("--reps", type=int, default=10)
    args = ap.parse_args()

    print("two_layer_experiments_ext.py")
    print("%s | Python %s | seed=%d"
          % (platform.platform(), platform.python_version(), args.seed))
    print("configs=%d random/config=%d sizes=%s reps=%d"
          % (args.configs, args.samples, tuple(args.sizes), args.reps))
    print()

    names = list(PROFILES) if args.profile == "all" else [args.profile]
    t0 = time.time()
    summary = []
    for nm in names:
        summary.append(run_profile(nm, args.seed, args.configs,
                                   args.samples, args.sizes, args.reps))
    print("=" * 74)
    print("SUMMARY")
    print("profile  d   addr-bits   total packet checks   total mismatches")
    print("-" * 60)
    for (nm, d, bits, checks, mism) in summary:
        print("%-7s  %-3d %-9d   %-19d %d" % (nm, d, bits, checks, mism))
    print("\nTotal wall time: %.1f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
