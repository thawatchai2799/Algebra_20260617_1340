#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
two_layer_experiments.py
========================

Experimental harness for the paper
"An Algebra for Two-Layer Cloud Filtering" (NACL  intersect  SG).

It extends the boundary/bucket analyzer with:
  * SG as a UNION of allow boxes  ->  A(G)        (kept disjoint internally)
  * the composition Phi = A(N)  intersect  A(G)
  * cross-layer anomaly detection (dead SG rule, Phi-redundant SG,
    Phi-ineffective NACL allow [sufficient cond.], layer disagreement)
  * a synthetic (N, G) generator with controllable anomaly injection
  * a brute-force ground-truth oracle (independent of the region engine)
  * three experiments that print paper-ready tables:
        EXP 1  Correctness vs brute force          (validates Thm 1 & Thm 5)
        EXP 2  Box-count / scaling                 (validates Thm 2)
        EXP 3  Anomaly detection + injection        (sensitivity + real-ish configs)

USAGE
    python3 two_layer_experiments.py            # run all three experiments
    python3 two_layer_experiments.py --seed 7   # reproducible run

IMPORTANT (research integrity)
    The NUMBERS this script prints are real measurements from YOUR run.
    Record your own machine + Python version in the paper. Timing is
    environment-specific; correctness (mismatch = 0) and box counts are
    reproducible properties of the algorithm.

Dimensions D = (proto, src, dst, dport),  d = 4   (paper Definition 1).
"""

from __future__ import annotations

import argparse
import ipaddress
import platform
import random
import sys
import time
from dataclasses import dataclass, field
from itertools import product
from typing import Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Output: results go to BOTH the screen and a text file (pr); live progress
# goes to stderr only (progress) so it stays out of the saved results file.
# ---------------------------------------------------------------------------
LOG = None  # set in main() to an open file handle


def pr(s=""):
    """Print a result line to the screen and (if open) to the results file."""
    s = str(s)
    sys.stdout.write(s + "\n")
    sys.stdout.flush()
    if LOG is not None:
        LOG.write(s + "\n")
        LOG.flush()


def progress(s):
    """Transient progress line on stderr (carriage return, screen only)."""
    sys.stderr.write("\r" + s.ljust(72))
    sys.stderr.flush()


def progress_done():
    sys.stderr.write("\n")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Dimensions
# ---------------------------------------------------------------------------
DIM_NAMES = ("proto", "src", "dst", "dport")
NDIM = len(DIM_NAMES)

Interval = Tuple[int, int]


@dataclass(frozen=True)
class Box:
    """A hyper-rectangle: one closed integer interval per dimension."""
    dims: Tuple[Interval, ...]

    def size(self) -> int:
        n = 1
        for lo, hi in self.dims:
            n *= (hi - lo + 1)
        return n

    def contains(self, p: Sequence[int]) -> bool:
        return all(lo <= p[i] <= hi for i, (lo, hi) in enumerate(self.dims))


def box_intersect(a: Box, b: Box) -> Optional[Box]:
    dims = []
    for (alo, ahi), (blo, bhi) in zip(a.dims, b.dims):
        lo, hi = max(alo, blo), min(ahi, bhi)
        if lo > hi:
            return None
        dims.append((lo, hi))
    return Box(tuple(dims))


def box_subtract(a: Box, b: Box) -> List[Box]:
    """a \\ b  ->  list of disjoint boxes (guillotine, <= 2*NDIM pieces)."""
    inter = box_intersect(a, b)
    if inter is None:
        return [a]
    pieces: List[Box] = []
    remaining = list(a.dims)
    for d in range(NDIM):
        alo, ahi = a.dims[d]
        ilo, ihi = inter.dims[d]
        if alo < ilo:
            piece = list(remaining); piece[d] = (alo, ilo - 1); pieces.append(Box(tuple(piece)))
        if ihi < ahi:
            piece = list(remaining); piece[d] = (ihi + 1, ahi); pieces.append(Box(tuple(piece)))
        remaining[d] = (ilo, ihi)
    return pieces


class Region:
    """A set of PAIRWISE-DISJOINT boxes (maintained disjoint by construction)."""

    def __init__(self, boxes: Optional[List[Box]] = None):
        self.boxes: List[Box] = boxes if boxes is not None else []

    # --- builders -------------------------------------------------------
    def union_box(self, b: Box) -> "Region":
        """Add box b keeping the region disjoint: add only b \\ (current region)."""
        rem = [b]
        for e in self.boxes:
            nxt: List[Box] = []
            for r in rem:
                nxt.extend(box_subtract(r, e))
            rem = nxt
            if not rem:
                break
        self.boxes.extend(rem)
        return self

    # --- set algebra ----------------------------------------------------
    def intersect(self, other: "Region") -> "Region":
        out: List[Box] = []
        for r in self.boxes:
            for s in other.boxes:
                i = box_intersect(r, s)
                if i is not None:
                    out.append(i)
        return Region(out)

    def intersect_box(self, b: Box) -> "Region":
        out = []
        for box in self.boxes:
            i = box_intersect(box, b)
            if i is not None:
                out.append(i)
        return Region(out)

    def subtract(self, other: "Region") -> "Region":
        boxes = list(self.boxes)
        for e in other.boxes:
            nxt: List[Box] = []
            for r in boxes:
                nxt.extend(box_subtract(r, e))
            boxes = nxt
            if not boxes:
                break
        return Region(boxes)

    def subtract_box(self, b: Box) -> "Region":
        out: List[Box] = []
        for box in self.boxes:
            out.extend(box_subtract(box, b))
        return Region(out)

    # --- predicates -----------------------------------------------------
    def contains_point(self, p: Sequence[int]) -> bool:
        return any(box.contains(p) for box in self.boxes)

    def cardinality(self) -> int:
        return sum(box.size() for box in self.boxes)

    def is_empty(self) -> bool:
        return self.cardinality() == 0

    def subset_of(self, other: "Region") -> bool:
        return self.subtract(other).is_empty()

    def nbox(self) -> int:
        return len(self.boxes)


# ---------------------------------------------------------------------------
# Field parsing (CIDR / range / any) -> interval
# ---------------------------------------------------------------------------
ANY = ("any", "*", "all", "0.0.0.0/0")
IP_MAX = (1 << 32) - 1
PORT_MAX = 65535
PROTO = {"tcp": 6, "udp": 17}


def parse_proto(v) -> Interval:
    v = str(v).strip().lower()
    if v in ANY:
        return (0, 255)
    n = PROTO.get(v, int(v) if str(v).isdigit() else None)
    if n is None:
        raise ValueError("proto %r" % v)
    return (n, n)


def parse_ip(v) -> Interval:
    v = str(v).strip().lower()
    if v in ANY:
        return (0, IP_MAX)
    if "-" in v:
        a, b = v.split("-", 1)
        a, b = int(ipaddress.IPv4Address(a.strip())), int(ipaddress.IPv4Address(b.strip()))
        return (min(a, b), max(a, b))
    if "/" in v:
        net = ipaddress.IPv4Network(v, strict=False)
        return (int(net.network_address), int(net.broadcast_address))
    a = int(ipaddress.IPv4Address(v))
    return (a, a)


def parse_port(v) -> Interval:
    v = str(v).strip().lower()
    if v in ANY:
        return (0, PORT_MAX)
    if "-" in v:
        a, b = v.split("-", 1)
        return (min(int(a), int(b)), max(int(a), int(b)))
    p = int(v)
    return (p, p)


def make_box(proto, src, dst, dport) -> Box:
    return Box((parse_proto(proto), parse_ip(src), parse_ip(dst), parse_port(dport)))


# ---------------------------------------------------------------------------
# Policy model
# ---------------------------------------------------------------------------
@dataclass
class NaclRule:
    box: Box
    action: str  # 'allow' | 'deny'


@dataclass
class Policy:
    nacl: List[NaclRule]      # ordered, first-match
    sg: List[Box]             # allow-only union
    name: str = ""


# --- semantics: A(N), A(G), Phi --------------------------------------------
def accept_nacl(nacl: List[NaclRule], top: Box) -> Tuple[Region, List[Region]]:
    """Return A(N) and the list of per-rule effective regions E_i."""
    B = Region([top])
    AN = Region()
    E: List[Region] = []
    for r in nacl:
        Ei = B.intersect_box(r.box)
        E.append(Ei)
        B = B.subtract_box(r.box)
        if r.action == "allow":
            for bx in Ei.boxes:
                AN.union_box(bx)
    return AN, E


def accept_sg(sg: List[Box]) -> Region:
    AG = Region()
    for b in sg:
        AG.union_box(b)
    return AG


def compose(AN: Region, AG: Region) -> Region:
    return AN.intersect(AG)


# --- brute-force ground truth (independent of the region engine) -----------
def nacl_decision(nacl: List[NaclRule], p) -> str:
    for r in nacl:
        if r.box.contains(p):
            return r.action
    return "deny"  # implicit default deny


def sg_admits(sg: List[Box], p) -> bool:
    return any(b.contains(p) for b in sg)


def admitted_bruteforce(pol: Policy, p) -> bool:
    return nacl_decision(pol.nacl, p) == "allow" and sg_admits(pol.sg, p)


# ---------------------------------------------------------------------------
# Anomaly detection (region-based, exact)
# ---------------------------------------------------------------------------
@dataclass
class Report:
    nacl_fully_shadowed: List[int] = field(default_factory=list)
    nacl_partially_shadowed: List[int] = field(default_factory=list)
    sg_intra_redundant: List[int] = field(default_factory=list)
    sg_dead: List[int] = field(default_factory=list)
    sg_phi_redundant: List[int] = field(default_factory=list)
    nacl_phi_ineffective: List[int] = field(default_factory=list)  # sufficient cond.
    disagreement_WN_boxes: int = 0
    disagreement_WG_boxes: int = 0
    phi_boxes: int = 0
    phi_card: int = 0


def detect(pol: Policy, top: Box) -> Report:
    AN, E = accept_nacl(pol.nacl, top)
    AG = accept_sg(pol.sg)
    PHI = compose(AN, AG)
    rep = Report(phi_boxes=PHI.nbox(), phi_card=PHI.cardinality())

    # single-layer: NACL shadowing
    for i, r in enumerate(pol.nacl):
        ec = E[i].cardinality()
        if ec == 0:
            rep.nacl_fully_shadowed.append(i)
        elif ec < r.box.size():
            rep.nacl_partially_shadowed.append(i)

    # single-layer: intra-SG redundancy  (m_j subset of union of the others)
    for j in range(len(pol.sg)):
        others = accept_sg([b for k, b in enumerate(pol.sg) if k != j])
        if Region([pol.sg[j]]).subset_of(others):
            rep.sg_intra_redundant.append(j)

    # cross-layer
    for j, mj in enumerate(pol.sg):
        mj_in_AN = AN.intersect_box(mj)               # m_j  intersect  A(N)
        if mj_in_AN.is_empty():
            rep.sg_dead.append(j)                     # Definition 9
        others = accept_sg([b for k, b in enumerate(pol.sg) if k != j])
        if mj_in_AN.subset_of(others):                # Theorem 4(2) iff
            rep.sg_phi_redundant.append(j)

    # cross-layer: Phi-ineffective NACL allow (sufficient condition E_i  intersect  A(G) = empty)
    for i, r in enumerate(pol.nacl):
        if r.action == "allow" and E[i].intersect(AG).is_empty():
            rep.nacl_phi_ineffective.append(i)

    # layer disagreement
    rep.disagreement_WN_boxes = AN.subtract(AG).nbox()
    rep.disagreement_WG_boxes = AG.subtract(AN).nbox()
    return rep


# ---------------------------------------------------------------------------
# Domain profiles
# ---------------------------------------------------------------------------
@dataclass
class Domain:
    protos: Tuple[int, ...]
    ip_max: int
    port_max: int

    def top(self) -> Box:
        return Box(((min(self.protos), max(self.protos)),
                    (0, self.ip_max), (0, self.ip_max), (0, self.port_max)))

    def enumerate_all(self):
        for pr in self.protos:
            for s in range(self.ip_max + 1):
                for d in range(self.ip_max + 1):
                    for dp in range(self.port_max + 1):
                        yield (pr, s, d, dp)

    def random_packet(self, rng: random.Random):
        return (rng.choice(self.protos),
                rng.randint(0, self.ip_max),
                rng.randint(0, self.ip_max),
                rng.randint(0, self.port_max))


# NOTE: in the SMALL correctness profile, proto is a *contiguous* 2-value domain
# {6,7} so that the interval [6,7] used by the region engine equals the discrete
# set enumerated by the brute-force oracle (avoids a spurious model mismatch).
SMALL = Domain(protos=(6, 7), ip_max=15, port_max=15)            # 2*16*16*16 = 8192 packets
MEDIUM = Domain(protos=(6, 7), ip_max=255, port_max=255)         # ~33.5M packets: random-only
FULL = Domain(protos=(6, 17), ip_max=IP_MAX, port_max=PORT_MAX)  # realistic ranges


# ---------------------------------------------------------------------------
# Synthetic policy generator
# ---------------------------------------------------------------------------
def _rand_interval(rng: random.Random, hi: int, any_prob: float) -> Interval:
    if rng.random() < any_prob:
        return (0, hi)
    a = rng.randint(0, hi)
    b = rng.randint(0, hi)
    return (min(a, b), max(a, b))


def _rand_box(rng: random.Random, dom: Domain, any_prob: float = 0.3) -> Box:
    pr = rng.choice(dom.protos)
    return Box((((pr, pr) if rng.random() > 0.2 else (min(dom.protos), max(dom.protos))),
                _rand_interval(rng, dom.ip_max, any_prob),
                _rand_interval(rng, dom.ip_max, any_prob),
                _rand_interval(rng, dom.port_max, any_prob)))


def gen_policy(rng: random.Random, dom: Domain, k: int, t: int,
               allow_prob: float = 0.6, name: str = "") -> Policy:
    nacl = [NaclRule(_rand_box(rng, dom), "allow" if rng.random() < allow_prob else "deny")
            for _ in range(k)]
    sg = [_rand_box(rng, dom) for _ in range(t)]
    return Policy(nacl=nacl, sg=sg, name=name)


def inject_anomalies(rng: random.Random, dom: Domain, pol: Policy,
                     n_dead: int, n_redundant: int) -> Policy:
    """Inject KNOWN anomalies for sensitivity testing.

    * dead SG rule: prepend a top-priority NACL deny of a fresh box D, then add
      an SG rule equal to D  ->  D is fully NACL-denied  ->  the SG rule is dead.
    * redundant SG rule: duplicate an existing SG rule  ->  intra-SG (and Phi-) redundant.
    """
    nacl = list(pol.nacl)
    sg = list(pol.sg)
    for _ in range(n_dead):
        D = _rand_box(rng, dom, any_prob=0.0)
        nacl.insert(0, NaclRule(D, "deny"))   # highest priority deny over all of D
        sg.append(D)                          # SG allows D, but NACL kills it -> dead
    for _ in range(n_redundant):
        if sg:
            sg.append(sg[rng.randrange(len(sg))])  # exact duplicate -> redundant
    return Policy(nacl=nacl, sg=sg, name=pol.name + "+inj")


# ---------------------------------------------------------------------------
# Brute-force anomaly oracle (for validating the detector in EXP 1)
# ---------------------------------------------------------------------------
def bf_dead_sg(pol: Policy, dom: Domain, j: int) -> bool:
    """m_j is dead iff no packet inside m_j is NACL-allowed (enumerate m_j cap domain)."""
    mj = pol.sg[j]
    (plo, phi), (slo, shi), (dlo, dhi), (qlo, qhi) = mj.dims
    for pr in range(max(plo, min(dom.protos)), min(phi, max(dom.protos)) + 1):
        if pr not in dom.protos:
            continue
        for s in range(max(slo, 0), min(shi, dom.ip_max) + 1):
            for d in range(max(dlo, 0), min(dhi, dom.ip_max) + 1):
                for q in range(max(qlo, 0), min(qhi, dom.port_max) + 1):
                    if nacl_decision(pol.nacl, (pr, s, d, q)) == "allow":
                        return False
    return True


def bf_phi_redundant_sg(pol: Policy, dom: Domain, j: int) -> bool:
    """m_j is Phi-redundant iff removing it changes no packet's admission."""
    pol2 = Policy(pol.nacl, [b for k, b in enumerate(pol.sg) if k != j])
    for p in dom.enumerate_all():
        if admitted_bruteforce(pol, p) != admitted_bruteforce(pol2, p):
            return False
    return True


# ---------------------------------------------------------------------------
# Pretty table printer
# ---------------------------------------------------------------------------
def print_table(headers: Sequence[str], rows: Sequence[Sequence], caption: str = ""):
    cols = list(zip(*([headers] + [[str(c) for c in r] for r in rows]))) if rows else [[h] for h in headers]
    widths = [max(len(str(c)) for c in col) for col in cols]
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    pr(line)
    pr("-" * len(line))
    for r in rows:
        pr("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))
    if caption:
        pr(caption)


# ---------------------------------------------------------------------------
# EXPERIMENT 1 — Correctness vs brute force  (Thm 1 & Thm 5)
# ---------------------------------------------------------------------------
def experiment_1(rng: random.Random, n_configs: int = 5, n_random: int = 5000):
    pr("\n" + "=" * 74)
    pr("EXPERIMENT 1  Correctness of Phi vs brute force")
    pr("  (a) exhaustive over SMALL domain (8192 pkts)  (b) random over MEDIUM domain (~33.5M)")
    pr("=" * 74)
    topS = SMALL.top()
    topM = MEDIUM.top()
    rows = []
    total_pkt_mismatch = total_anom_mismatch = 0
    exhaustive = list(SMALL.enumerate_all())
    for c in range(n_configs):
        progress("EXP1  config %d/%d   pkt_mism=%d  anom_mism=%d"
                 % (c + 1, n_configs, total_pkt_mismatch, total_anom_mismatch))
        # (a) SMALL policy: exhaustive packet check + anomaly-detector vs brute-force oracle
        kS, tS = rng.randint(4, 10), rng.randint(4, 10)
        polS = gen_policy(rng, SMALL, kS, tS, name="cfg%d" % c)
        AN_S, _ = accept_nacl(polS.nacl, topS)
        PHI_S = compose(AN_S, accept_sg(polS.sg))
        exh_mism = sum(1 for p in exhaustive
                       if PHI_S.contains_point(p) != admitted_bruteforce(polS, p))
        rep = detect(polS, topS)
        anom_mism = 0
        for j in range(len(polS.sg)):
            if (j in rep.sg_dead) != bf_dead_sg(polS, SMALL, j):
                anom_mism += 1
            if (j in rep.sg_phi_redundant) != bf_phi_redundant_sg(polS, SMALL, j):
                anom_mism += 1

        # (b) MEDIUM policy: random sampling (exhaustive infeasible here)
        kM, tM = rng.randint(6, 12), rng.randint(6, 12)
        polM = gen_policy(rng, MEDIUM, kM, tM)
        PHI_M = compose(accept_nacl(polM.nacl, topM)[0], accept_sg(polM.sg))
        rnd_mism = sum(1 for _ in range(n_random)
                       for p in [MEDIUM.random_packet(rng)]
                       if PHI_M.contains_point(p) != admitted_bruteforce(polM, p))

        total_pkt_mismatch += exh_mism + rnd_mism
        total_anom_mismatch += anom_mism
        rows.append([polS.name, kS, tS, len(exhaustive), n_random,
                     exh_mism, rnd_mism, anom_mism, PHI_S.nbox()])

    progress_done()
    print_table(
        ["Config", "k", "t", "exhaustive", "random", "exh mism", "rnd mism", "anom mism", "|Phi|S"],
        rows,
        caption=("\n%d configs | total packet checks = %s | packet mismatches = %d, "
                 "anomaly mismatches = %d  (expected 0 / 0 -> validates Thm 1 & Thm 5)"
                 % (n_configs, format(n_configs * (8192 + n_random), ","),
                    total_pkt_mismatch, total_anom_mismatch)))
    return total_pkt_mismatch, total_anom_mismatch


# ---------------------------------------------------------------------------
# EXPERIMENT 2 — Box-count / scaling  (Thm 2)
# ---------------------------------------------------------------------------
def grid_bound(pol: Policy) -> int:
    """Product over dimensions of the number of distinct endpoints (the O((k+t)^d) grid)."""
    bound = 1
    boxes = [r.box for r in pol.nacl] + list(pol.sg)
    for d in range(NDIM):
        pts = set()
        for b in boxes:
            lo, hi = b.dims[d]
            pts.add(lo); pts.add(hi + 1)
        bound *= max(1, 2 * len(pts) + 1)
    return bound


def experiment_2(rng: random.Random, sizes=(4, 8, 12, 16, 20, 24, 28, 32),
                 reps: int = 1, phi_cap: int = 400000):
    pr("\n" + "=" * 74)
    pr("EXPERIMENT 2  Box-count and scaling (FULL domain), reps=%d" % reps)
    pr("=" * 74)
    top = FULL.top()
    rows = []
    for total in sizes:
        k = total // 2
        t = total - k
        phis, ans, ags, bounds, times, maxphi, aborted = [], [], [], [], [], 0, 0
        for r in range(reps):
            progress("EXP2  size %d (k=%d,t=%d)  rep %d/%d" % (total, k, t, r + 1, reps))
            pol = gen_policy(rng, FULL, k, t)
            t0 = time.perf_counter()
            AN, _ = accept_nacl(pol.nacl, top)
            AG = accept_sg(pol.sg)
            PHI = compose(AN, AG)
            ms = (time.perf_counter() - t0) * 1000.0
            nb = PHI.nbox()
            if nb > phi_cap:                 # safety guard against worst-case blow-up
                aborted += 1
                continue
            phis.append(nb); ans.append(AN.nbox()); ags.append(AG.nbox())
            bounds.append(grid_bound(pol)); times.append(ms); maxphi = max(maxphi, nb)
        if not phis:
            rows.append([total, k, t, "-", "-", "ABORTED(>cap)", "-", "-", "-"]); continue
        mean = lambda xs: sum(xs) / len(xs)
        rows.append([total, k, t,
                     "%.0f" % mean(ans), "%.0f" % mean(ags),
                     "%.0f" % mean(phis), maxphi,
                     "%.2e" % mean(bounds), "%.1f" % mean(times)])
    progress_done()
    print_table(
        ["rules", "k", "t", "|A(N)|", "|A(G)|", "|Phi|avg", "|Phi|max", "grid bound", "build ms"],
        rows,
        caption=("\nMean over %d reps per size. |Phi| stays far below the O((k+t)^d) grid "
                 "bound -> Thm 2 (worst-case, not typical)." % reps))
    return rows


# ---------------------------------------------------------------------------
# EXPERIMENT 3 — Anomaly detection + injection (FULL domain)
# ---------------------------------------------------------------------------
def realistic_configs() -> List[Policy]:
    """Hand-crafted three-tier examples that contain known anomalies."""
    cfgs = []

    # C1 web tier: NACL denies port 22 entirely, but an SG rule allows 22 -> dead SG rule.
    cfgs.append(Policy(name="web-tier", nacl=[
        NaclRule(make_box("tcp", "any", "any", "22"), "deny"),     # block SSH at subnet
        NaclRule(make_box("tcp", "any", "any", "any"), "allow"),
    ], sg=[
        make_box("tcp", "0.0.0.0/0", "10.0.1.0/24", "443"),
        make_box("tcp", "0.0.0.0/0", "10.0.1.0/24", "80"),
        make_box("tcp", "10.0.0.0/8", "10.0.1.0/24", "22"),        # DEAD: NACL blocks 22
    ]))

    # C2 app tier: duplicate SG rule -> redundancy; SG allows DB port NACL never reaches.
    cfgs.append(Policy(name="app-tier", nacl=[
        NaclRule(make_box("tcp", "10.0.1.0/24", "10.0.2.0/24", "8080"), "allow"),
        NaclRule(make_box("tcp", "any", "any", "any"), "deny"),
    ], sg=[
        make_box("tcp", "10.0.1.0/24", "10.0.2.0/24", "8080"),
        make_box("tcp", "10.0.1.0/24", "10.0.2.0/24", "8080"),     # REDUNDANT duplicate
        make_box("tcp", "10.0.1.0/24", "10.0.2.0/24", "3306"),     # DEAD: NACL denies 3306
    ]))

    # C3 db tier: layer disagreement (NACL allows a wide range SG does not).
    cfgs.append(Policy(name="db-tier", nacl=[
        NaclRule(make_box("tcp", "10.0.2.0/24", "10.0.3.0/24", "3306"), "allow"),
        NaclRule(make_box("tcp", "10.0.0.0/8", "10.0.3.0/24", "any"), "allow"),  # broad allow
        NaclRule(make_box("tcp", "any", "any", "any"), "deny"),
    ], sg=[
        make_box("tcp", "10.0.2.0/24", "10.0.3.0/24", "3306"),     # SG only opens 3306
    ]))
    return cfgs


def experiment_3(rng: random.Random, n_trials: int = 5):
    pr("\n" + "=" * 74)
    pr("EXPERIMENT 3a  Anomaly detection on realistic example configs (FULL domain)")
    pr("=" * 74)
    top = FULL.top()
    rows = []
    for pol in realistic_configs():
        rep = detect(pol, top)
        rows.append([pol.name, len(pol.nacl), len(pol.sg),
                     len(rep.sg_dead), len(rep.sg_phi_redundant),
                     len(rep.nacl_fully_shadowed) + len(rep.nacl_partially_shadowed),
                     rep.disagreement_WN_boxes, rep.disagreement_WG_boxes])
    print_table(
        ["config", "|NACL|", "|SG|", "dead SG", "Phi-redun", "NACL shadow", "W_N box", "W_G box"],
        rows, caption="")

    pr("\n" + "=" * 74)
    pr("EXPERIMENT 3b  Injection sensitivity (FULL domain): inject 2 dead + 2 redundant")
    pr("=" * 74)
    rows = []
    for tr in range(n_trials):
        progress("EXP3b trial %d/%d" % (tr + 1, n_trials))
        k = rng.randint(6, 12)
        t = rng.randint(6, 12)
        base = gen_policy(rng, FULL, k, t, name="trial%d" % tr)
        rb = detect(base, top)
        inj = inject_anomalies(rng, FULL, base, n_dead=2, n_redundant=2)
        ri = detect(inj, top)
        rows.append([tr,
                     "%d->%d" % (len(rb.sg_dead), len(ri.sg_dead)),
                     "%d->%d" % (len(rb.sg_phi_redundant), len(ri.sg_phi_redundant)),
                     len(ri.sg_dead) - len(rb.sg_dead),
                     len(ri.sg_phi_redundant) - len(rb.sg_phi_redundant)])
    progress_done()
    print_table(
        ["trial", "dead (base->inj)", "Phi-redun (base->inj)", "d(dead)", "d(redun)"],
        rows,
        caption=("\nInjected 2 dead + 2 redundant per trial; deltas >= 2 confirm the injected "
                 "anomalies are detected (Thm 5 completeness; extra hits are natural anomalies)."))
    return rows


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
PRESETS = {
    # name      : (exp1_configs, exp1_random, exp2_sizes,                   exp2_reps, exp3_trials)
    "quick":     (5,   5000,  (4, 8, 12, 16, 20, 24, 28, 32),               1,  5),
    "standard":  (30,  20000, (4, 8, 12, 16, 20, 24, 28, 32, 36, 40),       5,  15),
    "thorough":  (250, 50000, (4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48), 20, 40),
}


def main():
    ap = argparse.ArgumentParser(
        description="Two-layer (NACL cap SG) experiment harness.")
    ap.add_argument("--preset", choices=list(PRESETS), default="quick",
                    help="quick (~seconds), standard (~1-3 min), thorough (~20-30 min)")
    ap.add_argument("--seed", type=int, default=20060626)
    ap.add_argument("--only", choices=["1", "2", "3"], default=None)
    # individual overrides (None = take from preset)
    ap.add_argument("--exp1-configs", type=int, default=None)
    ap.add_argument("--exp1-random", type=int, default=None)
    ap.add_argument("--exp2-sizes", type=str, default=None,
                    help="comma list, e.g. 4,8,12,16")
    ap.add_argument("--exp2-reps", type=int, default=None)
    ap.add_argument("--exp3-trials", type=int, default=None)
    ap.add_argument("--save", type=str, default=None,
                    help="results text file (default: auto-named); use --no-save to disable")
    ap.add_argument("--no-save", action="store_true", help="do not write a results file")
    args = ap.parse_args()

    c1, r1, sizes, reps2, tr3 = PRESETS[args.preset]
    if args.exp1_configs is not None: c1 = args.exp1_configs
    if args.exp1_random is not None:  r1 = args.exp1_random
    if args.exp2_sizes:               sizes = tuple(int(x) for x in args.exp2_sizes.split(","))
    if args.exp2_reps is not None:    reps2 = args.exp2_reps
    if args.exp3_trials is not None:  tr3 = args.exp3_trials

    rng = random.Random(args.seed)

    global LOG
    save_path = None
    if not args.no_save:
        save_path = args.save or ("results_%s_seed%d_%s.txt"
                                  % (args.preset, args.seed, time.strftime("%Y%m%d-%H%M%S")))
        LOG = open(save_path, "w", encoding="utf-8")
        sys.stderr.write("Writing results to: %s\n" % save_path)
        sys.stderr.flush()

    pr("two_layer_experiments.py")
    pr("Python %s on %s | seed=%d | %s"
          % (platform.python_version(), platform.platform(),
             args.seed, time.strftime("%Y-%m-%d")))
    pr("preset=%s | exp1 configs=%d random=%d | exp2 sizes=%s reps=%d | exp3 trials=%d"
          % (args.preset, c1, r1, sizes, reps2, tr3))
    pr("Dimensions d = %d  %s" % (NDIM, DIM_NAMES))

    wall0 = time.perf_counter()
    if args.only in (None, "1"):
        experiment_1(rng, n_configs=c1, n_random=r1)
    if args.only in (None, "2"):
        experiment_2(rng, sizes=sizes, reps=reps2)
    if args.only in (None, "3"):
        experiment_3(rng, n_trials=tr3)
    pr("\nTotal wall time: %.1f s" % (time.perf_counter() - wall0))
    if LOG is not None:
        LOG.close()
        sys.stderr.write("\nResults saved to: %s\n" % save_path)
        sys.stderr.flush()


if __name__ == "__main__":
    main()
