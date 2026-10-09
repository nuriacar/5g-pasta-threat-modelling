#!/usr/bin/env python3
"""Bootstrap stress test for the OWASP flat-score classification.

Every one of the 240 sub-factor scores is perturbed independently by
+-1 (one rubric step, equal probability, clamped to the 0--9 scale);
Likelihood and Impact aggregates and the severity classification are
recomputed, and the stability of the paper's primary classification
claims is reported over N replicates. This is a stress test of scoring
uncertainty under independent one-step disagreement; it is not a model
of how experts actually disagree.

Usage:
    python3 owasp_bootstrap.py            # N = 10000
    python3 owasp_bootstrap.py 100000
"""

import random
import sys

from build_data_files import OWASP, VULN_IDS

# Raw sub-factor column indices within the OWASP tuples
# (0-3 TAF, 4 TAF agg, 5-8 VF, 9 VF agg, 10 Likelihood,
#  11-14 TI, 15 TI agg, 16-19 BI, 20 BI agg, 21 Impact)
TAF_COLS = (0, 1, 2, 3)
VF_COLS = (5, 6, 7, 8)
TI_COLS = (11, 12, 13, 14)
BI_COLS = (16, 17, 18, 19)

# Mode groups follow the paper's counting convention (tab:sensitivity):
# the NSA group holds the three NSA-mode threats, the SA group holds the
# eleven SA-mode threats plus the cross-mode threat V-T14.
NSA = ("V-T01", "V-T02", "V-T03")
SA = tuple(t for t in VULN_IDS if t not in NSA)
RANK = {"NOTE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity(lik, imp):
    if lik >= 6.0 and imp >= 6.0:
        return "CRITICAL"
    m = max(lik, imp)
    if m >= 6.0:
        return "HIGH"
    if m >= 3.0:
        return "MEDIUM"
    if m >= 2.0:
        return "LOW"
    return "NOTE"


def classify(scores):
    out = {}
    for tid in VULN_IDS:
        row = scores[tid]
        taf = sum(row[c] for c in TAF_COLS) / 4.0
        vf = sum(row[c] for c in VF_COLS) / 4.0
        ti = sum(row[c] for c in TI_COLS) / 4.0
        bi = sum(row[c] for c in BI_COLS) / 4.0
        out[tid] = severity((taf + vf) / 2.0, (ti + bi) / 2.0)
    return out


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    rng = random.Random(20261009)
    base = classify(OWASP)
    print("baseline:",
          {t: base[t] for t in VULN_IDS})
    nsa_base = [base[t] for t in NSA]
    sa_base = [base[t] for t in SA]
    assert nsa_base.count("CRITICAL") == 2, nsa_base
    assert "CRITICAL" not in sa_base and sa_base.count("HIGH") == 6, sa_base

    counts = {
        "nsa_ge1_critical": 0,
        "nsa_exactly2_critical": 0,
        "sa_zero_critical": 0,
        "sa_6_high": 0,
        "asymmetry_nsa_gt_sa": 0,
        "asymmetry_as_published": 0,
    }
    sa_high_min, sa_high_max = 99, -1
    for _ in range(n):
        s = {tid: tuple(min(9, max(0, v + rng.choice((-1, 1))))
                        for v in OWASP[tid])
             for tid in VULN_IDS}
        c = classify(s)
        nsa = [c[t] for t in NSA]
        sa = [c[t] for t in SA]
        counts["nsa_ge1_critical"] += "CRITICAL" in nsa
        counts["nsa_exactly2_critical"] += nsa.count("CRITICAL") == 2
        counts["sa_zero_critical"] += "CRITICAL" not in sa
        counts["sa_6_high"] += sa.count("HIGH") == 6
        counts["asymmetry_nsa_gt_sa"] += (max(RANK[x] for x in nsa)
                                          > max(RANK[x] for x in sa))
        counts["asymmetry_as_published"] += ("CRITICAL" in nsa
                                             and "CRITICAL" not in sa)
        sa_high_min = min(sa_high_min, sa.count("HIGH"))
        sa_high_max = max(sa_high_max, sa.count("HIGH"))
    for k, v in counts.items():
        print(f"{k:<24} {v / n:.4f}")
    print(f"sa_high_count_range      {sa_high_min}..{sa_high_max}")


if __name__ == "__main__":
    main()
