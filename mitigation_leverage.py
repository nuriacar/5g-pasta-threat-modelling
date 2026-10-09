#!/usr/bin/env python3
"""Full mitigation-leverage sweep over all 15 vulnerability nodes.

For each threat, its prior is reduced to 0.05 (the convention of the two
published what-if scenarios: mTLS enforcement on V-T04 and anti-downgrade
protection on V-T01), all posteriors are recomputed by exact inference,
and the aggregate impact reduction is reported as the sum of the four
impact-node reductions from the deployment-agnostic baseline.

Usage:
    python3 mitigation_leverage.py            # full 15-row table
    python3 mitigation_leverage.py --top5     # exit 1 if top-5 differs
"""

import sys

from simulation import IMPACT, VULN_IDS, base_priors, marginal, all_marginals

MITIGATED_PRIOR = 0.05
IMPACT_IDS = [i[0] for i in IMPACT]
PAPER_TOP5 = {"V-T05", "V-T02", "V-T06", "V-T09", "V-T01"}


def main():
    base = all_marginals(nodes=IMPACT_IDS)
    rows = []
    for tid in VULN_IDS:
        pr = base_priors()
        pr[tid] = MITIGATED_PRIOR
        deltas = {i: base[i] - marginal(pr, i) for i in IMPACT_IDS}
        rows.append((tid, deltas, sum(deltas.values())))
    rows.sort(key=lambda r: -r[2])
    hdr = f"{'threat':<8}" + "".join(f"{i:>12}" for i in IMPACT_IDS) + f"{'sum':>10}"
    print(hdr)
    print("-" * len(hdr))
    for tid, d, s in rows:
        print(f"{tid:<8}" + "".join(f"{d[i]:>12.4f}" for i in IMPACT_IDS)
              + f"{s:>10.4f}")
    top5 = [r[0] for r in rows[:5]]
    print(f"\ntop-5 (computed) = {top5}")
    print(f"top-5 (paper)    = {sorted(PAPER_TOP5)}")
    ok = set(top5) == PAPER_TOP5
    print(f"match: {ok}")
    if "--top5" in sys.argv:
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
