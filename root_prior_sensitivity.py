#!/usr/bin/env python3
"""Sensitivity of impact posteriors to the initial-state priors.

The deployment-agnostic baseline sets all four initial-state priors to
0.5. This sweep varies IS-INSIDER and IS-PHYSICAL over {0.2, 0.5, 0.8}
whilst IS-NSA and IS-SA remain at the baseline 0.5, and reports the four
impact posteriors and their ranking in each of the nine configurations.

Usage:
    python3 root_prior_sensitivity.py
"""

import itertools

from simulation import IMPACT, base_priors, marginal

VALUES = (0.2, 0.5, 0.8)
IMPACT_IDS = [i[0] for i in IMPACT]


def main():
    base = base_priors()
    hdr = f"{'INSIDER':>8}{'PHYSICAL':>10}" + "".join(f"{i:>12}" for i in IMPACT_IDS)
    print(hdr)
    print("-" * len(hdr))
    rankings = set()
    for ins, phy in itertools.product(VALUES, VALUES):
        pr = dict(base)
        pr["IS-INSIDER"] = ins
        pr["IS-PHYSICAL"] = phy
        post = {i: marginal(pr, i) for i in IMPACT_IDS}
        order = tuple(sorted(IMPACT_IDS, key=lambda i: -post[i]))
        rankings.add(order)
        print(f"{ins:>8}{phy:>10}"
              + "".join(f"{post[i]:>12.4f}" for i in IMPACT_IDS)
              + "   " + " > ".join(order))
    print(f"\ndistinct rankings across the nine configurations: {len(rankings)}")
    for r in rankings:
        print("  " + " > ".join(r))


if __name__ == "__main__":
    main()
