#!/usr/bin/env python3
"""Prior-perturbation sensitivity analysis (Section `Sensitivity Analysis`).

Perturbs all 15 vulnerability priors simultaneously by x0.9/1.1 (+-10%)
and x0.8/1.2 (+-20%), clamped to [0.01, 0.99], recomputes all posteriors
through exact inference, and reports:
  - impact node posteriors and ranking stability,
  - replication of the two what-if mitigation scenarios,
  - the top-5 mitigation set by aggregate impact reduction.
"""

from simulation import NODES, IMPACT, VULN_IDS, base_priors, all_marginals

IMPACT_IDS = [i[0] for i in IMPACT]

SCENARIOS = [("m10", 0.9), ("p10", 1.1), ("m20", 0.8), ("p20", 1.2)]


def perturbed(mult, overrides=None):
    pr = base_priors()
    for v in VULN_IDS:
        pr[v] = min(0.99, max(0.01, pr[v] * mult))
    if overrides:
        pr.update(overrides)
    return pr


def order(d, keys):
    return [x[0] for x in sorted(((k, d[k]) for k in keys), key=lambda t: -t[1])]


def main():
    base = all_marginals()
    print("node             base    -10%    +10%    -20%    +20%")
    cols = {}
    for label, mult in SCENARIOS:
        cols[label] = all_marginals(perturbed(mult))
    for n in IMPACT_IDS:
        row = f"{n:<14}{base[n]:>7.3f}"
        for label, _ in SCENARIOS:
            row += f"{cols[label][n]:>8.3f}"
        print(row)

    base_order = order(base, IMPACT_IDS)
    print("\nimpact ranking base:", base_order)
    for label, _ in SCENARIOS:
        o = order(cols[label], IMPACT_IDS)
        print(f"  {label}: {o}  {'PRESERVED' if o == base_order else 'CHANGED'}")

    print("\nwhat-if scenarios (absolute posterior reduction):")
    for label, mult in [("base", 1.0)] + SCENARIOS:
        m = all_marginals(perturbed(mult))
        s1 = all_marginals(perturbed(mult, {"V-T04": 0.05}))
        s2 = all_marginals(perturbed(mult, {"V-T01": 0.05}))
        print(f"  {label}: S1(V-T04->0.05) dC-NRF={m['C-NRF']-s1['C-NRF']:.3f}"
              f" dC-NF={m['C-NF']-s1['C-NF']:.3f} | "
              f"S2(V-T01->0.05) dC-UE={m['C-UE']-s2['C-UE']:.3f}"
              f" dI-PRIVACY={m['I-PRIVACY']-s2['I-PRIVACY']:.3f}")

    print("\nmitigation leverage (sum of impact reductions, threat prior -> 0.05):")
    for label, mult in [("base", 1.0)] + SCENARIOS:
        m = all_marginals(perturbed(mult), IMPACT_IDS)
        lev = {}
        for t in VULN_IDS:
            mm = all_marginals(perturbed(mult, {t: 0.05}), IMPACT_IDS)
            lev[t] = sum(m[i] - mm[i] for i in IMPACT_IDS)
        top5 = sorted(lev.items(), key=lambda kv: -kv[1])[:5]
        print(f"  {label}: {[f'{k}={v:.3f}' for k, v in top5]}")


if __name__ == "__main__":
    main()
