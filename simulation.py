#!/usr/bin/env python3
"""Exact inference engine for the 35-node 5G Bayesian Attack Graph.

Reproduces every posterior in the paper (Table `tab:posteriors`).
Model: Noisy-OR CPTs (Eq. 4) with leak lambda=0.05, gate weight w=0.85,
child-centric p (the node's own prior); vulnerability priors derived from
OWASP Likelihood scores via min-max normalisation with epsilon smoothing
(Eq. 3, L_min=4.6, L_max=7.2, eps=0.01); all other priors 0.5.

Usage:
    python3 simulation.py             # print all 35 posteriors
    python3 simulation.py --validate  # compare against published values
"""

import itertools

LAM = 0.05
W = 0.85
EPS = 0.01
L_MIN, L_MAX = 4.6, 7.2

# (id, name, layer, owasp_likelihood or None, component, mode, attack)
THREATS = [
    ("V-T01", "Downgrade Attack", "vuln", 6.9, "Auth", "NSA", "T1562.001"),
    ("V-T02", "IMSI Catcher", "vuln", 7.2, "Auth", "NSA", "T1589*"),
    ("V-T03", "EPS-AKA Mismatch", "vuln", 5.2, "Auth", "NSA", "T1557"),
    ("V-T04", "Unauthorised NF Registration", "vuln", 5.1, "Core/SBA", "SA", "T1553.006"),
    ("V-T05", "API Abuse (HTTP/2 SBI)", "vuln", 5.5, "Core/SBA", "SA", "T1190"),
    ("V-T06", "Signalling Storm", "vuln", 6.4, "Core/SBA", "SA", "T1498"),
    ("V-T07", "Rogue Edge Node", "vuln", 5.0, "Edge/MEC", "SA", "T1195.002"),
    ("V-T08", "Third-party App Compromise", "vuln", 5.6, "Edge/MEC", "SA", "T1195.001"),
    ("V-T09", "Edge Data Exposure", "vuln", 5.8, "Edge/MEC", "SA", "T1530"),
    ("V-T10", "Cross-slice DoS", "vuln", 5.0, "Slicing", "SA", "T1498"),
    ("V-T11", "Resource Hijacking", "vuln", 5.0, "Slicing", "SA", "T1496"),
    ("V-T12", "Slice Policy Bypass", "vuln", 4.6, "Slicing", "SA", "T1548"),
    ("V-T13", "SUCI Replay", "vuln", 5.1, "Auth", "SA", "T1589*"),
    ("V-T14", "SUPI De-anonymisation", "vuln", 4.8, "Auth", "NSA-to-SA", "T1589*"),
    ("V-T15", "Authentication Sync Failure", "vuln", 5.8, "Auth", "SA", "T1557"),
]

INITIAL = [
    ("IS-NSA", "NSA Deployment"), ("IS-SA", "SA Deployment"),
    ("IS-INSIDER", "Insider Access"), ("IS-PHYSICAL", "Physical RAN Access"),
]
COMPROMISE = [
    ("C-UE", "UE Compromised"), ("C-NF", "NF Compromised"),
    ("C-SLICE", "Slice Breached"), ("C-SIGNAL", "Signalling Active"),
    ("C-SUPPLY", "Supply Chain Compromised"), ("C-AMF", "AMF Takeover"),
    ("C-SMF", "SMF Hijack"), ("C-UPF", "UPF Intercept"),
    ("C-AUSF", "Auth Bypass"), ("C-UDM", "Subscriber Data Leak"),
    ("C-NRF", "Registry Poison"), ("C-RAN", "RAN Manipulation"),
]
IMPACT = [
    ("I-PRIVACY", "Privacy Violation"), ("I-SERVICE", "Service Disruption"),
    ("I-DATA", "Data Exfiltration"), ("I-INTEGRITY", "Integrity Loss"),
]

# 53 directed enablement edges (Appendix C of the paper, in table order)
EDGES = [
    ("IS-NSA", "V-T01", "NSA exposes IMSI"),
    ("IS-NSA", "V-T02", "NSA enables fake BS"),
    ("IS-NSA", "V-T03", "NSA enables downgrade"),
    ("IS-NSA", "V-T14", "Cross-mode identity link"),
    ("IS-PHYSICAL", "V-T02", "Physical BS deployment"),
    ("IS-PHYSICAL", "V-T11", "Physical RAN jamming"),
    ("IS-PHYSICAL", "V-T13", "Fronthaul intercept"),
    ("V-T01", "C-UE", "IMSI captured"),
    ("V-T02", "C-SIGNAL", "Fake BS active"),
    ("V-T03", "C-SIGNAL", "Downgrade forced"),
    ("V-T11", "C-RAN", "RAN flooded"),
    ("V-T14", "C-UE", "Cross-mode identity"),
    ("C-SIGNAL", "C-UE", "Signalling reveals ID"),
    ("IS-SA", "V-T04", "SA exposes NRF"),
    ("IS-SA", "V-T05", "SA exposes SBI"),
    ("IS-SA", "V-T06", "SA uses slicing"),
    ("IS-SA", "V-T07", "SA deploys MEC"),
    ("IS-SA", "V-T08", "SA uses AUSF"),
    ("IS-SA", "V-T09", "Data stored in UDM"),
    ("IS-SA", "V-T10", "SA routes through UPF"),
    ("IS-SA", "V-T15", "Auth chain vulnerable"),
    ("V-T04", "C-NRF", "NRF unauthorised registration"),
    ("V-T05", "C-NF", "SBI traffic intercepted"),
    ("V-T05", "C-SMF", "SBI session hijack"),
    ("V-T06", "C-SLICE", "Slice isolation broken"),
    ("V-T07", "C-AMF", "AMF registration spoofed"),
    ("V-T08", "C-AUSF", "Auth bypassed"),
    ("V-T09", "C-UDM", "Subscriber data exposed"),
    ("V-T10", "C-UPF", "User plane intercepted"),
    ("V-T15", "C-AUSF", "Auth failure storm"),
    ("C-NRF", "C-NF", "Poisoned registry"),
    ("C-AMF", "C-NF", "AMF takeover"),
    ("C-SMF", "C-NF", "SMF session hijack"),
    ("C-UPF", "C-NF", "UPF compromise"),
    ("IS-INSIDER", "V-T12", "Insider supply chain"),
    ("IS-INSIDER", "V-T05", "Insider exploits SBI"),
    ("V-T12", "C-SUPPLY", "Supply chain infected"),
    ("V-T13", "C-RAN", "Fronthaul intercepted"),
    ("C-SUPPLY", "C-NF", "Compromised core component"),
    ("C-SUPPLY", "C-RAN", "Compromised RAN component"),
    ("C-UE", "I-PRIVACY", "Identity exposed"),
    ("C-AUSF", "I-PRIVACY", "Auth bypass exposes IDs"),
    ("C-UDM", "I-PRIVACY", "Subscriber data leak"),
    ("C-SIGNAL", "I-SERVICE", "Signalling disruption"),
    ("C-RAN", "I-SERVICE", "RAN manipulation"),
    ("C-NF", "I-SERVICE", "NF compromise"),
    ("C-SLICE", "I-SERVICE", "Slice breach"),
    ("C-NF", "I-DATA", "NF data exfiltration"),
    ("C-UDM", "I-DATA", "Subscriber data exfiltration"),
    ("C-UPF", "I-DATA", "User plane intercepted"),
    ("C-SLICE", "I-DATA", "Cross-tenant data access"),
    ("C-NF", "I-INTEGRITY", "Config tampering"),
    ("C-SUPPLY", "I-INTEGRITY", "Persistent backdoor"),
]

NODES = ([n[0] for n in INITIAL] + [t[0] for t in THREATS]
         + [c[0] for c in COMPROMISE] + [i[0] for i in IMPACT])
VULN_IDS = [t[0] for t in THREATS]
PARENTS = {n: [] for n in NODES}
for p, c, _ in EDGES:
    PARENTS[c].append(p)


def eq3_prior(likelihood):
    """OWASP Likelihood -> prior (Eq. 3)."""
    return EPS + (1 - 2 * EPS) * (likelihood - L_MIN) / (L_MAX - L_MIN)


def base_priors():
    pr = {n: 0.5 for n in NODES}
    for tid, _, _, lik, _, _, _ in THREATS:
        pr[tid] = eq3_prior(lik)
    return pr


def noisy_or(p_child, active_mask):
    q = 1.0
    for a in active_mask:
        if a:
            q *= (1.0 - p_child * W)
    return 1.0 - (1.0 - LAM) * q


def build_factors(priors):
    factors = []
    for n in NODES:
        p, pa = priors[n], PARENTS[n]
        if not pa:
            factors.append({"vars": (n,), "table": {(0,): 1 - p, (1,): p}})
        else:
            table = {}
            for config in itertools.product((0, 1), repeat=len(pa)):
                pt = noisy_or(p, config)
                for v in (0, 1):
                    table[(v,) + config] = pt if v else 1 - pt
            factors.append({"vars": (n,) + tuple(pa), "table": table})
    return factors


def _multiply(f1, f2):
    vs = list(f1["vars"]) + [v for v in f2["vars"] if v not in f1["vars"]]
    out = {}
    for asg in itertools.product((0, 1), repeat=len(vs)):
        env = dict(zip(vs, asg))
        out[asg] = (f1["table"][tuple(env[v] for v in f1["vars"])]
                    * f2["table"][tuple(env[v] for v in f2["vars"])])
    return {"vars": tuple(vs), "table": out}


def _sum_out(f, var):
    i = f["vars"].index(var)
    out = {}
    for k, v in f["table"].items():
        rk = k[:i] + k[i + 1:]
        out[rk] = out.get(rk, 0.0) + v
    return {"vars": tuple(x for x in f["vars"] if x != var), "table": out}


def marginal(priors, target):
    """Exact P(target=T) via min-degree variable elimination."""
    factors = build_factors(priors)
    elim = [n for n in NODES if n != target]
    adj = {n: set() for n in NODES}
    for f in factors:
        for a, b in itertools.permutations(f["vars"], 2):
            adj[a].add(b)
    while elim:
        n = min(elim, key=lambda x: len(adj[x] & set(elim)))
        elim.remove(n)
        related = [f for f in factors if n in f["vars"]]
        if not related:
            continue
        merged = related[0]
        for f in related[1:]:
            merged = _multiply(merged, f)
        factors = [f for f in factors if n not in f["vars"]]
        nf = _sum_out(merged, n)
        if nf["vars"]:
            factors.append(nf)
            for a, b in itertools.permutations(nf["vars"], 2):
                adj[a].add(b)
    joint = factors[0]
    for f in factors[1:]:
        joint = _multiply(joint, f)
    z = sum(joint["table"].values())
    return joint["table"][(1,)] / z


def all_marginals(priors=None, nodes=None):
    priors = priors or base_priors()
    nodes = nodes or NODES
    return {n: marginal(priors, n) for n in nodes}


PAPER_POSTERIORS = {
    "IS-NSA": 0.50, "IS-SA": 0.50, "IS-INSIDER": 0.50, "IS-PHYSICAL": 0.50,
    "V-T01": 0.40, "V-T02": 0.68, "V-T03": 0.15, "V-T04": 0.13,
    "V-T05": 0.31, "V-T06": 0.33, "V-T07": 0.12, "V-T08": 0.21,
    "V-T09": 0.24, "V-T10": 0.12, "V-T11": 0.12, "V-T12": 0.05,
    "V-T13": 0.13, "V-T14": 0.08, "V-T15": 0.24,
    "C-UE": 0.35, "C-NF": 0.33, "C-SLICE": 0.18, "C-SIGNAL": 0.36,
    "C-SUPPLY": 0.07, "C-AMF": 0.10, "C-SMF": 0.18, "C-UPF": 0.10,
    "C-AUSF": 0.22, "C-UDM": 0.15, "C-NRF": 0.10, "C-RAN": 0.17,
    "I-PRIVACY": 0.31, "I-SERVICE": 0.41, "I-DATA": 0.32, "I-INTEGRITY": 0.21,
}


def main():
    import sys
    m = all_marginals()
    if "--validate" in sys.argv:
        worst = max(abs(m[n] - PAPER_POSTERIORS[n]) for n in NODES)
        ok = worst <= 0.0051
        for n in NODES:
            d = m[n] - PAPER_POSTERIORS[n]
            flag = "" if abs(d) <= 0.0051 else "  <-- MISMATCH"
            print(f"{n:<14} computed={m[n]:.4f}  published={PAPER_POSTERIORS[n]:.2f}{flag}")
        print(f"worst |delta| = {worst:.4f} -> {'OK' if ok else 'FAILED'}")
        sys.exit(0 if ok else 1)
    for n in NODES:
        print(f"{n:<14} {m[n]:.4f}")


if __name__ == "__main__":
    main()
