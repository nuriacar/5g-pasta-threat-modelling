#!/usr/bin/env python3
"""Regenerates the machine-readable data files of this artifact from the
model definitions in simulation.py and the OWASP scoring of the paper:

  attack_graph.json     35 nodes + 53 edges + parameters + ATT&CK mappings
  edge_list.csv         53 edges (source, target, logic, label)
  probability_matrix.csv  priors for all 35 nodes (+ Eq. 3 parameters)
  cnf_cpt.csv           full 64-entry CPT of C-NF (six parents)
  owasp_scoring.csv     15 threats x 16 OWASP sub-factors + aggregates
"""

import csv
import itertools
import json

from simulation import (THREATS, INITIAL, COMPROMISE, IMPACT, EDGES, NODES,
                        VULN_IDS, PARENTS, base_priors, eq3_prior,
                        noisy_or, LAM, W, EPS, L_MIN, L_MAX)

# Complete OWASP sub-factor scores (paper, Table `tab:subfactors`).
# Columns: skill, motive, opportunity, size | TAF | discovery, exploit,
# awareness, detection | VF | likelihood | conf, integ, avail, acct | TI |
# fin, rep, comp, priv | BI | impact
OWASP = {
    "V-T01": (7, 6, 7, 7, 6.8, 7, 8, 7, 6, 7.0, 6.9, 4, 5, 7, 5, 5.2, 7, 8, 7, 8, 7.5, 6.4),
    "V-T02": (7, 7, 7, 7, 7.0, 8, 8, 7, 7, 7.5, 7.2, 5, 5, 5, 4, 4.8, 7, 8, 6, 8, 7.2, 6.0),
    "V-T03": (5, 5, 6, 6, 5.5, 5, 5, 5, 5, 5.0, 5.2, 4, 5, 5, 4, 4.5, 5, 5, 4, 5, 4.8, 4.6),
    "V-T04": (6, 5, 5, 6, 5.5, 5, 5, 4, 5, 4.8, 5.1, 8, 7, 7, 6, 7.0, 8, 8, 7, 9, 8.0, 7.5),
    "V-T05": (5, 5, 5, 4, 4.8, 7, 7, 5, 6, 6.2, 5.5, 7, 6, 7, 5, 6.2, 7, 7, 6, 7, 6.8, 6.5),
    "V-T06": (6, 6, 7, 6, 6.2, 7, 7, 6, 6, 6.5, 6.4, 4, 3, 5, 4, 4.0, 4, 5, 4, 4, 4.2, 4.1),
    "V-T07": (6, 5, 6, 6, 5.8, 4, 4, 5, 4, 4.2, 5.0, 8, 8, 7, 7, 7.5, 8, 7, 7, 7, 7.2, 7.4),
    "V-T08": (6, 6, 6, 6, 6.0, 5, 5, 6, 5, 5.2, 5.6, 5, 5, 5, 5, 5.0, 5, 5, 5, 5, 5.0, 5.0),
    "V-T09": (6, 5, 7, 6, 6.0, 6, 5, 6, 5, 5.5, 5.8, 5, 5, 4, 5, 4.8, 7, 7, 6, 8, 7.0, 5.9),
    "V-T10": (5, 5, 6, 5, 5.2, 5, 5, 4, 5, 4.8, 5.0, 3, 4, 4, 3, 3.5, 4, 4, 4, 4, 4.0, 3.8),
    "V-T11": (5, 5, 6, 6, 5.5, 4, 4, 5, 5, 4.5, 5.0, 4, 5, 4, 4, 4.2, 5, 5, 4, 5, 4.8, 4.5),
    "V-T12": (5, 5, 5, 6, 5.2, 4, 4, 3, 5, 4.0, 4.6, 8, 8, 7, 7, 7.5, 9, 9, 8, 9, 8.8, 8.1),
    "V-T13": (6, 5, 6, 5, 5.5, 5, 5, 4, 5, 4.8, 5.1, 3, 4, 4, 4, 3.8, 5, 5, 4, 6, 5.0, 4.4),
    "V-T14": (6, 5, 5, 6, 5.5, 4, 4, 4, 4, 4.0, 4.8, 5, 5, 4, 6, 5.0, 8, 8, 7, 9, 8.0, 6.5),
    "V-T15": (6, 5, 7, 6, 6.0, 6, 5, 5, 6, 5.5, 5.8, 5, 5, 5, 5, 5.0, 5, 5, 4, 5, 4.8, 4.9),
}

SUBFACTORS = ["skill_level", "motive", "opportunity", "size", "TAF",
              "ease_of_discovery", "ease_of_exploit", "awareness",
              "intrusion_detection", "VF", "likelihood",
              "loss_confidentiality", "loss_integrity", "loss_availability",
              "loss_accountability", "TI", "financial_damage",
              "reputation_damage", "non_compliance", "privacy_violation",
              "BI", "impact"]


def main():
    priors = base_priors()

    # ---- attack_graph.json -------------------------------------------------
    nodes = []
    for nid, name in INITIAL:
        nodes.append({"id": nid, "name": name, "layer": 1, "type": "initial",
                      "prior": priors[nid], "parents": []})
    for tid, name, _, lik, comp, mode, attck in THREATS:
        nodes.append({"id": tid, "name": name, "layer": 2, "type": "vulnerability",
                      "owasp_likelihood": lik, "component": comp, "mode": mode,
                      "attack_mapping": attck, "prior": priors[tid],
                      "parents": PARENTS[tid]})
    for cid, name in COMPROMISE:
        nodes.append({"id": cid, "name": name, "layer": 3, "type": "compromise",
                      "prior": priors[cid], "parents": PARENTS[cid]})
    for iid, name in IMPACT:
        nodes.append({"id": iid, "name": name, "layer": 4, "type": "impact",
                      "prior": priors[iid], "parents": PARENTS[iid]})
    graph = {
        "description": "35-node Bayesian Attack Graph for 5G PASTA threat "
                       "model (NSA/SA). See the accompanying paper.",
        "parameters": {"leak_lambda": LAM, "gate_weight": W,
                       "eq3_epsilon": EPS, "eq3_L_min": L_MIN,
                       "eq3_L_max": L_MAX,
                       "cpt": "Noisy-OR, child-centric p = node's own prior"},
        "nodes": nodes,
        "edges": [{"from": p, "to": c, "logic": "OR", "label": lbl}
                  for p, c, lbl in EDGES],
    }
    with open("attack_graph.json", "w") as fh:
        json.dump(graph, fh, indent=1)

    # ---- edge_list.csv -----------------------------------------------------
    with open("edge_list.csv", "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["index", "source", "target", "logic", "label"])
        for i, (p, c, lbl) in enumerate(EDGES, 1):
            wr.writerow([i, p, c, "OR", lbl])

    # ---- probability_matrix.csv --------------------------------------------
    with open("probability_matrix.csv", "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["node", "type", "prior", "source"])
        for n in nodes:
            src = ("Eq.3 from OWASP Likelihood" if n["type"] == "vulnerability"
                   else "uninformative 0.5")
            wr.writerow([n["id"], n["type"], n["prior"], src])
        wr.writerow([])
        wr.writerow(["parameter", "value"])
        wr.writerow(["lambda", LAM])
        wr.writerow(["w", W])
        wr.writerow(["epsilon", EPS])
        wr.writerow(["L_min", L_MIN])
        wr.writerow(["L_max", L_MAX])

    # ---- cnf_cpt.csv -------------------------------------------------------
    parents = PARENTS["C-NF"]
    p_cnf = priors["C-NF"]
    with open("cnf_cpt.csv", "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(parents + ["C-NF", "P(C-NF=True)"])
        for config in itertools.product((0, 1), repeat=len(parents)):
            pt = noisy_or(p_cnf, config)
            wr.writerow(list(config) + [1, f"{pt:.4f}"])
            wr.writerow(list(config) + [0, f"{1 - pt:.4f}"])

    # ---- owasp_scoring.csv ---------------------------------------------------
    with open("owasp_scoring.csv", "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["threat_id"] + SUBFACTORS)
        for tid in VULN_IDS:
            wr.writerow([tid] + list(OWASP[tid]))

    # ---- mitigation_scoring.csv ----------------------------------------------
    # Pre-mitigation Likelihood/Impact = OWASP aggregates (owasp_scoring.csv).
    # Post-mitigation values follow the paper rule: re-rate only the
    # sub-factors the cited 3GPP control directly addresses; all other
    # sub-factors are unchanged (paper Table `tab:mitigation`).
    MITIGATION = {
        "V-T01": ("TS 33.501 §5.1.1", 6.3, 5.8, "anti-downgrade; likelihood-only effect"),
        "V-T02": ("N/A (4G EPC limitation)", 7.2, 6.0, "architectural limitation; unchanged"),
        "V-T03": ("TS 33.501 §6.1", 5.2, 4.6, "authentication likelihood only; impact unchanged"),
        "V-T04": ("TS 33.501 §13.1, §13.4.1.3", 4.5, 5.5, "mutual TLS, NRF authentication"),
        "V-T05": ("TS 33.501 §13.4.1", 4.8, 5.2, "OAuth 2.0 based authorisation"),
        "V-T06": ("TS 33.501 §6.4.7", 5.2, 3.5, "SMS over NAS security"),
        "V-T07": ("TS 33.501 Annex T", 4.5, 5.8, "edge computing security"),
        "V-T08": ("TS 33.501 Annex T", 4.8, 4.2, "edge computing security"),
        "V-T09": ("TS 33.501 Annex T, §9", 5.0, 4.5, "edge transport security"),
        "V-T10": ("TS 33.501 §16.2", 4.5, 3.2, "slice access authorisation"),
        "V-T11": ("TS 33.501 §16", 4.5, 3.8, "network slice security"),
        "V-T12": ("TS 33.501 §16.3", 4.2, 7.5, "slice-specific authentication"),
        "V-T13": ("TS 33.501 §6.1", 4.5, 3.8, "registration integrity"),
        "V-T14": ("TS 33.501 §6.1", 4.2, 5.2, "SUCI encryption"),
        "V-T15": ("TS 33.501 §6.1", 5.0, 4.2, "SQN management"),
    }
    with open("mitigation_scoring.csv", "w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["threat_id", "pre_likelihood", "pre_impact",
                     "post_likelihood", "post_impact",
                     "control_reference", "rationale"])
        for tid in VULN_IDS:
            ref, pl, pi, why = MITIGATION[tid]
            wr.writerow([tid, f"{OWASP[tid][10]:.1f}", f"{OWASP[tid][21]:.1f}",
                         f"{pl:.1f}", f"{pi:.1f}", ref, why])

    print("wrote: attack_graph.json, edge_list.csv, probability_matrix.csv,"
          " cnf_cpt.csv, owasp_scoring.csv, mitigation_scoring.csv")
    # sanity: priors derived from the OWASP table must match Eq. 3
    for tid, _, _, lik, *_ in THREATS:
        assert abs(eq3_prior(lik) - priors[tid]) < 1e-12
        assert abs(OWASP[tid][10] - lik) < 1e-9, (tid, OWASP[tid][10], lik)
    # sanity: post-mitigation risk never exceeds pre-mitigation risk
    for tid in VULN_IDS:
        _, pl, pi, _ = MITIGATION[tid]
        assert pl <= OWASP[tid][10] + 1e-9 and pi <= OWASP[tid][21] + 1e-9, tid
    print("sanity: OWASP likelihoods, Eq. 3 priors, and post<=pre consistent")


if __name__ == "__main__":
    main()
