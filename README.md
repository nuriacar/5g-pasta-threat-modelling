# 5G PASTA Bayesian Attack Graph — Analysis Artifact

Machine-readable data and exact-inference code for the 35-node Bayesian
Attack Graph (BAG) of the paper "PASTA-Based 5G Network Threat Modelling:
ATT&CK-Mapped Kill Chains for NSA and SA Deployments".

## Contents

| File | Description |
|---|---|
| `attack_graph.json` | 35 nodes (4 layers: initial state, vulnerability, compromise, impact) + 53 directed enablement edges + parameters + ATT&CK mappings |
| `edge_list.csv` | The 53 edges as (source, target, logic, label) rows |
| `probability_matrix.csv` | Prior for every node with its source (Eq. 3 from OWASP Likelihood, or uninformative 0.5) + Noisy-OR parameters |
| `cnf_cpt.csv` | Full 64-entry conditional probability table of C-NF (six parents) |
| `owasp_scoring.csv` | 15 threats x 16 OWASP sub-factor scores + aggregates (TAF, VF, TI, BI, Likelihood, Impact) |
| `mitigation_scoring.csv` | 15 threats x pre-/post-mitigation Likelihood/Impact + 3GPP control reference and rationale (paper Table `tab:mitigation`) |
| `simulation.py` | Self-contained exact inference engine (min-degree variable elimination) |
| `sensitivity.py` | Prior-perturbation analysis: ±10% and ±20% on all 15 vulnerability priors |
| `mitigation_leverage.py` | Mitigation-leverage sweep: each vulnerability prior in turn reduced to 0.05; ranks all 15 threats by aggregate impact-node reduction (reproduces the invariant top-5 set) |
| `root_prior_sensitivity.py` | Impact posteriors under IS-INSIDER/IS-PHYSICAL varied over {0.2, 0.5, 0.8} (nine configurations) |
| `owasp_bootstrap.py` | Flat-score classification stress test: all 240 sub-factors independently resampled by ±1 (fixed seed, 100,000 replicates by default) |
| `build_data_files.py` | Regenerates all data files above from the model definitions |

## Model

- Priors: OWASP Likelihood scores mapped through min-max normalisation with
  epsilon smoothing, `P = eps + (1 - 2*eps) * (L - L_min) / (L_max - L_min)`
  with `L_min = 4.6`, `L_max = 7.2`, `eps = 0.01` (Eq. 3 of the paper);
  all non-vulnerability priors are uninformative 0.5.
- CPTs: Noisy-OR canonical parameterisation (Eq. 4),
  `P(X=T | parents) = 1 - (1 - lambda) * prod(1 - p_X * w)` with
  leak `lambda = 0.05`, gate weight `w = 0.85`, and child-centric
  `p_X` equal to the child node's own prior.
- Inference: exact, per-node variable elimination with min-degree ordering
  (35 binary variables; induced treewidth <= 6).

## Requirements

Python 3.8+ with the standard library only. No third-party dependencies.

## Usage

```bash
python3 simulation.py --validate   # reproduce all 35 published posteriors
python3 simulation.py              # print all 35 posteriors
python3 sensitivity.py             # prior-perturbation robustness analysis
python3 build_data_files.py        # regenerate the data files
```

`simulation.py --validate` must terminate with `worst |delta| <= 0.0051`
against the paper's Table of posteriors (tolerance reflects the paper's
two-decimal display rounding).

## Sensitivity summary

Perturbing all 15 vulnerability priors simultaneously by ±10% and ±20%
(clamped to [0.01, 0.99]) preserves: the impact-node ranking
(I-SERVICE > I-DATA > I-PRIVACY > I-INTEGRITY), the structure of both
what-if mitigation scenarios, and the top-5 mitigation set
{V-T05, V-T02, V-T06, V-T09, V-T01}. Absolute posteriors shift by at most
0.029 under ±20%. The leading pair V-T05/V-T02 differs by ~4% at baseline
and swaps order under the −10% scenario.

The mitigation-leverage sweep (`mitigation_leverage.py`, prior in turn set
to 0.05) reproduces the invariant top-5 set above from first principles;
the V-T01 and V-T04 rows reproduce the two published what-if tables.
V-T12's baseline prior (0.01) lies below the sweep value, so its row
quantifies a small increase (−0.004 aggregate) rather than a reduction.
The root-prior sweep (`root_prior_sensitivity.py`) keeps I-SERVICE
highest and I-INTEGRITY lowest in all nine configurations; the middle
pair (I-PRIVACY, I-DATA) swaps in three of nine, tracking whether
physical-RAN or insider paths dominate. The flat-score bootstrap
(`owasp_bootstrap.py`) keeps at least one 4G legacy threat CRITICAL in
94.6% of replicates and SA CRITICAL-free in 74.1% (joint: 70.1%);
independent one-step disagreement is markedly gentler than the uniform
+1 shift, which drives five SA threats to CRITICAL with certainty.

## License

MIT (see `LICENSE`). Threat descriptions and scoring reflect the
accompanying paper; the OWASP sub-factor scores are the authors' expert
judgement against the published OWASP Risk Rating rubric.
