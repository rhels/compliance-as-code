# CLAUDE.md — compliance-as-code

## Purpose

This repo is the **source of truth** for supply chain security policies on the RHELS platform.
The image registry allowlist here drives the Kyverno ClusterPolicy in `rhels/platform-gitops`.

**Owner:** ShieldBot (InfoSec Compliance Lead)

## Key Concepts

- **Allowlist as data**: `policies/image-registry/allowlist.yaml` is structured data, not a Kubernetes resource
- **Sync to Kyverno**: `scripts/sync-allowlist-to-kyverno.sh` generates the Kyverno ClusterPolicy YAML and opens a PR on `platform-gitops`
- **Evaluation pipeline**: GitHub Actions workflow evaluates image trustworthiness when registry request issues are opened
- **Scoring threshold**: Auto-approve >= 80 points. Unknown vendors max 70 points (always need human review)

## File Layout

```
policies/image-registry/allowlist.yaml   # Source of truth for approved registries
scripts/evaluate-registry-request.sh     # Image trust scoring (Trivy + Skopeo + cosign)
scripts/generate-registry-pr.sh          # Auto PR generation
scripts/sync-allowlist-to-kyverno.sh     # Allowlist -> Kyverno policy generator
.github/workflows/evaluate-registry-request.yml   # Triggered on issue open
.github/workflows/approve-registry-request.yml     # Manual /approve-registry
```

## Rules

1. **Every allowlist change must have justification** — either via issue template or PR description
2. **Broad patterns (entire registries) require Konda approval** — vendor-scoped patterns can be auto-approved
3. **No secrets in this repo** — no tokens, passwords, or API keys
4. **All scripts must be idempotent** — safe to run repeatedly
5. **Allowlist is the input; Kyverno policy is the output** — never edit the Kyverno policy directly in platform-gitops for allowlist changes

## Trusted Vendors (for scoring)

These vendor namespaces score 30 points (known-trusted) in the evaluation:

```
redhat, rhdh-community, fedora, openshift     # Red Hat ecosystem
hashicorp                                       # HashiCorp
bitnami, bitnamilegacy                         # Bitnami
kyverno                                         # CNCF / Kyverno
aquasecurity                                    # Trivy / Aqua
grafana                                         # Grafana Labs
prometheus                                      # CNCF / Prometheus
jetstack                                        # cert-manager
argoproj                                        # Argo Project
```

## Git Conventions

- Commit types: `feat`, `fix`, `docs`, `chore`, `ci`
- Branches: `feature/<description>`, `fix/<description>`
- Every PR must reference an issue or provide justification in the description
