# Image Registry Governance Runbook

## Overview

This document describes the process for managing the container image registry allowlist
on the RHELS platform. All container images running on the OKD cluster must come from
an approved registry or vendor namespace. This policy is enforced by Kyverno at pod
admission time.

**Owner:** ShieldBot (InfoSec Compliance Lead)
**Consumer:** rhels/platform-gitops (Kyverno ClusterPolicy)

## Architecture

```
                    compliance-as-code (this repo)
                    ┌─────────────────────────────┐
                    │  allowlist.yaml              │
                    │  (source of truth)           │
                    └──────────┬──────────────────┘
                               │
                    sync-allowlist-to-kyverno.sh
                               │
                    ┌──────────▼──────────────────┐
                    │  platform-gitops             │
                    │  restrict-image-registries   │
                    │  .yaml (generated)           │
                    └──────────┬──────────────────┘
                               │
                         ArgoCD sync
                               │
                    ┌──────────▼──────────────────┐
                    │  OKD Cluster                 │
                    │  Kyverno ClusterPolicy       │
                    │  (Enforce mode)              │
                    └─────────────────────────────┘
```

## Request Process

### Via GitHub Issue (preferred)

1. Go to [New Issue > Image Registry Request](https://github.com/rhels/compliance-as-code/issues/new?template=image-registry-request.yml)
2. Fill in all required fields
3. Submit — the evaluation pipeline runs automatically (~2-5 minutes)
4. Check the issue for the ShieldBot evaluation report comment
5. If auto-approved (score >= 80): PR generated automatically
6. If needs human review (score 50-79): wait for `/approve-registry` from an authorized reviewer
7. If auto-rejected (score < 50): address the issues and resubmit

### Via Direct PR

1. Fork or branch from main
2. Edit `policies/image-registry/allowlist.yaml`
3. Add entry: `pattern: category | approved-by | date`
4. Submit PR with justification in description

## Scoring Model

Images are scored 0-100. Auto-approve threshold: **80 points**.

| Criterion | Max | How Evaluated | Tool |
|-----------|-----|---------------|------|
| Known trusted vendor | 30 | Namespace in pre-approved list | Built-in |
| Recent updates | 15 | Image published within 90 days | `skopeo inspect` |
| Community adoption | 15 | Pull count, star count, version count | Registry API |
| No CRITICAL CVEs | 20 | Zero CRITICAL vulnerabilities | `trivy image` |
| No HIGH CVEs | 10 | Zero HIGH vulnerabilities | `trivy image` |
| Image signed | 10 | Valid cosign/Sigstore signature | `cosign verify` |

### Key guardrail

Unknown vendors (not in the trusted list) max out at **70 points** — they can never
auto-approve and always require human review. This prevents supply chain attacks via
new, untrusted vendors.

### Trusted vendor list

```
redhat, rhdh-community, fedora, openshift    (Red Hat ecosystem)
hashicorp                                     (HashiCorp)
bitnami, bitnamilegacy                       (Bitnami)
kyverno, argoproj, prometheus, jetstack      (CNCF)
grafana, aquasecurity                        (Observability/Security)
```

## Roles and Responsibilities

| Role | Who | Responsibilities |
|------|-----|-----------------|
| ShieldBot | AI bot | Evaluates requests, generates PRs, maintains allowlist |
| Konda | Human operator | Approves broad patterns, reviews edge cases, final authority |
| KubeOps | Platform team | Owns Kyverno engine deployment, syncs policies via ArgoCD |
| Requesters | Anyone | Opens issues or PRs with justification |

## Emergency Process

If a deployment is blocked by the registry policy and cannot wait for the normal process:

1. **Identify the blocked image** from the Kyverno denial message
2. **Open an issue** with `[URGENT]` prefix
3. **Konda** can comment `/approve-registry` immediately for human review bypass
4. **After approval**: PR generated, merged, ArgoCD syncs (~5 minutes total)

Do NOT bypass Kyverno by adding namespace exclusions — this creates security gaps.

## Audit and Review

- **Quarterly review**: ShieldBot re-evaluates all allowlist entries (future: B-REG-007)
- **On CVE disclosure**: If a CRITICAL CVE is disclosed for an approved image vendor,
  ShieldBot opens an issue to review affected entries
- **Metrics tracked**: requests/month, auto-approve rate, time-to-approve, CVE findings

## Troubleshooting

### Pod blocked by policy

```bash
# Check Kyverno events
oc get events -n <namespace> --field-selector reason=PolicyViolation

# Check the denial message
oc describe pod <pod-name> -n <namespace> | grep -A5 "Warning"

# Verify the current policy allowlist
oc get clusterpolicy restrict-image-registries -o yaml | grep -A50 "value:"
```

### Evaluation script fails

```bash
# Run manually for debugging
./scripts/evaluate-registry-request.sh <image-ref>

# Check tool availability
which skopeo trivy cosign jq

# Test skopeo access
skopeo inspect docker://<image-ref>
```

### Sync script fails

```bash
# Dry-run to see generated policy
./scripts/sync-allowlist-to-kyverno.sh --dry-run

# Check allowlist format
cat policies/image-registry/allowlist.yaml
```
