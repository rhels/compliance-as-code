# compliance-as-code

Supply chain security policies, image registry allowlists, and compliance automation for the RHELS platform.

**Owner:** ShieldBot (InfoSec Compliance Lead)

## What This Repo Contains

| Directory | Purpose |
|-----------|---------|
| `policies/image-registry/` | Image registry allowlist (source of truth for Kyverno policy) |
| `scripts/` | Evaluation engine, PR generation, allowlist-to-Kyverno sync |
| `docs/` | Process runbooks and governance documentation |
| `.github/workflows/` | Automated evaluation and approval pipelines |
| `.github/ISSUE_TEMPLATE/` | Structured request forms |

## How It Works

```
Developer/Bot opens Issue          ShieldBot evaluates           PR auto-generated
(image-registry-request)    --->   (Trivy + Skopeo + scoring)   (if score >= 80)
                                          |
                                   Score < 80?
                                          |
                                   Label: needs-human-review
                                   Konda approves via /approve-registry
```

## Requesting a New Image Registry

1. Go to [Issues > New Issue](../../issues/new/choose)
2. Select **Image Registry Request**
3. Fill in: image reference, vendor, justification, scope
4. The evaluation pipeline runs automatically
5. If auto-approved (score >= 80): a PR is generated targeting both this repo's allowlist and `rhels/platform-gitops` Kyverno policy
6. If human review needed (score 50-79): Konda reviews and comments `/approve-registry`

## Current Approved Registries

See [`policies/image-registry/allowlist.yaml`](policies/image-registry/allowlist.yaml) for the full list.

| Registry Pattern | Vendor | Type |
|-----------------|--------|------|
| `ghcr.io/rhels/*` | RHELS (org) | Organization |
| `ghcr.io/openclaw/*` | OpenClaw (org) | Organization |
| `registry.access.redhat.com/*` | Red Hat | Vendor |
| `registry.redhat.io/*` | Red Hat | Vendor |
| `quay.io/rhdh-community/*` | Red Hat Developer Hub | Community |
| `quay.io/fedora/*` | Fedora Project | Community |
| `quay.io/openshift/*` | OpenShift | Vendor |
| `docker.io/bitnami/*` | Bitnami | Vendor |
| `docker.io/bitnamilegacy/*` | Bitnami (legacy) | Vendor |
| `docker.io/hashicorp/*` | HashiCorp | Vendor |
| `hashicorp/*` | HashiCorp (alt) | Vendor |

## Scoring Model

Images are evaluated on a 0-100 scale. Auto-approve threshold: **80 points**.

| Criterion | Max Points | How |
|-----------|-----------|-----|
| Known trusted vendor | 30 | Namespace in pre-approved vendor list |
| Recent updates (<=90 days) | 15 | `skopeo inspect` timestamp |
| Community adoption | 15 | Registry API (pulls, stars) |
| No CRITICAL CVEs | 20 | `trivy image --severity CRITICAL` |
| No HIGH CVEs | 10 | `trivy image --severity HIGH` |
| Image signed (cosign) | 10 | `cosign verify` |

**Key guardrail:** Unknown vendors max out at 70 points and always require human review.

## Related Repos

| Repo | Relationship |
|------|-------------|
| `rhels/platform-gitops` | Consumer: Kyverno ClusterPolicy generated from this allowlist |
| `rhels/team` | ShieldBot persona definition |

## License

Internal use only. RHELS platform engineering.
