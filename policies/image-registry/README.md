# Image Registry Policy

## Rationale

This policy reduces software supply chain risk by restricting workload container images
to explicitly approved registries and vendor namespaces. Broad wildcards like `quay.io/*`
or `docker.io/*` are not permitted — each vendor must be individually approved.

## How This Works

1. **This file** (`allowlist.yaml`) is the source of truth
2. The `sync-allowlist-to-kyverno.sh` script reads this file and generates a Kyverno ClusterPolicy
3. The generated policy is committed to `rhels/platform-gitops` via PR
4. ArgoCD syncs the policy to the OKD cluster
5. Kyverno enforces the policy at pod admission time

## Adding a New Registry

See the [CONTRIBUTING guide](../../CONTRIBUTING.md) or open an
[Image Registry Request](../../../issues/new?template=image-registry-request.yml).

## Current Policy Scope

- **Enforcement mode**: `Enforce` (blocks non-compliant pods at admission)
- **Applies to**: All Pods (containers, initContainers, ephemeralContainers)
- **Excluded namespaces**: kube-system, kyverno, openshift-*, open-cluster-management*, argocd, openshift-gitops
