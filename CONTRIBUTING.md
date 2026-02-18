# Contributing to compliance-as-code

## How to Request a New Image Registry

1. Open an [Image Registry Request](../../issues/new?template=image-registry-request.yml) issue
2. Fill in all required fields: image reference, vendor, justification
3. Wait for the automated evaluation (runs in ~2-5 minutes)
4. If auto-approved: a PR is generated automatically
5. If human review needed: wait for an authorized reviewer to approve

## How to Submit a Direct PR

If you prefer a PR over an issue:

1. Fork the repo or create a branch
2. Edit `policies/image-registry/allowlist.yaml` — add your entry following the existing format
3. Include in your PR description:
   - Full image reference
   - Vendor name
   - Justification (why this image, why no alternative from approved registries)
   - Which platform component uses it
4. The PR will be reviewed by ShieldBot or Konda

## Allowlist Entry Format

Each line in `allowlist.yaml` follows this format:

```
pattern: vendor-category | approved-by | date
```

Example:
```
quay.io/fedora/*: Fedora Project | ShieldBot | 2026-02-18
```

## Who Can Approve

- **Auto-approval**: The evaluation pipeline (score >= 80)
- **Manual approval**: Konda (human operator) via `/approve-registry` comment
- **Broad patterns** (entire registries like `quay.io/*`): Always require Konda

## Code Style

- Shell scripts: use `shellcheck` conventions, `set -euo pipefail`
- YAML: 2-space indent, no tabs
- Workflows: pin action versions to full SHA
