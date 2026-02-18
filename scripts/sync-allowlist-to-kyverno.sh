#!/usr/bin/env bash
# sync-allowlist-to-kyverno.sh
# Reads the allowlist.yaml from compliance-as-code and generates the Kyverno
# ClusterPolicy YAML for platform-gitops.
#
# This is the bridge between the compliance repo (data) and the GitOps repo (policy).
#
# Usage:
#   ./scripts/sync-allowlist-to-kyverno.sh [--dry-run] [--pr]
#
# Options:
#   --dry-run   Print the generated policy to stdout without writing files
#   --pr        Clone platform-gitops, write the policy, and create a PR
#
# Requires: yq, git, gh (for --pr mode)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALLOWLIST_FILE="$REPO_ROOT/policies/image-registry/allowlist.yaml"
PLATFORM_GITOPS_REPO="rhels/platform-gitops"
POLICY_PATH="platform/kyverno-policies/policies/restrict-image-registries.yaml"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

DRY_RUN=false
CREATE_PR=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --pr) CREATE_PR=true ;;
  esac
done

# --- Extract patterns from allowlist ---
echo "[SYNC] Reading allowlist from $ALLOWLIST_FILE..."

# Extract lines that look like registry patterns (contain / and *)
# Skip comments and blank lines
PATTERNS=()
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "$line" ]] && continue
  [[ "$line" == "---" ]] && continue

  # Extract pattern (everything before the colon)
  pattern=$(echo "$line" | cut -d':' -f1 | xargs)
  if [[ -n "$pattern" ]] && [[ "$pattern" == *"/"* ]]; then
    PATTERNS+=("$pattern")
  fi
done < "$ALLOWLIST_FILE"

if [[ ${#PATTERNS[@]} -eq 0 ]]; then
  echo "ERROR: No patterns found in $ALLOWLIST_FILE" >&2
  exit 1
fi

echo "[SYNC] Found ${#PATTERNS[@]} registry patterns"

# --- Generate YAML list entries ---
generate_value_list() {
  for pattern in "${PATTERNS[@]}"; do
    echo "                      - \"$pattern\""
  done
}

VALUE_LIST=$(generate_value_list)

# --- Generate the ClusterPolicy ---
# Uses a single foreach with JMESPath flattening to cover all container types
# in one pass — avoids duplicating the allowlist 3x and is cleaner YAML.
# Note: validate.message cannot use {{ element.* }} (element is only in scope
# inside foreach). The deny block also does not support .message in Kyverno v1.
POLICY_YAML=$(cat <<POLICYEOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
  annotations:
    policies.kyverno.io/title: Restrict Image Registries
    policies.kyverno.io/category: Supply Chain Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Enforces approved container image registries for all workloads.
      Images must come from explicitly approved vendor paths.
      Allowlist managed in rhels/compliance-as-code.
      To request a new registry: https://github.com/rhels/compliance-as-code/issues/new?template=image-registry-request.yml
    compliance-as-code/synced-at: "$TIMESTAMP"
    compliance-as-code/pattern-count: "${#PATTERNS[@]}"
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-approved-registries
      match:
        any:
          - resources:
              kinds:
                - Pod
      exclude:
        any:
          - resources:
              namespaces:
                - kube-system
                - kyverno
                - openshift-*
                - open-cluster-management*
                - argocd
                - openshift-gitops
      validate:
        # NOTE: validate.message cannot use {{ element.* }} — element is only in scope
        # inside foreach. Use a static message here.
        message: >-
          One or more container images are not from an approved registry.
          Approved registries are vendor-scoped (not entire registries).
          To request a new registry: https://github.com/rhels/compliance-as-code/issues/new?template=image-registry-request.yml
        # Single foreach with JMESPath flattening covers containers, initContainers,
        # and ephemeralContainers in one pass — no allowlist duplication.
        # Allowlist source of truth: rhels/compliance-as-code/policies/image-registry/allowlist.yaml
        foreach:
          - list: "request.object.spec.[containers, initContainers, ephemeralContainers][] | []"
            deny:
              conditions:
                all:
                  - key: "{{ element.image }}"
                    operator: AnyNotIn
                    value:
$VALUE_LIST
POLICYEOF
)

# --- Output or write ---
if [[ "$DRY_RUN" == true ]]; then
  echo "[SYNC] Generated policy (dry-run):"
  echo "$POLICY_YAML"
  exit 0
fi

if [[ "$CREATE_PR" == true ]]; then
  echo "[SYNC] Cloning platform-gitops and creating PR..."

  WORK_DIR=$(mktemp -d)
  cd "$WORK_DIR"
  gh repo clone "$PLATFORM_GITOPS_REPO" platform-gitops
  cd platform-gitops

  BRANCH_NAME="feature/sync-registry-allowlist-$(date +%Y%m%d-%H%M%S)"
  git checkout -b "$BRANCH_NAME"

  echo "$POLICY_YAML" > "$POLICY_PATH"
  git add "$POLICY_PATH"
  git commit -m "feat(kyverno): sync image registry allowlist from compliance-as-code

Synced ${#PATTERNS[@]} registry patterns from rhels/compliance-as-code allowlist.
Generated by sync-allowlist-to-kyverno.sh at $TIMESTAMP.

Co-Authored-By: ShieldBot <noreply@rhels.com>"

  git push -u origin "$BRANCH_NAME"

  PR_URL=$(gh pr create \
    --title "feat(kyverno): sync image registry allowlist (${#PATTERNS[@]} patterns)" \
    --body "$(cat <<EOF
## Summary

Syncs the image registry allowlist from \`rhels/compliance-as-code\` to the Kyverno ClusterPolicy.

- **Patterns:** ${#PATTERNS[@]}
- **Source:** \`rhels/compliance-as-code/policies/image-registry/allowlist.yaml\`
- **Generated at:** $TIMESTAMP

## Changes

- Updated \`$POLICY_PATH\` with current allowlist

## Verification

After merge, ArgoCD will sync the policy to the cluster. Verify:
\`\`\`bash
oc get clusterpolicy restrict-image-registries -o yaml
\`\`\`

---
Generated by ShieldBot sync pipeline.
EOF
)")

  echo "[SYNC] PR created: $PR_URL"
  rm -rf "$WORK_DIR"
else
  # Write to local file
  echo "$POLICY_YAML" > "$REPO_ROOT/output/restrict-image-registries.yaml"
  echo "[SYNC] Written to $REPO_ROOT/output/restrict-image-registries.yaml"
fi

echo "[SYNC] Done."
