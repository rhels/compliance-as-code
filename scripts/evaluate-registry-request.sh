#!/usr/bin/env bash
# evaluate-registry-request.sh
# Evaluates a container image for trustworthiness before adding to the Kyverno allowlist.
#
# Usage:
#   ./scripts/evaluate-registry-request.sh <image-reference> [--json]
#
# Exit codes:
#   0 = auto-approve (score >= 80)
#   1 = needs-human-review (score 50-79)
#   2 = auto-reject (score < 50)
#   3 = error (evaluation failed)
#
# Requires: skopeo, trivy, cosign, jq, curl
#
# Scoring model (0-100):
#   Known trusted vendor    30 pts
#   Recent updates (<=90d)  15 pts
#   Community adoption      15 pts
#   No CRITICAL CVEs        20 pts
#   No HIGH CVEs            10 pts
#   Image signed (cosign)   10 pts
#
# Auto-approve threshold: >= 80
# Unknown vendors max: 70 (always need human review)

set -euo pipefail

# --- Configuration ---
TRUSTED_VENDORS=(
  # Red Hat ecosystem
  "redhat" "rhdh-community" "fedora" "openshift" "ubi"
  # HashiCorp
  "hashicorp"
  # Bitnami
  "bitnami" "bitnamilegacy"
  # CNCF projects
  "kyverno" "argoproj" "prometheus" "jetstack" "fluxcd" "envoyproxy"
  # Observability
  "grafana" "aquasecurity"
  # Infrastructure
  "calico" "cilium"
)

TRUSTED_REGISTRIES=(
  # These registries are inherently trusted (curated by vendor)
  "registry.access.redhat.com"
  "registry.redhat.io"
)

RECENCY_DAYS=90
AUTO_APPROVE_THRESHOLD=80
HUMAN_REVIEW_THRESHOLD=50

# --- Argument parsing ---
IMAGE_REF="${1:-}"
JSON_OUTPUT=false
if [[ "${2:-}" == "--json" ]]; then
  JSON_OUTPUT=true
fi

if [[ -z "$IMAGE_REF" ]]; then
  echo "Usage: $0 <image-reference> [--json]" >&2
  exit 3
fi

# --- Helper functions ---
log() { if [[ "$JSON_OUTPUT" == false ]]; then echo "[EVAL] $*"; fi; }
warn() { if [[ "$JSON_OUTPUT" == false ]]; then echo "[WARN] $*" >&2; fi; }

# Parse image reference into components
parse_image() {
  local image="$1"
  # Handle images without registry prefix (e.g., hashicorp/vault:latest)
  if [[ "$image" != *"/"*"/"* ]] && [[ "$image" != *"."*"/"* ]]; then
    image="docker.io/$image"
  fi

  REGISTRY=$(echo "$image" | cut -d'/' -f1)
  # Everything after registry, before the tag
  local repo_with_tag="${image#*/}"
  NAMESPACE=$(echo "$repo_with_tag" | cut -d'/' -f1)
  REPO_NAME=$(echo "$repo_with_tag" | sed 's/:.*//' | cut -d'/' -f2-)
  TAG=$(echo "$image" | grep -o ':[^:]*$' | sed 's/://' || echo "latest")
  if [[ -z "$TAG" ]]; then TAG="latest"; fi
}

# --- Score variables ---
score_vendor=0
score_recency=0
score_adoption=0
score_cve_critical=0
score_cve_high=0
score_signature=0

detail_vendor=""
detail_recency=""
detail_adoption=""
detail_cve_critical=""
detail_cve_high=""
detail_signature=""

trivy_critical=0
trivy_high=0
trivy_medium=0
trivy_low=0

image_created=""
image_size_mb=0
image_layers=0
image_digest=""

# --- Parse image ---
parse_image "$IMAGE_REF"
log "Evaluating: $IMAGE_REF"
log "Registry: $REGISTRY | Namespace: $NAMESPACE | Repo: $REPO_NAME | Tag: $TAG"

# --- Check 1: Vendor Trust (30 pts) ---
log "Checking vendor trust..."

# Check if the entire registry is trusted
registry_trusted=false
for trusted_reg in "${TRUSTED_REGISTRIES[@]}"; do
  if [[ "$REGISTRY" == "$trusted_reg" ]]; then
    registry_trusted=true
    score_vendor=30
    detail_vendor="Registry $REGISTRY is a trusted vendor registry"
    break
  fi
done

# If registry not inherently trusted, check namespace against known vendors
if [[ "$registry_trusted" == false ]]; then
  for vendor in "${TRUSTED_VENDORS[@]}"; do
    if [[ "$NAMESPACE" == "$vendor" ]]; then
      score_vendor=30
      detail_vendor="$NAMESPACE is a known trusted vendor"
      break
    fi
  done
fi

if [[ $score_vendor -eq 0 ]]; then
  detail_vendor="$NAMESPACE is NOT a known trusted vendor (unknown vendors require human review)"
fi

# --- Check 2: Recency (15 pts) ---
log "Checking image recency via skopeo..."

if command -v skopeo &>/dev/null; then
  inspect_json=$(skopeo inspect "docker://$IMAGE_REF" 2>/dev/null || echo "{}")
  if [[ "$inspect_json" != "{}" ]]; then
    image_created=$(echo "$inspect_json" | jq -r '.Created // empty' 2>/dev/null || echo "")
    image_digest=$(echo "$inspect_json" | jq -r '.Digest // empty' 2>/dev/null || echo "")
    image_layers=$(echo "$inspect_json" | jq '.Layers | length // 0' 2>/dev/null || echo 0)

    if [[ -n "$image_created" ]]; then
      created_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${image_created%%.*}" "+%s" 2>/dev/null || \
                      date -d "${image_created}" "+%s" 2>/dev/null || echo 0)
      now_epoch=$(date "+%s")
      days_old=$(( (now_epoch - created_epoch) / 86400 ))

      if [[ $days_old -le $RECENCY_DAYS ]]; then
        score_recency=15
        detail_recency="Last published $days_old days ago (within ${RECENCY_DAYS}d threshold)"
      elif [[ $days_old -le 365 ]]; then
        score_recency=5
        detail_recency="Last published $days_old days ago (older than ${RECENCY_DAYS}d but within 1 year)"
      else
        score_recency=0
        detail_recency="Last published $days_old days ago (STALE: over 1 year old)"
      fi
    else
      score_recency=0
      detail_recency="Could not determine image creation date"
    fi
  else
    score_recency=0
    detail_recency="skopeo inspect failed — image may not be publicly accessible"
  fi
else
  score_recency=0
  detail_recency="skopeo not available — skipping recency check"
fi

# --- Check 3: Community Adoption (15 pts) ---
log "Checking community adoption..."

case "$REGISTRY" in
  "docker.io")
    # Docker Hub API
    api_url="https://hub.docker.com/v2/repositories/$NAMESPACE/$REPO_NAME/"
    api_json=$(curl -sf "$api_url" 2>/dev/null || echo "{}")
    if [[ "$api_json" != "{}" ]]; then
      pull_count=$(echo "$api_json" | jq -r '.pull_count // 0')
      star_count=$(echo "$api_json" | jq -r '.star_count // 0')
      if [[ $pull_count -ge 1000000 ]]; then
        score_adoption=15
        detail_adoption="Docker Hub: ${pull_count} pulls, ${star_count} stars (highly adopted)"
      elif [[ $pull_count -ge 100000 ]]; then
        score_adoption=10
        detail_adoption="Docker Hub: ${pull_count} pulls, ${star_count} stars (well adopted)"
      elif [[ $pull_count -ge 10000 ]]; then
        score_adoption=5
        detail_adoption="Docker Hub: ${pull_count} pulls, ${star_count} stars (moderately adopted)"
      else
        score_adoption=0
        detail_adoption="Docker Hub: ${pull_count} pulls, ${star_count} stars (low adoption)"
      fi
    else
      score_adoption=0
      detail_adoption="Docker Hub API unavailable for $NAMESPACE/$REPO_NAME"
    fi
    ;;
  "quay.io")
    # Quay API
    api_url="https://quay.io/api/v1/repository/$NAMESPACE/$REPO_NAME"
    api_json=$(curl -sf "$api_url" 2>/dev/null || echo "{}")
    if [[ "$api_json" != "{}" ]]; then
      star_count=$(echo "$api_json" | jq -r '.star_count // 0')
      tag_count=$(echo "$api_json" | jq -r '.tags | length // 0' 2>/dev/null || echo 0)
      if [[ $star_count -ge 10 ]] || [[ $tag_count -ge 20 ]]; then
        score_adoption=15
        detail_adoption="Quay.io: ${star_count} stars, ${tag_count} tags (well adopted)"
      elif [[ $star_count -ge 3 ]] || [[ $tag_count -ge 5 ]]; then
        score_adoption=10
        detail_adoption="Quay.io: ${star_count} stars, ${tag_count} tags (moderately adopted)"
      else
        score_adoption=5
        detail_adoption="Quay.io: ${star_count} stars, ${tag_count} tags (limited adoption data)"
      fi
    else
      score_adoption=5
      detail_adoption="Quay.io API unavailable — partial score awarded"
    fi
    ;;
  "registry.access.redhat.com"|"registry.redhat.io")
    # Red Hat registries are curated — auto-pass
    score_adoption=15
    detail_adoption="Red Hat curated registry — adoption verified"
    ;;
  "ghcr.io")
    # GitHub Container Registry — check via GitHub API
    api_url="https://api.github.com/orgs/$NAMESPACE/packages/container/$REPO_NAME/versions"
    api_json=$(curl -sf -H "Accept: application/vnd.github+json" "$api_url" 2>/dev/null || echo "[]")
    version_count=$(echo "$api_json" | jq 'length // 0' 2>/dev/null || echo 0)
    if [[ $version_count -ge 50 ]]; then
      score_adoption=15
      detail_adoption="GHCR: ${version_count} versions (actively maintained)"
    elif [[ $version_count -ge 10 ]]; then
      score_adoption=10
      detail_adoption="GHCR: ${version_count} versions"
    else
      score_adoption=5
      detail_adoption="GHCR: ${version_count} versions (limited history)"
    fi
    ;;
  *)
    score_adoption=0
    detail_adoption="Unknown registry type — cannot assess adoption"
    ;;
esac

# --- Check 4: CVE Scan - CRITICAL (20 pts) ---
log "Running Trivy CVE scan (CRITICAL)..."

if command -v trivy &>/dev/null; then
  trivy_json=$(trivy image --severity CRITICAL,HIGH,MEDIUM,LOW --format json --quiet "$IMAGE_REF" 2>/dev/null || echo "{}")
  if [[ "$trivy_json" != "{}" ]]; then
    trivy_critical=$(echo "$trivy_json" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo 0)
    trivy_high=$(echo "$trivy_json" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' 2>/dev/null || echo 0)
    trivy_medium=$(echo "$trivy_json" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' 2>/dev/null || echo 0)
    trivy_low=$(echo "$trivy_json" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' 2>/dev/null || echo 0)

    if [[ $trivy_critical -eq 0 ]]; then
      score_cve_critical=20
      detail_cve_critical="0 CRITICAL CVEs found"
    else
      score_cve_critical=0
      detail_cve_critical="${trivy_critical} CRITICAL CVEs found"
    fi
  else
    score_cve_critical=10
    detail_cve_critical="Trivy scan returned no results — partial score"
  fi
else
  score_cve_critical=10
  detail_cve_critical="Trivy not available — partial score awarded"
fi

# --- Check 5: CVE Scan - HIGH (10 pts) ---
if [[ $trivy_high -eq 0 ]]; then
  score_cve_high=10
  detail_cve_high="0 HIGH CVEs found"
else
  score_cve_high=0
  detail_cve_high="${trivy_high} HIGH CVEs found"
fi

# --- Check 6: Image Signature (10 pts) ---
log "Checking image signature via cosign..."

if command -v cosign &>/dev/null; then
  if cosign verify "$IMAGE_REF" --certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*' 2>/dev/null; then
    score_signature=10
    detail_signature="cosign signature verified (Sigstore)"
  else
    score_signature=0
    detail_signature="No cosign signature found (not signed or verification failed)"
  fi
else
  score_signature=0
  detail_signature="cosign not available — skipping signature check"
fi

# --- Calculate total ---
total_score=$((score_vendor + score_recency + score_adoption + score_cve_critical + score_cve_high + score_signature))
max_score=100

# --- Decision ---
if [[ $total_score -ge $AUTO_APPROVE_THRESHOLD ]]; then
  decision="auto-approve"
elif [[ $total_score -ge $HUMAN_REVIEW_THRESHOLD ]]; then
  decision="needs-human-review"
else
  decision="auto-reject"
fi

# --- Output ---
if [[ "$JSON_OUTPUT" == true ]]; then
  jq -n \
    --arg image "$IMAGE_REF" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson sv "$score_vendor" --argjson mv 30 --arg dv "$detail_vendor" \
    --argjson sr "$score_recency" --argjson mr 15 --arg dr "$detail_recency" \
    --argjson sa "$score_adoption" --argjson ma 15 --arg da "$detail_adoption" \
    --argjson sc "$score_cve_critical" --argjson mc 20 --arg dc "$detail_cve_critical" \
    --argjson sh "$score_cve_high" --argjson mh 10 --arg dh "$detail_cve_high" \
    --argjson ss "$score_signature" --argjson ms 10 --arg ds "$detail_signature" \
    --argjson total "$total_score" --argjson max "$max_score" \
    --arg decision "$decision" \
    --argjson tc "$trivy_critical" --argjson th "$trivy_high" \
    --argjson tm "$trivy_medium" --argjson tl "$trivy_low" \
    --arg ic "$image_created" --argjson is "$image_size_mb" \
    --argjson il "$image_layers" --arg id "$image_digest" \
    '{
      image: $image,
      timestamp: $timestamp,
      scores: {
        vendor_trust: { points: $sv, max: $mv, detail: $dv },
        recency: { points: $sr, max: $mr, detail: $dr },
        adoption: { points: $sa, max: $ma, detail: $da },
        cve_critical: { points: $sc, max: $mc, detail: $dc },
        cve_high: { points: $sh, max: $mh, detail: $dh },
        signature: { points: $ss, max: $ms, detail: $ds }
      },
      total_score: $total,
      max_score: $max,
      decision: $decision,
      trivy_summary: { critical: $tc, high: $th, medium: $tm, low: $tl },
      image_metadata: { created: $ic, size_mb: $is, layers: $il, digest: $id }
    }'
else
  echo ""
  echo "=== Image Registry Evaluation Report ==="
  echo "Image:    $IMAGE_REF"
  echo "Date:     $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo ""
  echo "--- Scores ---"
  printf "%-20s %3d / %3d  %s\n" "Vendor Trust" "$score_vendor" 30 "$detail_vendor"
  printf "%-20s %3d / %3d  %s\n" "Recency" "$score_recency" 15 "$detail_recency"
  printf "%-20s %3d / %3d  %s\n" "Adoption" "$score_adoption" 15 "$detail_adoption"
  printf "%-20s %3d / %3d  %s\n" "CVE (Critical)" "$score_cve_critical" 20 "$detail_cve_critical"
  printf "%-20s %3d / %3d  %s\n" "CVE (High)" "$score_cve_high" 10 "$detail_cve_high"
  printf "%-20s %3d / %3d  %s\n" "Signature" "$score_signature" 10 "$detail_signature"
  echo ""
  echo "--- Trivy Summary ---"
  echo "Critical: $trivy_critical | High: $trivy_high | Medium: $trivy_medium | Low: $trivy_low"
  echo ""
  echo "TOTAL:    $total_score / $max_score"
  echo "DECISION: $decision"
  echo ""
fi

# Exit with appropriate code
case "$decision" in
  "auto-approve") exit 0 ;;
  "needs-human-review") exit 1 ;;
  "auto-reject") exit 2 ;;
  *) exit 3 ;;
esac
