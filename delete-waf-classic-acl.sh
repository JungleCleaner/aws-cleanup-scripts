#!/usr/bin/env bash
# delete-waf-classic-acl.sh
#
# Safely deletes an orphaned WAF Classic Web ACL and all its associated rules.
#
# WAF Classic requires a strict deletion sequence:
#   1. Remove every rule from the ACL  (update-web-acl)
#   2. Delete the now-empty ACL        (delete-web-acl)
#   3. Remove all predicates from each rule (update-rule)
#   4. Delete the now-empty rules      (delete-rule)
#
# Usage:
#   ./delete-waf-classic-acl.sh --acl-id <id> [--scope global|regional] [--region <region>] [--dry-run]
#
# Options:
#   --acl-id   <id>       Required. WAF Classic WebACL ID (not ARN).
#   --scope    global|regional   Default: global.
#                           global   = aws waf     (CloudFront; always us-east-1)
#                           regional = aws waf-regional
#   --region   <region>   AWS region. Default: us-east-1 (required for regional scope).
#   --dry-run             Print commands without executing them.
#   --profile  <profile>  AWS CLI profile to use.
#
# Examples:
#   ./delete-waf-classic-acl.sh --acl-id 387d7905-0d80-484f-9238-bb4467d9f382
#   ./delete-waf-classic-acl.sh --acl-id abc123 --scope regional --region eu-west-1
#   ./delete-waf-classic-acl.sh --acl-id abc123 --dry-run

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

ACL_ID=""
SCOPE="global"
REGION="us-east-1"
DRY_RUN=false
PROFILE_ARG=""

# ── Arg parsing ───────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --acl-id)   ACL_ID="$2"; shift 2 ;;
    --scope)    SCOPE="$2"; shift 2 ;;
    --region)   REGION="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=true; shift ;;
    --profile)  PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$ACL_ID" ]]; then
  echo "Error: --acl-id is required." >&2
  exit 1
fi

if [[ "$SCOPE" != "global" && "$SCOPE" != "regional" ]]; then
  echo "Error: --scope must be 'global' or 'regional'." >&2
  exit 1
fi

# WAF Classic Global is always us-east-1
if [[ "$SCOPE" == "global" ]]; then
  REGION="us-east-1"
fi

CLI="aws waf"
if [[ "$SCOPE" == "regional" ]]; then
  CLI="aws waf-regional"
fi

REGION_ARG="--region $REGION"

# ── Helpers ───────────────────────────────────────────────────────────────────

run() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] $*"
  else
    eval "$*"
  fi
}

get_change_token() {
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY-RUN-TOKEN"
  else
    $CLI get-change-token $REGION_ARG $PROFILE_ARG --query ChangeToken --output text
  fi
}

# ── Fetch ACL details ─────────────────────────────────────────────────────────

echo "Fetching ACL $ACL_ID ($SCOPE, $REGION)…"

ACL_JSON=$($CLI get-web-acl --web-acl-id "$ACL_ID" $REGION_ARG $PROFILE_ARG 2>/dev/null || echo "")
if [[ -z "$ACL_JSON" ]]; then
  echo "Error: could not fetch ACL $ACL_ID. Check the ID, scope, and region." >&2
  exit 1
fi

ACL_NAME=$(echo "$ACL_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['WebACL']['Name'])")
DEFAULT_ACTION=$(echo "$ACL_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin)['WebACL']['DefaultAction']; print(list(d.keys())[0])")
RULES_JSON=$(echo "$ACL_JSON" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['WebACL'].get('Rules', [])))")
RULE_COUNT=$(echo "$RULES_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

echo "  Name          : $ACL_NAME"
echo "  Default action: $DEFAULT_ACTION"
echo "  Rules         : $RULE_COUNT"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[dry-run mode — no changes will be made]"
  echo ""
fi

# ── Step 1: Remove all rules from the ACL ────────────────────────────────────

if [[ "$RULE_COUNT" -gt 0 ]]; then
  echo "Step 1: Removing $RULE_COUNT rule(s) from ACL…"

  # Build the Updates JSON to DELETE each ActivatedRule
  UPDATES=$(echo "$RULES_JSON" | python3 -c "
import sys, json
rules = json.load(sys.stdin)
updates = [{'Action': 'DELETE', 'ActivatedRule': r} for r in rules]
print(json.dumps(updates))
")

  CT=$(get_change_token)
  run "$CLI update-web-acl \
    --web-acl-id '$ACL_ID' \
    --default-action Type=$DEFAULT_ACTION \
    --updates '$UPDATES' \
    --change-token '$CT' \
    $REGION_ARG $PROFILE_ARG"

  echo "  ✓ Rules detached."
else
  echo "Step 1: No rules attached — skipping."
fi

echo ""

# ── Step 2: Delete the now-empty ACL ─────────────────────────────────────────

echo "Step 2: Deleting ACL '$ACL_NAME' ($ACL_ID)…"
CT=$(get_change_token)
run "$CLI delete-web-acl \
  --web-acl-id '$ACL_ID' \
  --change-token '$CT' \
  $REGION_ARG $PROFILE_ARG"
echo "  ✓ ACL deleted."
echo ""

# ── Step 3 & 4: Remove predicates from each rule, then delete it ─────────────

RULE_IDS=$(echo "$RULES_JSON" | python3 -c "
import sys, json
rules = json.load(sys.stdin)
for r in rules:
    print(r['RuleId'])
")

for RULE_ID in $RULE_IDS; do
  echo "Processing rule $RULE_ID…"

  RULE_JSON=$($CLI get-rule --rule-id "$RULE_ID" $REGION_ARG $PROFILE_ARG 2>/dev/null || echo "")
  if [[ -z "$RULE_JSON" ]]; then
    echo "  ⚠ Could not fetch rule $RULE_ID — may already be deleted."
    continue
  fi

  RULE_NAME=$(echo "$RULE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['Rule']['Name'])")
  PREDICATES=$(echo "$RULE_JSON" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['Rule'].get('Predicates', [])))")
  PRED_COUNT=$(echo "$PREDICATES" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

  echo "  Name      : $RULE_NAME"
  echo "  Predicates: $PRED_COUNT"

  if [[ "$PRED_COUNT" -gt 0 ]]; then
    echo "  Step 3: Removing $PRED_COUNT predicate(s)…"

    PRED_UPDATES=$(echo "$PREDICATES" | python3 -c "
import sys, json
preds = json.load(sys.stdin)
updates = [{'Action': 'DELETE', 'Predicate': p} for p in preds]
print(json.dumps(updates))
")

    CT=$(get_change_token)
    run "$CLI update-rule \
      --rule-id '$RULE_ID' \
      --updates '$PRED_UPDATES' \
      --change-token '$CT' \
      $REGION_ARG $PROFILE_ARG"

    echo "  ✓ Predicates removed."
  fi

  echo "  Step 4: Deleting rule '$RULE_NAME' ($RULE_ID)…"
  CT=$(get_change_token)
  run "$CLI delete-rule \
    --rule-id '$RULE_ID' \
    --change-token '$CT' \
    $REGION_ARG $PROFILE_ARG"
  echo "  ✓ Rule deleted."
  echo ""
done

echo "Done. ACL '$ACL_NAME' and all its rules have been deleted."
