#!/usr/bin/env bash
#
# account-handover.sh — Detach a Quipux-managed AWS account and hand it over.
#
# Direct AWS CLI orchestration (no Python/boto3 for cloud ops). MongoDB step
# delegates to the sanctioned `mongodb_controller` tool (auth via security.py).
#
# SAFETY MODEL
#   * Dry-run by default. Mutations run ONLY with --apply.
#   * Account-ID guard: aborts if the active profile != EXPECTED_ACCOUNT_ID.
#   * Phase-based: run one phase at a time. There is no "do everything" mode,
#     by design — handover is irreversible.
#
# USAGE
#   ./account-handover.sh <phase> [--apply]
#
#   Phases (run in this order):
#     preflight          Identity guard + deployed-stack inventory (read-only)
#     freeze             Disable the nightly destroy scheduler (mutation)
#     power-on           Start create_test_resources {"project":"cloud-apps"} (mutation)
#     validate           EC2/RDS/ECS up? (read-only)
#     detach-network     Check Compliance->Network export link (read-only + guidance)
#     delete-governance  Delete CostControl, Operations, Compliance, Optimization (mutation)
#     deactivate-mongo   Set cloud-dashboard-db.accounts.status = "inactive"
#     detach-org         Remove account from AWS Organization (needs PAYER_PROFILE)
#     security-info      Show Security/KMS/IAM footprint to resolve MANUALLY (read-only)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Target config — VERIFIED for QXCOMPARENDERASSOMOSTEST (sts/list-stacks, 2026-06-30)
# ---------------------------------------------------------------------------
ACCOUNT_ALIAS="QXCOMPARENDERASSOMOSTEST"
EXPECTED_ACCOUNT_ID="883623967094"
PROFILE="${AWS_PROFILE_OVERRIDE:-QXCOMPARENDERASSOMOSTEST}"
REGION="us-east-1"

PROJECT_PAYLOAD='{"project": "cloud-apps"}'   # NOTE: lowercase "project" — state machines read $.project
CFN_ROLE="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:role/Security-CloudFormationRole"
SM_CREATE="arn:aws:states:${REGION}:${EXPECTED_ACCOUNT_ID}:stateMachine:create_test_resources"
DESTROY_RULE="Compliance-DestroyTestInstancesStepScheduler"
CONFIG_EXPORT="Compliance-ConfigS3BucketArn"

# Governance stacks to delete, in dependency-safe order.
# CostControl & Operations have 0 importers. Compliance is gated on detach-network.
GOVERNANCE_STACKS=(CostControl Operations Compliance OptimizationManagementDataRoleStack)

# MongoDB (Cloud Dashboard registry) — sanctioned tool + its own venv
MONGO_DIR="/home/cloud-agent/Projects/oci-scripts/scripts/mongodb_controller"
MONGO_PY="${MONGO_DIR}/.venv/bin/python3"
MONGO_COLLECTION="accounts"
MONGO_FILTER="{\"account_id\": \"${EXPECTED_ACCOUNT_ID}\"}"
MONGO_UPDATE='{"$set": {"status": "inactive"}}'

# Decision-required inputs (set via env before the relevant phase)
PAYER_PROFILE="${PAYER_PROFILE:-}"   # management/payer profile for AWS Organizations

# ---------------------------------------------------------------------------
APPLY=0
PHASE="${1:-help}"
[[ "${2:-}" == "--apply" ]] && APPLY=1

AWS=(aws --profile "$PROFILE" --region "$REGION")

c_red()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
hr()     { printf '%s\n' "------------------------------------------------------------"; }

# run MUTATION — printed always; executed only under --apply
run() {
  printf '  + %s\n' "$*"
  if [[ $APPLY -eq 1 ]]; then
    "$@"
  else
    c_ylw "    [dry-run] not executed (pass --apply)"
  fi
}

confirm() {
  # Typed confirmation for the most destructive phases (only when applying)
  [[ $APPLY -eq 0 ]] && return 0
  local ans
  read -r -p "Type the account alias ($ACCOUNT_ALIAS) to proceed: " ans
  [[ "$ans" == "$ACCOUNT_ALIAS" ]] || { c_red "Mismatch — aborting."; exit 1; }
}

guard_account() {
  local who
  who="$(${AWS[@]} sts get-caller-identity --query Account --output text 2>/dev/null || true)"
  if [[ "$who" != "$EXPECTED_ACCOUNT_ID" ]]; then
    c_red "GUARD FAILED: active account '$who' != expected '$EXPECTED_ACCOUNT_ID' (profile $PROFILE)"
    exit 1
  fi
  c_grn "Account guard OK: $who ($ACCOUNT_ALIAS) via profile $PROFILE"
}

delete_stack() {
  local stack="$1"
  if ! ${AWS[@]} cloudformation describe-stacks --stack-name "$stack" >/dev/null 2>&1; then
    c_ylw "  $stack: not present (already gone) — skip"
    return 0
  fi
  run "${AWS[@]}" cloudformation delete-stack --stack-name "$stack" --role-arn "$CFN_ROLE"
  if [[ $APPLY -eq 1 ]]; then
    printf '    waiting for delete...\n'
    ${AWS[@]} cloudformation wait stack-delete-complete --stack-name "$stack" \
      && c_grn "  $stack deleted" || c_red "  $stack delete did NOT complete — inspect events"
  fi
}

# ===========================================================================
phase_preflight() {
  hr; echo "PHASE: preflight (read-only)"; hr
  guard_account
  echo "Deployed stacks:"
  ${AWS[@]} cloudformation list-stacks \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE IMPORT_COMPLETE \
    --query "StackSummaries[].StackName" --output text | tr '\t' '\n' | sort
}

phase_freeze() {
  hr; echo "PHASE: freeze nightly destroy scheduler"; hr
  guard_account
  run "${AWS[@]}" events disable-rule --name "$DESTROY_RULE"
}

phase_power_on() {
  hr; echo "PHASE: power-on (create_test_resources)"; hr
  guard_account
  c_ylw "Payload (lowercase 'project' is mandatory): $PROJECT_PAYLOAD"
  run "${AWS[@]}" stepfunctions start-execution \
    --state-machine-arn "$SM_CREATE" --input "$PROJECT_PAYLOAD"
}

phase_validate() {
  hr; echo "PHASE: validate (read-only)"; hr
  guard_account
  echo "EC2 running:"
  ${AWS[@]} ec2 describe-instances --filters "Name=instance-state-name,Values=running" \
    --query "Reservations[].Instances[].[Tags[?Key=='Name']|[0].Value,InstanceId,State.Name]" --output table || true
  echo "RDS:"
  ${AWS[@]} rds describe-db-instances \
    --query "DBInstances[].[DBInstanceIdentifier,DBInstanceStatus]" --output table || true
  echo "ECS clusters:"
  ${AWS[@]} ecs list-clusters --output text || true
}

phase_detach_network() {
  hr; echo "PHASE: detach-network (read-only check)"; hr
  guard_account
  local imp
  imp="$(${AWS[@]} cloudformation list-imports --export-name "$CONFIG_EXPORT" \
          --query 'Imports' --output text 2>/dev/null || true)"
  if [[ -n "$imp" && "$imp" != "None" ]]; then
    c_red "BLOCKED: export $CONFIG_EXPORT still imported by: $imp"
    cat <<EOF
  To unblock (do NOT edit the shared template in the repo):
    1) Make an ad-hoc copy of account-all-network.yml under aws-cloudformation/temp/
       removing  Fn::ImportValue: $CONFIG_EXPORT  and repointing VPC Flow Logs
       to a client-owned bucket (or disabling them).
    2) ${AWS[*]} cloudformation update-stack --stack-name Network \\
         --template-body file:///home/cloud-agent/Projects/aws-cloudformation/temp/Network-handover-${ACCOUNT_ALIAS}.yml \\
         --role-arn $CFN_ROLE --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
    3) Re-run this phase; it must report CLEAR before delete-governance.
EOF
    exit 1
  fi
  c_grn "CLEAR: $CONFIG_EXPORT is not imported — Compliance can be deleted."
}

phase_delete_governance() {
  hr; echo "PHASE: delete-governance (IRREVERSIBLE)"; hr
  guard_account
  # Re-check the Compliance<-Network gate before deleting Compliance
  local imp
  imp="$(${AWS[@]} cloudformation list-imports --export-name "$CONFIG_EXPORT" \
          --query 'Imports' --output text 2>/dev/null || true)"
  if [[ -n "$imp" && "$imp" != "None" ]]; then
    c_red "ABORT: $CONFIG_EXPORT still in use by $imp — run detach-network first."
    exit 1
  fi
  c_ylw "About to delete: ${GOVERNANCE_STACKS[*]}"
  c_ylw "Security is intentionally NOT deleted (KMS keys encrypt data — see security-info)."
  confirm
  for s in "${GOVERNANCE_STACKS[@]}"; do
    echo ">> $s"
    delete_stack "$s"
  done
}

phase_deactivate_mongo() {
  hr; echo "PHASE: deactivate-mongo (cloud-dashboard-db.accounts.status=inactive)"; hr
  [[ -x "$MONGO_PY" ]] || { c_red "mongodb_controller venv not found: $MONGO_PY"; exit 1; }
  cd "$MONGO_DIR"
  echo "Current document:"
  "$MONGO_PY" query.py "$MONGO_COLLECTION" --filter "$MONGO_FILTER" || \
    c_ylw "  (no match by account_id — adjust MONGO_FILTER to the real field, e.g. account_alias)"
  echo "Update preview (dry-run):"
  "$MONGO_PY" execute.py update_one "$MONGO_COLLECTION" "$MONGO_FILTER" "$MONGO_UPDATE" --dry-run
  if [[ $APPLY -eq 1 ]]; then
    confirm
    "$MONGO_PY" execute.py update_one "$MONGO_COLLECTION" "$MONGO_FILTER" "$MONGO_UPDATE"
    c_grn "Mongo status set to inactive."
  else
    c_ylw "[dry-run] not applied (pass --apply)"
  fi
}

phase_detach_org() {
  hr; echo "PHASE: detach-org (AWS Organizations — runs against PAYER_PROFILE)"; hr
  [[ -n "$PAYER_PROFILE" ]] || { c_red "Set PAYER_PROFILE=<management profile> first."; exit 1; }
  c_ylw "Removing $EXPECTED_ACCOUNT_ID from the Organization via profile '$PAYER_PROFILE'."
  c_ylw "Account must be standalone-ready (billing/contact configured) or AWS will refuse."
  confirm
  run aws --profile "$PAYER_PROFILE" --region "$REGION" \
    organizations remove-account-from-organization --account-id "$EXPECTED_ACCOUNT_ID"
}

phase_security_info() {
  hr; echo "PHASE: security-info (read-only — resolve MANUALLY)"; hr
  guard_account
  c_ylw "Security stack is NOT auto-deleted. Decisions required:"
  echo " * KMS: transfer key policy to client OR re-encrypt OR recreate (test data)."
  echo " * IAM CloudAgent user (delete LAST, it is your access)."
  echo
  echo "Customer-managed KMS keys:"
  ${AWS[@]} kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null | tr '\t' '\n' | \
    while read -r k; do
      [[ -z "$k" ]] && continue
      desc="$(${AWS[@]} kms describe-key --key-id "$k" \
              --query 'KeyMetadata.[KeyId,KeyManager,Description]' --output text 2>/dev/null || true)"
      echo "  $desc"
    done || true
  echo
  echo "IAM users (look for the CloudAgent operator):"
  ${AWS[@]} iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n' || true
}

case "$PHASE" in
  preflight)         phase_preflight ;;
  freeze)            phase_freeze ;;
  power-on)          phase_power_on ;;
  validate)          phase_validate ;;
  detach-network)    phase_detach_network ;;
  delete-governance) phase_delete_governance ;;
  deactivate-mongo)  phase_deactivate_mongo ;;
  detach-org)        phase_detach_org ;;
  security-info)     phase_security_info ;;
  help|--help|-h)
    sed -n '2,40p' "$0" ;;
  *)
    c_red "Unknown phase: $PHASE"; sed -n '24,40p' "$0"; exit 1 ;;
esac
