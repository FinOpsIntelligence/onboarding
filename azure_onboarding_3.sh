#!/usr/bin/env bash
# ==============================================================================
# FinOps Intelligence Azure Onboarding Bootstrap Script
# Daily + Deep (Starter) — single active subscription
# ==============================================================================
# Grants the minimum read-only permissions required by the current Azure FinOps
# collector for Daily and Deep execution on the active subscription:
#   - Reader                          @ /subscriptions/<subscriptionId>
#   - Cost Management Reader          @ /subscriptions/<subscriptionId>
#   - Savings plan reader             @ /providers/Microsoft.BillingBenefits
#   - Reservations Reader             @ /providers/Microsoft.Capacity
#
# Tenant-level roles require Microsoft.Authorization/roleAssignments/write at
# the provider scope. If the signed-in user cannot assign them, the script tries
# Microsoft's elevateAccess flow. That only succeeds for an eligible Microsoft
# Entra Global Administrator. Elevated root access is removed again afterwards.
# ==============================================================================

set -Eeuo pipefail

DISPLAY_NAME="FinOps-Intelligence-Portal"

READER_ROLE="Reader"
COST_READER_ROLE="Cost Management Reader"
SAVINGS_PLAN_READER_ROLE="Savings plan reader"
RESERVATIONS_READER_ROLE="Reservations Reader"
UAA_ROLE="User Access Administrator"

SUB_SCOPE=""
SP_SCOPE="/providers/Microsoft.BillingBenefits"
RES_SCOPE="/providers/Microsoft.Capacity"

CLIENT_ID=""
CLIENT_SECRET=""
SP_OBJECT_ID=""
CURRENT_USER_OBJECT_ID=""
ELEVATED_BY_SCRIPT="false"
ELEVATED_ASSIGNMENT_IDS=()
LAST_ROLE_ERROR=""

TENANT_SP_OK="false"
TENANT_RES_OK="false"
CORE_READER_OK="false"
CORE_COST_OK="false"

red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
cyan='\033[1;36m'
reset='\033[0m'

info() { echo -e "${cyan}$*${reset}"; }
ok()   { echo -e "  ${green}✓ $*${reset}"; }
warn() { echo -e "  ${yellow}⚠ $*${reset}"; }
err()  { echo -e "  ${red}✗ $*${reset}" >&2; }

cleanup() {
  # Remove only the exact root role-assignment IDs created by elevateAccess.
  # This avoids deleting a pre-existing User Access Administrator assignment.
  if [[ "$ELEVATED_BY_SCRIPT" == "true" ]]; then
    echo ""
    echo "Removing temporary elevated root access..."

    if [[ ${#ELEVATED_ASSIGNMENT_IDS[@]} -eq 0 ]]; then
      warn "The script elevated access but could not identify the new root role-assignment ID."
      warn "Verify that your temporary 'User Access Administrator' assignment at scope '/' was removed."
    else
      local assignment_id delete_err
      for assignment_id in "${ELEVATED_ASSIGNMENT_IDS[@]}"; do
        delete_err=$(mktemp)
        if az role assignment delete --ids "$assignment_id" --yes 2>"$delete_err"; then
          ok "Temporary root role assignment removed: $assignment_id"
        else
          warn "Could not remove temporary root role assignment: $assignment_id"
          if [[ -s "$delete_err" ]]; then
            sed 's/^/    /' "$delete_err" >&2
          fi
        fi
        rm -f "$delete_err"
      done
    fi

    ELEVATED_BY_SCRIPT="false"
  fi
}
trap cleanup EXIT

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command not found: $1"
    exit 1
  fi
}

need_cmd az
need_cmd jq
need_cmd curl

info "== FinOps Intelligence Azure Setup =="
echo "Fetching active account context..."

TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || true)
SUB_ID=$(az account show --query id -o tsv 2>/dev/null || true)
SUB_NAME=$(az account show --query name -o tsv 2>/dev/null || true)

if [[ -z "$TENANT_ID" || -z "$SUB_ID" ]]; then
  err "Could not retrieve Azure account context."
  echo "Make sure you are logged in and have an active subscription selected."
  exit 1
fi

SUB_SCOPE="/subscriptions/$SUB_ID"

echo -e "  Tenant ID:           ${yellow}$TENANT_ID${reset}"
echo -e "  Active Subscription: ${green}$SUB_NAME ($SUB_ID)${reset}"
echo ""

# Current user ID is needed only for the optional elevateAccess flow.
CURRENT_USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
resolve_role_id() {
  local role_name="$1"
  az role definition list --name "$role_name" --query '[0].name' -o tsv 2>/dev/null || true
}

role_assignment_exists() {
  local principal_id="$1"
  local role_name="$2"
  local scope="$3"
  local role_id existing_json

  role_id=$(resolve_role_id "$role_name")
  [[ -z "$role_id" ]] && return 1

  existing_json=$(az role assignment list \
    --assignee-object-id "$principal_id" \
    --scope "$scope" \
    --include-inherited false \
    -o json 2>/dev/null || true)

  [[ -z "$existing_json" ]] && return 1

  jq -e --arg rid "$role_id" \
    'any(.[]?; ((.roleDefinitionId // "") | endswith($rid)))' \
    <<<"$existing_json" >/dev/null 2>&1
}

ensure_role_assignment() {
  local role_name="$1"
  local scope="$2"
  local label="$3"
  local role_id err_file err_text

  LAST_ROLE_ERROR=""

  role_id=$(resolve_role_id "$role_name")
  if [[ -z "$role_id" ]]; then
    LAST_ROLE_ERROR="Role definition not found: $role_name"
    err "$label: Azure role definition '$role_name' was not found."
    return 1
  fi

  if role_assignment_exists "$SP_OBJECT_ID" "$role_name" "$scope"; then
    ok "$label already assigned."
    return 0
  fi

  err_file=$(mktemp)
  if az role assignment create \
    --assignee-object-id "$SP_OBJECT_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "$role_id" \
    --scope "$scope" \
    --output none 2>"$err_file"; then
    rm -f "$err_file"
    ok "$label assigned successfully."
    return 0
  fi

  err_text=$(cat "$err_file" 2>/dev/null || true)
  rm -f "$err_file"
  LAST_ROLE_ERROR="$err_text"

  # Idempotency: Azure can return RoleAssignmentExists even if the pre-check
  # could not list role assignments at the provider scope.
  if grep -qiE 'RoleAssignmentExists|role assignment already exists' <<<"$err_text"; then
    ok "$label already assigned."
    return 0
  fi

  err "$label assignment failed."
  if [[ -n "$err_text" ]]; then
    sed 's/^/    /' <<<"$err_text" >&2
  fi
  return 1
}

is_authorization_error() {
  local text="$1"
  grep -qiE \
    'AuthorizationFailed|Forbidden|does not have authorization|roleAssignments/write|not authorized|Insufficient privileges' \
    <<<"$text"
}

wait_for_sp_object() {
  local attempt
  for attempt in {1..12}; do
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)
    [[ -n "$SP_OBJECT_ID" ]] && return 0
    sleep 2
  done
  return 1
}

try_elevate_access() {
  local err_file err_text before_ids after_ids assignment_id

  if [[ -z "$CURRENT_USER_OBJECT_ID" ]]; then
    warn "Signed-in user Object ID could not be resolved; automatic tenant-scope elevation cannot be attempted."
    return 1
  fi

  # Record any pre-existing UAA assignment IDs so cleanup never removes them.
  before_ids=$(az role assignment list \
    --assignee-object-id "$CURRENT_USER_OBJECT_ID" \
    --role "$UAA_ROLE" \
    --scope "/" \
    --include-inherited false \
    --query '[].id' -o tsv 2>/dev/null || true)

  echo ""
  echo "Tenant-level RBAC assignment requires root/provider-scope authorization."
  echo "Attempting Microsoft elevateAccess flow for the signed-in user..."

  err_file=$(mktemp)
  if az rest \
    --method post \
    --url "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" \
    --output none 2>"$err_file"; then
    rm -f "$err_file"
    ELEVATED_BY_SCRIPT="true"
    ok "Temporary root User Access Administrator access granted."

    # RBAC propagation can be slightly delayed.
    sleep 5

    after_ids=$(az role assignment list \
      --assignee-object-id "$CURRENT_USER_OBJECT_ID" \
      --role "$UAA_ROLE" \
      --scope "/" \
      --include-inherited false \
      --query '[].id' -o tsv 2>/dev/null || true)

    while IFS= read -r assignment_id; do
      [[ -z "$assignment_id" ]] && continue
      if ! grep -Fqx "$assignment_id" <<<"$before_ids"; then
        ELEVATED_ASSIGNMENT_IDS+=("$assignment_id")
      fi
    done <<<"$after_ids"

    return 0
  fi

  err_text=$(cat "$err_file" 2>/dev/null || true)
  rm -f "$err_file"
  warn "Automatic elevation was not available for this user."
  if [[ -n "$err_text" ]]; then
    sed 's/^/    /' <<<"$err_text" >&2
  fi
  return 1
}

# ------------------------------------------------------------------------------
# Create Service Principal + credential
# ------------------------------------------------------------------------------
echo "Creating Service Principal and credentials..."
SP_INFO=""
CREATE_ERR=$(mktemp)

if SP_INFO=$(az ad sp create-for-rbac \
  --name "$DISPLAY_NAME" \
  --role "$READER_ROLE" \
  --scopes "$SUB_SCOPE" \
  --output json 2>"$CREATE_ERR"); then
  CLIENT_ID=$(jq -r '.appId // empty' <<<"$SP_INFO")
  CLIENT_SECRET=$(jq -r '.password // empty' <<<"$SP_INFO")
  ok "Service Principal created via create-for-rbac."
else
  warn "create-for-rbac failed; trying explicit App Registration flow."
  if [[ -s "$CREATE_ERR" ]]; then
    sed 's/^/    /' "$CREATE_ERR" >&2
  fi

  APP_JSON=$(az ad app create --display-name "$DISPLAY_NAME" --output json)
  CLIENT_ID=$(jq -r '.appId // empty' <<<"$APP_JSON")

  if [[ -z "$CLIENT_ID" ]]; then
    err "Application registration did not return appId."
    rm -f "$CREATE_ERR"
    exit 1
  fi

  az ad sp create --id "$CLIENT_ID" --output none
  SECRET_JSON=$(az ad app credential reset --id "$CLIENT_ID" --output json)
  CLIENT_SECRET=$(jq -r '.password // empty' <<<"$SECRET_JSON")
  ok "Service Principal created via explicit App Registration flow."
fi
rm -f "$CREATE_ERR"

if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  err "Could not obtain Service Principal credentials."
  exit 1
fi

if ! wait_for_sp_object; then
  err "Could not resolve Service Principal Object ID after creation."
  exit 1
fi
ok "Service Principal Object ID resolved."

# ------------------------------------------------------------------------------
# Subscription-level roles — required by Daily and Deep
# ------------------------------------------------------------------------------
echo ""
echo "Ensuring subscription-level read permissions..."

if ensure_role_assignment "$READER_ROLE" "$SUB_SCOPE" "Reader @ subscription"; then
  CORE_READER_OK="true"
fi

if ensure_role_assignment "$COST_READER_ROLE" "$SUB_SCOPE" "Cost Management Reader @ subscription"; then
  CORE_COST_OK="true"
fi

# ------------------------------------------------------------------------------
# Tenant/provider-level roles — required for complete commitment inventory
# ------------------------------------------------------------------------------
echo ""
echo "Ensuring tenant-level commitment read permissions..."

SP_FIRST_ERROR=""
RES_FIRST_ERROR=""

if ensure_role_assignment "$SAVINGS_PLAN_READER_ROLE" "$SP_SCOPE" "Savings plan reader @ BillingBenefits"; then
  TENANT_SP_OK="true"
else
  SP_FIRST_ERROR="$LAST_ROLE_ERROR"
fi

if ensure_role_assignment "$RESERVATIONS_READER_ROLE" "$RES_SCOPE" "Reservations Reader @ Capacity"; then
  TENANT_RES_OK="true"
else
  RES_FIRST_ERROR="$LAST_ROLE_ERROR"
fi

# If one or both failed specifically because the signed-in user cannot create
# provider-scope role assignments, try Microsoft's temporary root elevation.
if [[ "$TENANT_SP_OK" != "true" || "$TENANT_RES_OK" != "true" ]]; then
  AUTH_FAILURE="false"
  if [[ "$TENANT_SP_OK" != "true" ]] && is_authorization_error "$SP_FIRST_ERROR"; then AUTH_FAILURE="true"; fi
  if [[ "$TENANT_RES_OK" != "true" ]] && is_authorization_error "$RES_FIRST_ERROR"; then AUTH_FAILURE="true"; fi

  if [[ "$AUTH_FAILURE" == "true" ]] && try_elevate_access; then
    echo "Retrying tenant-level assignments after elevation..."

    if [[ "$TENANT_SP_OK" != "true" ]]; then
      if ensure_role_assignment "$SAVINGS_PLAN_READER_ROLE" "$SP_SCOPE" "Savings plan reader @ BillingBenefits"; then
        TENANT_SP_OK="true"
      fi
    fi

    if [[ "$TENANT_RES_OK" != "true" ]]; then
      if ensure_role_assignment "$RESERVATIONS_READER_ROLE" "$RES_SCOPE" "Reservations Reader @ Capacity"; then
        TENANT_RES_OK="true"
      fi
    fi
  fi
fi

# Remove temporary root elevation before credentials are printed.
cleanup
trap - EXIT

# ------------------------------------------------------------------------------
# Final readiness report
# ------------------------------------------------------------------------------
echo ""
info "== FinOps Intelligence permission readiness =="
printf '  %-42s %s\n' "Reader @ subscription" "$([[ "$CORE_READER_OK" == "true" ]] && echo READY || echo FAILED)"
printf '  %-42s %s\n' "Cost Management Reader @ subscription" "$([[ "$CORE_COST_OK" == "true" ]] && echo READY || echo FAILED)"
printf '  %-42s %s\n' "Savings plan reader @ tenant" "$([[ "$TENANT_SP_OK" == "true" ]] && echo READY || echo FAILED)"
printf '  %-42s %s\n' "Reservations Reader @ tenant" "$([[ "$TENANT_RES_OK" == "true" ]] && echo READY || echo FAILED)"

FULL_READY="false"
if [[ "$CORE_READER_OK" == "true" && "$CORE_COST_OK" == "true" && \
      "$TENANT_SP_OK" == "true" && "$TENANT_RES_OK" == "true" ]]; then
  FULL_READY="true"
fi

# Credentials are printed even on partial failure so an administrator can assign
# the missing tenant roles to this same SP instead of forcing a new onboarding.
echo ""
info "=== COPY THE ENTIRE JSON BLOCK BELOW AND PASTE IT IN FINOPS INTELLIGENCE ==="
cat <<JSON
{
  "tenantId": "$TENANT_ID",
  "clientId": "$CLIENT_ID",
  "clientSecret": "$CLIENT_SECRET",
  "subscriptionId": "$SUB_ID"
}
JSON
info "============================================================================"
echo ""

if [[ "$FULL_READY" == "true" ]]; then
  ok "Onboarding completed. FinOps Azure Daily + Deep permissions are READY."
  exit 0
fi

err "Onboarding completed with missing permissions. FinOps Azure is NOT fully ready for Daily + Deep."
echo ""
echo "The Service Principal was created and the credentials above remain valid."
echo "Assign the missing roles to this same Service Principal Object ID:"
echo "  $SP_OBJECT_ID"
echo ""
echo "Required tenant scopes:"
echo "  Savings plan reader : $SP_SCOPE"
echo "  Reservations Reader : $RES_SCOPE"
echo ""
echo "If automatic elevation failed, the signed-in user is not authorized to assign roles at those tenant/provider scopes."
echo "Use a Microsoft Entra Global Administrator with temporary elevated Azure access, or another identity that can create role assignments at those scopes."
exit 2
