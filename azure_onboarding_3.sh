#!/usr/bin/env bash
# ==============================================================================
# FinOps Intelligence Azure Onboarding Bootstrap Script
# Starter Daily + Deep — active subscription
# ==============================================================================
#
# Creates one Service Principal and grants the read-only permissions required by
# the current FinOps Intelligence Azure collector:
#
#   Subscription scope:
#     Reader
#     Cost Management Reader
#
#   Tenant/provider scopes:
#     Savings plan Reader @ /providers/Microsoft.BillingBenefits
#     Reservations Reader @ /providers/Microsoft.Capacity
#
# IMPORTANT:
# - AWS/other subscriptions are not touched.
# - The active Azure subscription remains the onboarding target.
# - Tenant/provider roles are created directly through ARM using stable built-in
#   role-definition GUIDs, avoiding Azure CLI role-name lookup issues.
# - If provider-scope assignment is denied, the script attempts Microsoft's
#   elevateAccess flow. This succeeds only for an eligible Microsoft Entra
#   Global Administrator. Any temporary root User Access Administrator grant
#   created by this script is removed before completion.
# ==============================================================================

set -Eeuo pipefail

DISPLAY_NAME="FinOps-Intelligence-Portal"

# Stable Azure built-in role definition GUIDs.
READER_ROLE_ID="acdd72a7-3385-48ef-bd42-f606fba81ae7"
COST_READER_ROLE_ID="72fafb9e-0641-4937-9268-a91bfd8191a3"
SAVINGS_PLAN_READER_ROLE_ID="d534ad90-4ac5-4815-a178-b2e47397baab"
RESERVATIONS_READER_ROLE_ID="582fc458-8989-419f-a480-75249bc5db7e"
UAA_ROLE_ID="18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

READER_ROLE_NAME="Reader"
COST_READER_ROLE_NAME="Cost Management Reader"
SAVINGS_PLAN_READER_ROLE_NAME="Savings plan Reader"
RESERVATIONS_READER_ROLE_NAME="Reservations Reader"

SUB_SCOPE=""
SP_SCOPE="/providers/Microsoft.BillingBenefits"
RES_SCOPE="/providers/Microsoft.Capacity"

CLIENT_ID=""
CLIENT_SECRET=""
SP_OBJECT_ID=""
CURRENT_USER_OBJECT_ID=""

CORE_READER_OK="false"
CORE_COST_OK="false"
TENANT_SP_OK="false"
TENANT_RES_OK="false"

ELEVATED_BY_SCRIPT="false"
ELEVATED_ASSIGNMENT_IDS=()
LAST_ROLE_ERROR=""

red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
cyan='\033[1;36m'
reset='\033[0m'

info() { echo -e "${cyan}$*${reset}"; }
ok()   { echo -e "  ${green}✓ $*${reset}"; }
warn() { echo -e "  ${yellow}⚠ $*${reset}"; }
err()  { echo -e "  ${red}✗ $*${reset}" >&2; }

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command not found: $1"
    exit 1
  fi
}

need_cmd az
need_cmd jq
need_cmd python3

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

full_role_definition_id() {
  printf '/providers/Microsoft.Authorization/roleDefinitions/%s' "$1"
}

is_authorization_error() {
  local text="${1:-}"
  grep -qiE \
    'AuthorizationFailed|Forbidden|does not have authorization|roleAssignments/write|not authorized|Insufficient privileges|LinkedAuthorizationFailed' \
    <<<"$text"
}

is_already_exists_error() {
  local text="${1:-}"
  grep -qiE \
    'RoleAssignmentExists|role assignment already exists|The role assignment already exists' \
    <<<"$text"
}

wait_for_sp_object() {
  local attempt
  for attempt in {1..15}; do
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)
    [[ -n "$SP_OBJECT_ID" ]] && return 0
    sleep 2
  done
  return 1
}

deterministic_assignment_uuid() {
  local principal_id="$1"
  local scope="$2"
  local role_id="$3"

  python3 - "$principal_id" "$scope" "$role_id" <<'PY'
import sys, uuid
principal_id, scope, role_id = sys.argv[1:4]
seed = f"finops-intelligence|{principal_id}|{scope}|{role_id}"
print(uuid.uuid5(uuid.NAMESPACE_URL, seed))
PY
}

# ------------------------------------------------------------------------------
# Subscription-level RBAC
# ------------------------------------------------------------------------------

subscription_role_assignment_exists() {
  local role_id="$1"
  local scope="$2"
  local full_role_id
  full_role_id="$(full_role_definition_id "$role_id")"

  local payload
  payload=$(az role assignment list \
    --assignee-object-id "$SP_OBJECT_ID" \
    --scope "$scope" \
    --include-inherited false \
    -o json 2>/dev/null || true)

  [[ -z "$payload" ]] && return 1

  jq -e \
    --arg rid "$full_role_id" \
    'any(.[]?; ((.roleDefinitionId // "") | ascii_downcase) == ($rid | ascii_downcase))' \
    <<<"$payload" >/dev/null 2>&1
}

ensure_subscription_role() {
  local role_id="$1"
  local role_name="$2"
  local scope="$3"
  local label="$4"

  LAST_ROLE_ERROR=""

  if subscription_role_assignment_exists "$role_id" "$scope"; then
    ok "$label already assigned."
    return 0
  fi

  local err_file err_text
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

  if is_already_exists_error "$err_text"; then
    ok "$label already assigned."
    return 0
  fi

  err "$label assignment failed."
  [[ -n "$err_text" ]] && sed 's/^/    /' <<<"$err_text" >&2
  return 1
}

# ------------------------------------------------------------------------------
# Tenant/provider-scope RBAC
#
# We intentionally DO NOT use:
#   az role definition list --name ...
#
# These roles have restricted assignableScopes and CLI name lookup may not
# expose them correctly from a subscription context.
# ------------------------------------------------------------------------------

provider_role_assignment_exists() {
  local role_id="$1"
  local scope="$2"
  local full_role_id
  full_role_id="$(full_role_definition_id "$role_id")"

  local url payload
  url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

  payload=$(az rest \
    --method get \
    --url "$url" \
    -o json 2>/dev/null || true)

  [[ -z "$payload" ]] && return 1

  jq -e \
    --arg pid "$SP_OBJECT_ID" \
    --arg rid "$full_role_id" \
    'any(.value[]?;
      ((.properties.principalId // "") | ascii_downcase) == ($pid | ascii_downcase)
      and
      ((.properties.roleDefinitionId // "") | ascii_downcase) == ($rid | ascii_downcase)
    )' \
    <<<"$payload" >/dev/null 2>&1
}

ensure_provider_role() {
  local role_id="$1"
  local role_name="$2"
  local scope="$3"
  local label="$4"

  LAST_ROLE_ERROR=""

  if provider_role_assignment_exists "$role_id" "$scope"; then
    ok "$label already assigned."
    return 0
  fi

  local assignment_uuid role_definition_id url body err_file err_text
  assignment_uuid="$(deterministic_assignment_uuid "$SP_OBJECT_ID" "$scope" "$role_id")"
  role_definition_id="$(full_role_definition_id "$role_id")"

  url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignments/${assignment_uuid}?api-version=2022-04-01"

  body=$(jq -nc \
    --arg rid "$role_definition_id" \
    --arg pid "$SP_OBJECT_ID" \
    '{
      properties: {
        roleDefinitionId: $rid,
        principalId: $pid,
        principalType: "ServicePrincipal"
      }
    }')

  err_file=$(mktemp)

  if az rest \
    --method put \
    --url "$url" \
    --headers "Content-Type=application/json" \
    --body "$body" \
    --output none 2>"$err_file"; then
    rm -f "$err_file"
    ok "$label assigned successfully."
    return 0
  fi

  err_text=$(cat "$err_file" 2>/dev/null || true)
  rm -f "$err_file"
  LAST_ROLE_ERROR="$err_text"

  if is_already_exists_error "$err_text"; then
    ok "$label already assigned."
    return 0
  fi

  err "$label assignment failed."
  if [[ -n "$err_text" ]]; then
    sed 's/^/    /' <<<"$err_text" >&2
  fi
  return 1
}

# ------------------------------------------------------------------------------
# Temporary root elevation
# ------------------------------------------------------------------------------

list_current_user_root_uaa_ids() {
  [[ -z "$CURRENT_USER_OBJECT_ID" ]] && return 0

  az role assignment list \
    --assignee-object-id "$CURRENT_USER_OBJECT_ID" \
    --scope "/" \
    --include-inherited false \
    -o json 2>/dev/null \
    | jq -r \
        --arg rid "$(full_role_definition_id "$UAA_ROLE_ID")" \
        '.[]?
         | select(((.roleDefinitionId // "") | ascii_downcase) == ($rid | ascii_downcase))
         | .id // empty' \
    || true
}

try_elevate_access() {
  local before_ids after_ids assignment_id err_file err_text

  if [[ -z "$CURRENT_USER_OBJECT_ID" ]]; then
    warn "Signed-in user Object ID could not be resolved; automatic elevateAccess cannot be attempted."
    return 1
  fi

  before_ids="$(list_current_user_root_uaa_ids)"

  echo ""
  echo "Provider-scope RBAC assignment requires tenant/root authorization."
  echo "Attempting Microsoft's temporary elevateAccess flow for the signed-in user..."

  err_file=$(mktemp)

  if az rest \
    --method post \
    --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" \
    --output none 2>"$err_file"; then

    rm -f "$err_file"
    ELEVATED_BY_SCRIPT="true"
    ok "Temporary root User Access Administrator access granted."

    # Allow RBAC propagation.
    sleep 10

    after_ids="$(list_current_user_root_uaa_ids)"

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

  warn "Automatic elevateAccess was not available for this signed-in user."
  if [[ -n "$err_text" ]]; then
    sed 's/^/    /' <<<"$err_text" >&2
  fi
  return 1
}

cleanup_elevation() {
  if [[ "$ELEVATED_BY_SCRIPT" != "true" ]]; then
    return
  fi

  echo ""
  echo "Removing temporary elevated root access..."

  if [[ ${#ELEVATED_ASSIGNMENT_IDS[@]} -eq 0 ]]; then
    warn "Temporary elevation succeeded, but the new root assignment ID could not be identified automatically."
    warn "Review Azure RBAC at scope '/' and remove the temporary User Access Administrator assignment if it remains."
    return
  fi

  local assignment_id err_file
  for assignment_id in "${ELEVATED_ASSIGNMENT_IDS[@]}"; do
    err_file=$(mktemp)
    if az role assignment delete --ids "$assignment_id" 2>"$err_file"; then
      ok "Temporary root role assignment removed."
    else
      warn "Could not remove temporary root role assignment: $assignment_id"
      [[ -s "$err_file" ]] && sed 's/^/    /' "$err_file" >&2
    fi
    rm -f "$err_file"
  done

  ELEVATED_BY_SCRIPT="false"
}

trap cleanup_elevation EXIT

# ------------------------------------------------------------------------------
# Account context
# ------------------------------------------------------------------------------

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

CURRENT_USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

# ------------------------------------------------------------------------------
# Create Service Principal + credential
# ------------------------------------------------------------------------------

echo "Creating Service Principal and credentials..."

CREATE_ERR=$(mktemp)
SP_INFO=""

if SP_INFO=$(az ad sp create-for-rbac \
  --name "$DISPLAY_NAME" \
  --role "$READER_ROLE_ID" \
  --scopes "$SUB_SCOPE" \
  --output json 2>"$CREATE_ERR"); then

  CLIENT_ID=$(jq -r '.appId // empty' <<<"$SP_INFO")
  CLIENT_SECRET=$(jq -r '.password // empty' <<<"$SP_INFO")
  ok "Service Principal created via create-for-rbac."

else
  warn "create-for-rbac failed; trying explicit App Registration flow."
  [[ -s "$CREATE_ERR" ]] && sed 's/^/    /' "$CREATE_ERR" >&2

  APP_JSON=$(az ad app create \
    --display-name "$DISPLAY_NAME" \
    --output json)

  CLIENT_ID=$(jq -r '.appId // empty' <<<"$APP_JSON")

  if [[ -z "$CLIENT_ID" ]]; then
    rm -f "$CREATE_ERR"
    err "Application registration did not return appId."
    exit 1
  fi

  az ad sp create --id "$CLIENT_ID" --output none

  SECRET_JSON=$(az ad app credential reset \
    --id "$CLIENT_ID" \
    --output json)

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
# Subscription roles
# ------------------------------------------------------------------------------

echo ""
echo "Ensuring subscription-level read permissions..."

if ensure_subscription_role \
  "$READER_ROLE_ID" \
  "$READER_ROLE_NAME" \
  "$SUB_SCOPE" \
  "Reader @ subscription"; then
  CORE_READER_OK="true"
fi

if ensure_subscription_role \
  "$COST_READER_ROLE_ID" \
  "$COST_READER_ROLE_NAME" \
  "$SUB_SCOPE" \
  "Cost Management Reader @ subscription"; then
  CORE_COST_OK="true"
fi

# ------------------------------------------------------------------------------
# Tenant/provider roles — first attempt
# ------------------------------------------------------------------------------

echo ""
echo "Ensuring tenant-level commitment read permissions..."

SP_FIRST_ERROR=""
RES_FIRST_ERROR=""

if ensure_provider_role \
  "$SAVINGS_PLAN_READER_ROLE_ID" \
  "$SAVINGS_PLAN_READER_ROLE_NAME" \
  "$SP_SCOPE" \
  "Savings plan Reader @ BillingBenefits"; then
  TENANT_SP_OK="true"
else
  SP_FIRST_ERROR="$LAST_ROLE_ERROR"
fi

if ensure_provider_role \
  "$RESERVATIONS_READER_ROLE_ID" \
  "$RESERVATIONS_READER_ROLE_NAME" \
  "$RES_SCOPE" \
  "Reservations Reader @ Capacity"; then
  TENANT_RES_OK="true"
else
  RES_FIRST_ERROR="$LAST_ROLE_ERROR"
fi

# ------------------------------------------------------------------------------
# Elevate + retry only when authorization is the blocker
# ------------------------------------------------------------------------------

if [[ "$TENANT_SP_OK" != "true" || "$TENANT_RES_OK" != "true" ]]; then
  AUTH_FAILURE="false"

  if [[ "$TENANT_SP_OK" != "true" ]] && is_authorization_error "$SP_FIRST_ERROR"; then
    AUTH_FAILURE="true"
  fi

  if [[ "$TENANT_RES_OK" != "true" ]] && is_authorization_error "$RES_FIRST_ERROR"; then
    AUTH_FAILURE="true"
  fi

  if [[ "$AUTH_FAILURE" == "true" ]]; then
    if try_elevate_access; then
      echo ""
      echo "Retrying tenant-level assignments after elevation..."

      if [[ "$TENANT_SP_OK" != "true" ]]; then
        if ensure_provider_role \
          "$SAVINGS_PLAN_READER_ROLE_ID" \
          "$SAVINGS_PLAN_READER_ROLE_NAME" \
          "$SP_SCOPE" \
          "Savings plan Reader @ BillingBenefits"; then
          TENANT_SP_OK="true"
        fi
      fi

      if [[ "$TENANT_RES_OK" != "true" ]]; then
        if ensure_provider_role \
          "$RESERVATIONS_READER_ROLE_ID" \
          "$RESERVATIONS_READER_ROLE_NAME" \
          "$RES_SCOPE" \
          "Reservations Reader @ Capacity"; then
          TENANT_RES_OK="true"
        fi
      fi
    fi
  fi
fi

# Remove temporary elevation before printing credentials.
cleanup_elevation
trap - EXIT

# ------------------------------------------------------------------------------
# Readiness report
# ------------------------------------------------------------------------------

echo ""
info "== FinOps Intelligence permission readiness =="

printf '  %-44s %s\n' \
  "Reader @ subscription" \
  "$([[ "$CORE_READER_OK" == "true" ]] && echo READY || echo FAILED)"

printf '  %-44s %s\n' \
  "Cost Management Reader @ subscription" \
  "$([[ "$CORE_COST_OK" == "true" ]] && echo READY || echo FAILED)"

printf '  %-44s %s\n' \
  "Savings plan Reader @ tenant" \
  "$([[ "$TENANT_SP_OK" == "true" ]] && echo READY || echo FAILED)"

printf '  %-44s %s\n' \
  "Reservations Reader @ tenant" \
  "$([[ "$TENANT_RES_OK" == "true" ]] && echo READY || echo FAILED)"

FULL_READY="false"

if [[ "$CORE_READER_OK" == "true" && \
      "$CORE_COST_OK" == "true" && \
      "$TENANT_SP_OK" == "true" && \
      "$TENANT_RES_OK" == "true" ]]; then
  FULL_READY="true"
fi

# ------------------------------------------------------------------------------
# Credentials
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# Final status
# ------------------------------------------------------------------------------

if [[ "$FULL_READY" == "true" ]]; then
  ok "Onboarding completed. FinOps Azure Daily + Deep permissions are READY."
  exit 0
fi

err "Onboarding completed with missing permissions. FinOps Azure is NOT fully ready for Daily + Deep."
echo ""
echo "The Service Principal was created and the credentials above remain valid."
echo "Service Principal Object ID:"
echo "  $SP_OBJECT_ID"
echo ""
echo "Expected provider-level role definitions:"
echo "  Savings plan Reader : $SAVINGS_PLAN_READER_ROLE_ID @ $SP_SCOPE"
echo "  Reservations Reader : $RESERVATIONS_READER_ROLE_ID @ $RES_SCOPE"
echo ""
echo "If the errors above are AuthorizationFailed/Forbidden:"
echo "  - Run onboarding with an eligible Microsoft Entra Global Administrator,"
echo "    or with an identity that can create role assignments at these scopes."
echo "  - The script automatically attempts elevateAccess when authorization is"
echo "    the only blocker."
echo ""
echo "Subscription-level permissions remain configured."
exit 2
