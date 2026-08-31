#!/usr/bin/env bash
# ==============================================================================
# FinOps Intelligence Azure Onboarding Bootstrap Script
# Starter Daily + Deep — active subscription — v4 idempotent identity + ARM RBAC
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
#
# Use ARM REST instead of `az role assignment create`.
# This avoids the Cloud Shell legacy-token path that can request an audience for
# management.core.windows.net and fail before the assignment is even attempted.
# ------------------------------------------------------------------------------

subscription_role_definition_resource_id() {
  local role_id="$1"
  printf '%s/providers/Microsoft.Authorization/roleDefinitions/%s' "$SUB_SCOPE" "$role_id"
}

subscription_role_assignment_exists() {
  local role_id="$1"
  local scope="$2"
  local url payload

  url="https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=principalId%20eq%20%27${SP_OBJECT_ID}%27"

  payload=$(az rest \
    --method get \
    --url "$url" \
    -o json 2>/dev/null || true)

  [[ -z "$payload" ]] && return 1

  jq -e \
    --arg pid "$SP_OBJECT_ID" \
    --arg rid "$role_id" \
    'any(.value[]?;
      ((.properties.principalId // "") | ascii_downcase) == ($pid | ascii_downcase)
      and
      ((.properties.roleDefinitionId // "") | ascii_downcase | endswith(("/" + ($rid | ascii_downcase))))
    )' \
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

  local assignment_uuid role_definition_id url body err_file err_text
  assignment_uuid="$(deterministic_assignment_uuid "$SP_OBJECT_ID" "$scope" "$role_id")"
  role_definition_id="$(subscription_role_definition_resource_id "$role_id")"

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
#
# elevateAccess is asynchronous from an RBAC propagation perspective. A 200/204
# response means the request was accepted, not that Microsoft.Authorization/*
# is immediately effective in ARM. We therefore poll the root role assignment
# until User Access Administrator @ "/" is actually visible for the caller.
# ------------------------------------------------------------------------------

ROOT_UAA_ASSIGNMENT_ID=""
ROOT_UAA_PREEXISTING="false"

find_current_user_root_uaa_id() {
  [[ -z "$CURRENT_USER_OBJECT_ID" ]] && return 1

  local url payload
  url="https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=principalId%20eq%20%27${CURRENT_USER_OBJECT_ID}%27"

  payload=$(az rest \
    --method get \
    --url "$url" \
    -o json 2>/dev/null || true)

  [[ -z "$payload" ]] && return 1

  jq -r \
    --arg pid "$CURRENT_USER_OBJECT_ID" \
    --arg rid "$(full_role_definition_id "$UAA_ROLE_ID")" \
    '.value[]?
     | select(
         ((.properties.principalId // "") | ascii_downcase) == ($pid | ascii_downcase)
         and
         ((.properties.roleDefinitionId // "") | ascii_downcase) == ($rid | ascii_downcase)
       )
     | .id // empty' \
    <<<"$payload" \
    | head -n 1
}

wait_for_root_uaa_visibility() {
  local attempt assignment_id

  echo "Waiting for root User Access Administrator assignment to become effective..."

  for attempt in {1..30}; do
    az account get-access-token \
      --resource "https://management.azure.com/" \
      --output none >/dev/null 2>&1 || true

    assignment_id=$(find_current_user_root_uaa_id || true)

    if [[ -n "$assignment_id" ]]; then
      ROOT_UAA_ASSIGNMENT_ID="$assignment_id"
      ok "User Access Administrator @ / is now visible."
      return 0
    fi

    sleep 5
  done

  return 1
}

try_elevate_access() {
  local existing_id err_file err_text

  if [[ -z "$CURRENT_USER_OBJECT_ID" ]]; then
    warn "Signed-in user Object ID could not be resolved; automatic elevateAccess cannot be attempted."
    return 1
  fi

  existing_id=$(find_current_user_root_uaa_id || true)
  if [[ -n "$existing_id" ]]; then
    ROOT_UAA_ASSIGNMENT_ID="$existing_id"
    ROOT_UAA_PREEXISTING="true"
    ok "User already has User Access Administrator @ /."
    return 0
  fi

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
    ok "Temporary root elevation request accepted."

    if wait_for_root_uaa_visibility; then
      return 0
    fi

    warn "elevateAccess was accepted, but User Access Administrator @ / did not become visible."
    return 1
  fi

  err_text=$(cat "$err_file" 2>/dev/null || true)
  rm -f "$err_file"

  warn "Automatic elevateAccess was not available for this signed-in user."
  if [[ -n "$err_text" ]]; then
    sed 's/^/    /' <<<"$err_text" >&2
  fi
  return 1
}

ensure_provider_role_with_retry() {
  local role_id="$1"
  local role_name="$2"
  local scope="$3"
  local label="$4"
  local attempt last_error=""

  for attempt in {1..18}; do
    if ensure_provider_role "$role_id" "$role_name" "$scope" "$label"; then
      return 0
    fi

    last_error="$LAST_ROLE_ERROR"

    if ! is_authorization_error "$last_error"; then
      return 1
    fi

    if [[ "$attempt" -lt 18 ]]; then
      warn "$label is not effective yet; retrying after RBAC propagation..."
      sleep 5
    fi
  done

  LAST_ROLE_ERROR="$last_error"
  return 1
}

cleanup_elevation() {
  if [[ "$ELEVATED_BY_SCRIPT" != "true" ]]; then
    return
  fi

  if [[ "$ROOT_UAA_PREEXISTING" == "true" ]]; then
    return
  fi

  echo ""
  echo "Removing temporary elevated root access..."

  if [[ -z "$ROOT_UAA_ASSIGNMENT_ID" ]]; then
    ROOT_UAA_ASSIGNMENT_ID=$(find_current_user_root_uaa_id || true)
  fi

  if [[ -z "$ROOT_UAA_ASSIGNMENT_ID" ]]; then
    warn "Temporary elevation was requested, but its exact root role assignment could not be resolved."
    warn "Review Microsoft Entra ID > Properties > Access management for Azure resources and disable it if still enabled."
    return
  fi

  local url err_file err_text attempt
  url="https://management.azure.com${ROOT_UAA_ASSIGNMENT_ID}?api-version=2022-04-01"

  for attempt in {1..10}; do
    err_file=$(mktemp)

    if az rest \
      --method delete \
      --url "$url" \
      --output none 2>"$err_file"; then
      rm -f "$err_file"
      ok "Temporary User Access Administrator @ / removed."
      ELEVATED_BY_SCRIPT="false"
      ROOT_UAA_ASSIGNMENT_ID=""
      return
    fi

    err_text=$(cat "$err_file" 2>/dev/null || true)
    rm -f "$err_file"

    if [[ "$attempt" -lt 10 ]]; then
      sleep 3
    fi
  done

  warn "Could not automatically remove temporary root elevation."
  [[ -n "${err_text:-}" ]] && sed 's/^/    /' <<<"$err_text" >&2
  warn "Disable 'Access management for Azure resources' for the signed-in Global Administrator after this onboarding."
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
# Create or reuse App Registration + Service Principal + generate credential
#
# Do NOT use `az ad sp create-for-rbac`.
# Identity creation and Azure RBAC are intentionally separate operations.
# Re-runs reuse the exact existing App Registration/SP for DISPLAY_NAME.
# A new password credential is appended instead of deleting existing credentials.
# ------------------------------------------------------------------------------

echo "Resolving FinOps Intelligence App Registration..."

APP_LIST=$(az ad app list \
  --display-name "$DISPLAY_NAME" \
  --output json 2>/dev/null || echo '[]')

EXACT_APPS=$(jq -c \
  --arg name "$DISPLAY_NAME" \
  '[.[]? | select(.displayName == $name)]' \
  <<<"$APP_LIST" 2>/dev/null || echo '[]')

APP_COUNT=$(jq 'length' <<<"$EXACT_APPS" 2>/dev/null || echo "0")

if [[ "$APP_COUNT" -eq 0 ]]; then
  echo "Creating App Registration..."
  APP_JSON=$(az ad app create \
    --display-name "$DISPLAY_NAME" \
    --output json)

  CLIENT_ID=$(jq -r '.appId // empty' <<<"$APP_JSON")
  APP_OBJECT_ID=$(jq -r '.id // empty' <<<"$APP_JSON")

  if [[ -z "$CLIENT_ID" ]]; then
    err "Application registration did not return appId."
    exit 1
  fi

  ok "App Registration created."

elif [[ "$APP_COUNT" -eq 1 ]]; then
  CLIENT_ID=$(jq -r '.[0].appId // empty' <<<"$EXACT_APPS")
  APP_OBJECT_ID=$(jq -r '.[0].id // empty' <<<"$EXACT_APPS")
  ok "Existing App Registration found; reusing it."

else
  # Duplicate display names are ambiguous. Resolve automatically only if exactly
  # one of those applications already has a Service Principal in this tenant.
  MATCHING_WITH_SP=()
  while IFS= read -r candidate_app_id; do
    [[ -z "$candidate_app_id" ]] && continue
    candidate_sp=$(az ad sp show \
      --id "$candidate_app_id" \
      --query id \
      -o tsv 2>/dev/null || true)
    if [[ -n "$candidate_sp" ]]; then
      MATCHING_WITH_SP+=("$candidate_app_id")
    fi
  done < <(jq -r '.[].appId // empty' <<<"$EXACT_APPS")

  if [[ "${#MATCHING_WITH_SP[@]}" -eq 1 ]]; then
    CLIENT_ID="${MATCHING_WITH_SP[0]}"
    APP_OBJECT_ID=$(jq -r \
      --arg cid "$CLIENT_ID" \
      '.[] | select(.appId == $cid) | .id // empty' \
      <<<"$EXACT_APPS" | head -n 1)
    warn "Multiple App Registrations share the display name; reused the only one with an existing Service Principal."
  else
    err "Multiple App Registrations named '$DISPLAY_NAME' were found and cannot be resolved safely."
    echo "Matching application IDs:" >&2
    jq -r '.[].appId' <<<"$EXACT_APPS" | sed 's/^/  - /' >&2
    echo "Remove the obsolete duplicates in Microsoft Entra ID and run onboarding again." >&2
    exit 1
  fi
fi

if [[ -z "$CLIENT_ID" ]]; then
  err "Could not resolve application client ID."
  exit 1
fi

echo "Ensuring Service Principal exists..."

SP_OBJECT_ID=$(az ad sp show \
  --id "$CLIENT_ID" \
  --query id \
  -o tsv 2>/dev/null || true)

if [[ -n "$SP_OBJECT_ID" ]]; then
  ok "Existing Service Principal found; reusing it."
else
  SP_CREATE_ERROR=""
  SP_CREATE_ERR_FILE=$(mktemp)

  if az ad sp create \
    --id "$CLIENT_ID" \
    --output none 2>"$SP_CREATE_ERR_FILE"; then
    ok "Service Principal created."
  else
    SP_CREATE_ERROR=$(cat "$SP_CREATE_ERR_FILE" 2>/dev/null || true)

    # A previous/parallel run may have created the SP between show and create.
    if grep -qiE 'already in use|already exists|service principal.*exists' <<<"$SP_CREATE_ERROR"; then
      warn "Service Principal already exists; waiting for Microsoft Graph propagation."
    else
      rm -f "$SP_CREATE_ERR_FILE"
      err "Service Principal creation failed."
      [[ -n "$SP_CREATE_ERROR" ]] && sed 's/^/    /' <<<"$SP_CREATE_ERROR" >&2
      exit 1
    fi
  fi

  rm -f "$SP_CREATE_ERR_FILE"

  if ! wait_for_sp_object; then
    err "Could not resolve Service Principal Object ID after creation/reuse."
    exit 1
  fi
fi

ok "Service Principal Object ID resolved."

echo "Generating onboarding credential..."

CREDENTIAL_DISPLAY_NAME="FinOps-Intelligence-Onboarding-$(date -u +%Y%m%dT%H%M%SZ)"

# --append is intentional: a retry must not revoke a credential that may already
# have been pasted into the platform. Old test credentials can be revoked later.
SECRET_JSON=$(az ad app credential reset \
  --id "$CLIENT_ID" \
  --append \
  --display-name "$CREDENTIAL_DISPLAY_NAME" \
  --years 1 \
  --output json)

CLIENT_SECRET=$(jq -r '.password // empty' <<<"$SECRET_JSON")

if [[ -z "$CLIENT_SECRET" ]]; then
  err "Could not generate the client secret."
  exit 1
fi

ok "New client secret generated without removing existing credentials."

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
        if ensure_provider_role_with_retry \
          "$SAVINGS_PLAN_READER_ROLE_ID" \
          "$SAVINGS_PLAN_READER_ROLE_NAME" \
          "$SP_SCOPE" \
          "Savings plan Reader @ BillingBenefits"; then
          TENANT_SP_OK="true"
        fi
      fi

      if [[ "$TENANT_RES_OK" != "true" ]]; then
        if ensure_provider_role_with_retry \
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
echo "The App Registration / Service Principal were created or reused and the credentials above remain valid."
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
