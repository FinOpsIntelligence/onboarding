#!/usr/bin/env bash
set -euo pipefail

# Microsoft 365 Onboarding Script for Vulneri FinOps M365
# Cloud Shell-first implementation using Azure CLI + Microsoft Graph REST.

GRAPH_APP_ID="00000003-0000-0000-c000-000000000000" # Microsoft Graph
DEFAULT_DISPLAY_NAME="Vulneri FinOps M365"

DISPLAY_NAME="$DEFAULT_DISPLAY_NAME"
MODE="starter"
SECRET_MONTHS="12"
TENANT_ID=""
CLIENT_ID=""
VALIDATE_ONLY="false"
RENEW_SECRET="false"
WRITE_ENV_FILE="false"
YES="false"
FORCE_NEW="false"
SKIP_AUTO_CONSENT="false"

log_info() { printf '\033[36m[INFO]\033[0m %s\n' "$*"; }
log_warn() { printf '\033[33m[WARNING]\033[0m %s\n' "$*"; }
log_err()  { printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2; }

usage() {
  cat <<USAGE
Vulneri Microsoft 365 Onboarding

Usage:
  ./m365_onboarding.sh [options]

Options:
  --mode starter|expert          Permission profile. Default: starter
  --tenant-id <tenantId>         Microsoft 365 / Entra tenant ID to onboard
  --client-id <clientId>         Existing App Registration client ID
  --display-name <name>          App Registration display name. Default: "$DEFAULT_DISPLAY_NAME"
  --secret-months <months>       Client secret validity in months. Default: 12
  --validate-only                Validate an existing App Registration. Requires --client-id
  --renew-secret                 Generate a new client secret. Requires --client-id
  --write-env-file               Also write a local .env file. For tests only
  --yes                          Do not ask tenant confirmation when tenant is inferred
  --force-new                    Create a new App Registration even if one with the same name exists
  --skip-auto-consent            Do not try az ad app permission admin-consent automatically
  -h, --help                     Show this help

Recommended Cloud Shell command:
  curl -fsSL https://raw.githubusercontent.com/FinOpsIntelligence/onboarding/main/m365_onboarding.sh | bash -s -- --mode starter

USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"; shift 2 ;;
    --tenant-id|--tenant)
      TENANT_ID="${2:-}"; shift 2 ;;
    --client-id|--client)
      CLIENT_ID="${2:-}"; shift 2 ;;
    --display-name)
      DISPLAY_NAME="${2:-}"; shift 2 ;;
    --secret-months)
      SECRET_MONTHS="${2:-}"; shift 2 ;;
    --validate-only)
      VALIDATE_ONLY="true"; shift ;;
    --renew-secret)
      RENEW_SECRET="true"; shift ;;
    --write-env-file)
      WRITE_ENV_FILE="true"; shift ;;
    --yes|-y)
      YES="true"; shift ;;
    --force-new)
      FORCE_NEW="true"; shift ;;
    --skip-auto-consent)
      SKIP_AUTO_CONSENT="true"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      log_err "Unknown option: $1"; usage; exit 1 ;;
  esac
done

MODE="$(printf '%s' "$MODE" | tr '[:upper:]' '[:lower:]')"
if [[ "$MODE" != "starter" && "$MODE" != "expert" ]]; then
  log_err "Invalid --mode '$MODE'. Use starter or expert."
  exit 1
fi

if ! [[ "$SECRET_MONTHS" =~ ^[0-9]+$ ]] || [[ "$SECRET_MONTHS" -lt 1 ]]; then
  log_err "--secret-months must be a positive integer."
  exit 1
fi

if [[ "$VALIDATE_ONLY" == "true" && -z "$CLIENT_ID" ]]; then
  log_err "--client-id is required when --validate-only is used."
  exit 1
fi

if [[ "$RENEW_SECRET" == "true" && -z "$CLIENT_ID" ]]; then
  log_err "--client-id is required when --renew-secret is used."
  exit 1
fi

if [[ "$VALIDATE_ONLY" == "true" && "$RENEW_SECRET" == "true" ]]; then
  log_err "Use either --validate-only or --renew-secret, not both."
  exit 1
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_err "Required command not found: $cmd"
    exit 1
  fi
}

now_utc() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

calc_secret_expiry() {
  if date -u -d "+${SECRET_MONTHS} months" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
    date -u -d "+${SECRET_MONTHS} months" '+%Y-%m-%dT%H:%M:%SZ'
  else
    # Fallback approximation for non-GNU date environments.
    python3 - <<PY
from datetime import datetime, timedelta, timezone
months = int("$SECRET_MONTHS")
print((datetime.now(timezone.utc) + timedelta(days=30*months)).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY
  fi
}

json_array() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
  else
    printf '%s\n' "$@" | jq -R -s -c 'split("\n") | map(select(length > 0))'
  fi
}

print_header() {
  echo "== Vulneri Microsoft 365 Onboarding =="
  log_info "This script only configures Microsoft 365 access. The scanner will run on the Vulneri backend."
  log_info "Local machine administrator privileges are not required; Microsoft 365 tenant administrator privileges may be needed."

  if [[ "$VALIDATE_ONLY" == "true" ]]; then
    log_info "Selected mode: Permission Validation (--validate-only)"
  elif [[ "$RENEW_SECRET" == "true" ]]; then
    log_info "Selected mode: Credential Renewal (--renew-secret)"
  else
    log_info "Selected mode: $MODE"
    if [[ "$MODE" == "starter" ]]; then
      log_info "This mode requests read-only permissions for license inventory and usage."
    else
      log_info "This mode requests additional permissions for security, governance, identity, and applications."
    fi
  fi
  echo
}

ensure_dependencies() {
  log_info "Verifying Cloud Shell dependencies..."
  require_cmd az
  require_cmd jq
  require_cmd curl

  if ! az account show >/dev/null 2>&1; then
    log_warn "Azure CLI is not authenticated. Starting az login with device code."
    az login --use-device-code --allow-no-subscriptions -o none
  fi
}

get_active_tenant_id() {
  az account show --query tenantId -o tsv 2>/dev/null || true
}

ensure_tenant_context() {
  local active_tenant
  active_tenant="$(get_active_tenant_id)"

  if [[ -z "$active_tenant" ]]; then
    log_err "Could not determine the current Azure CLI tenant."
    log_err "Run: az login --use-device-code --allow-no-subscriptions"
    exit 1
  fi

  if [[ -n "$TENANT_ID" && "$active_tenant" != "$TENANT_ID" ]]; then
    log_warn "Current Azure CLI tenant is different from the requested Microsoft 365 tenant."
    log_warn "Current tenant:   $active_tenant"
    log_warn "Requested tenant: $TENANT_ID"
    log_info "Attempting to authenticate Azure CLI into the requested tenant..."

    az login --tenant "$TENANT_ID" --use-device-code --allow-no-subscriptions -o none
    active_tenant="$(get_active_tenant_id)"

    if [[ "$active_tenant" != "$TENANT_ID" ]]; then
      log_err "Azure CLI is still not using the requested tenant."
      log_err "Current tenant:   $active_tenant"
      log_err "Requested tenant: $TENANT_ID"
      exit 1
    fi
  fi

  if [[ -z "$TENANT_ID" ]]; then
    TENANT_ID="$active_tenant"
    log_warn "No --tenant-id was provided. Using the current Azure CLI tenant."
    log_warn "Detected Microsoft 365 / Entra TenantId: $TENANT_ID"

    if [[ "$YES" != "true" ]]; then
      echo
      read -r -p "Is this the correct Microsoft 365 tenant for onboarding? (Y/N): " confirm
      if [[ ! "$confirm" =~ ^[YySs]$ ]]; then
        log_err "Onboarding cancelled. Re-run with: --tenant-id <M365_TENANT_ID>"
        exit 1
      fi
    fi
  fi

  log_info "Using Microsoft 365 / Entra TenantId: $TENANT_ID"
}

# Permissions are resolved dynamically from Microsoft Graph service principal.
declare -a PERMISSIONS=()
declare -A ROLE_IDS=()
GRAPH_SP_JSON=""
GRAPH_SP_OBJECT_ID=""

load_permissions_for_mode() {
  PERMISSIONS=(
    "Directory.Read.All"
    "LicenseAssignment.Read.All"
    "Reports.Read.All"
    "MailboxSettings.Read"
    "ReportSettings.Read.All"
  )

  if [[ "$MODE" == "expert" ]]; then
    PERMISSIONS+=(
      "Policy.Read.All"
      "SecurityEvents.Read.All"
      "Application.Read.All"
      "AuditLog.Read.All"
      "RoleManagement.Read.Directory"
      "IdentityRiskyUser.Read.All"
    )
  fi
}

resolve_graph_roles() {
  log_info "Resolving Microsoft Graph application permission IDs..."
  GRAPH_SP_JSON="$(az ad sp show --id "$GRAPH_APP_ID" -o json)"
  GRAPH_SP_OBJECT_ID="$(jq -r '.id' <<<"$GRAPH_SP_JSON")"

  if [[ -z "$GRAPH_SP_OBJECT_ID" || "$GRAPH_SP_OBJECT_ID" == "null" ]]; then
    log_err "Could not locate the Microsoft Graph service principal in this tenant."
    exit 1
  fi

  local permission role_id
  for permission in "${PERMISSIONS[@]}"; do
    role_id="$(jq -r --arg value "$permission" '.appRoles[]? | select(.value == $value and (.allowedMemberTypes | index("Application"))) | .id' <<<"$GRAPH_SP_JSON" | head -n 1)"
    if [[ -z "$role_id" || "$role_id" == "null" ]]; then
      log_err "Microsoft Graph application permission not found: $permission"
      exit 1
    fi
    ROLE_IDS["$permission"]="$role_id"
  done
}

find_existing_app() {
  az ad app list --display-name "$DISPLAY_NAME" -o json | jq -r '.[0].appId // empty'
}

create_or_reuse_app() {
  local existing_app_id=""

  if [[ "$FORCE_NEW" != "true" ]]; then
    log_info "Checking if an App Registration named '$DISPLAY_NAME' already exists..."
    existing_app_id="$(find_existing_app)"
  fi

  if [[ -n "$existing_app_id" ]]; then
    CLIENT_ID="$existing_app_id"
    log_warn "An App Registration with this name already exists. Reusing it."
    log_info "M365 Client ID: $CLIENT_ID"
  else
    log_info "Creating new App Registration..."
    CLIENT_ID="$(az ad app create \
      --display-name "$DISPLAY_NAME" \
      --sign-in-audience AzureADMyOrg \
      --web-redirect-uris "https://localhost" \
      --query appId -o tsv)"

    if [[ -z "$CLIENT_ID" ]]; then
      log_err "Failed to create App Registration."
      exit 1
    fi
    log_info "App Registration created. M365 Client ID: $CLIENT_ID"
  fi
}

ensure_service_principal() {
  log_info "Ensuring corresponding Service Principal exists..."
  if az ad sp show --id "$CLIENT_ID" >/dev/null 2>&1; then
    log_info "Service Principal already exists."
  else
    log_info "Creating Service Principal..."
    az ad sp create --id "$CLIENT_ID" -o none >/dev/null
    log_info "Service Principal created."
  fi
}

configure_permissions() {
  log_info "Configuring Microsoft Graph application permissions..."

  local permission role_id api_permission
  for permission in "${PERMISSIONS[@]}"; do
    role_id="${ROLE_IDS[$permission]}"
    api_permission="${role_id}=Role"

    if az ad app permission add \
      --id "$CLIENT_ID" \
      --api "$GRAPH_APP_ID" \
      --api-permissions "$api_permission" \
      -o none >/dev/null 2>&1; then
      log_info "Configured permission: $permission"
    else
      log_warn "Permission may already be configured or could not be added: $permission"
    fi
  done
}

create_client_secret() {
  local secret_expires_at secret
  secret_expires_at="$(calc_secret_expiry)"
  log_info "Adding a new client secret. Expiration: $secret_expires_at"

  secret="$(az ad app credential reset \
    --id "$CLIENT_ID" \
    --display-name "vulneri-finops-secret" \
    --end-date "$secret_expires_at" \
    --append \
    --query password -o tsv)"

  if [[ -z "$secret" ]]; then
    log_err "Failed to generate client secret."
    exit 1
  fi

  M365_CLIENT_SECRET="$secret"
  SECRET_EXPIRES_AT="$secret_expires_at"
  SECRET_DISPLAY_NAME="vulneri-finops-secret"
}

admin_consent_url() {
  printf 'https://login.microsoftonline.com/%s/v2.0/adminconsent?client_id=%s&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default&redirect_uri=https%%3A%%2F%%2Flocalhost' "$TENANT_ID" "$CLIENT_ID"
}

# Validation globals
declare -a PERMISSIONS_CONFIGURED=()
declare -a PERMISSIONS_GRANTED=()
declare -a PERMISSIONS_MISSING=()
declare -a PERMISSIONS_PENDING_CONSENT=()
VALIDATION_STATUS="error"

contains_line() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

validate_onboarding() {
  PERMISSIONS_CONFIGURED=()
  PERMISSIONS_GRANTED=()
  PERMISSIONS_MISSING=()
  PERMISSIONS_PENDING_CONSENT=()

  log_info "Validating App Registration and admin consent..."

  local app_json sp_object_id configured_ids granted_ids permission role_id
  app_json="$(az ad app show --id "$CLIENT_ID" -o json)"

  mapfile -t configured_ids < <(jq -r --arg graph "$GRAPH_APP_ID" '.requiredResourceAccess[]? | select(.resourceAppId == $graph) | .resourceAccess[]?.id' <<<"$app_json" | sort -u)

  if ! sp_object_id="$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null)" || [[ -z "$sp_object_id" ]]; then
    log_warn "Service Principal was not found during validation."
    VALIDATION_STATUS="error"
    return 1
  fi

  mapfile -t granted_ids < <(az rest \
    --method GET \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_object_id}/appRoleAssignments?\$top=999" \
    -o json 2>/dev/null | jq -r --arg graph_sp "$GRAPH_SP_OBJECT_ID" '.value[]? | select(.resourceId == $graph_sp) | .appRoleId' | sort -u)

  for permission in "${PERMISSIONS[@]}"; do
    role_id="${ROLE_IDS[$permission]}"

    if contains_line "$role_id" "${configured_ids[@]}"; then
      PERMISSIONS_CONFIGURED+=("$permission")
    else
      PERMISSIONS_MISSING+=("$permission")
    fi

    if contains_line "$role_id" "${granted_ids[@]}"; then
      PERMISSIONS_GRANTED+=("$permission")
    elif contains_line "$role_id" "${configured_ids[@]}"; then
      PERMISSIONS_PENDING_CONSENT+=("$permission")
    fi
  done

  if [[ ${#PERMISSIONS_MISSING[@]} -gt 0 ]]; then
    VALIDATION_STATUS="missing_permissions"
  elif [[ ${#PERMISSIONS_PENDING_CONSENT[@]} -gt 0 ]]; then
    VALIDATION_STATUS="pending_admin_consent"
  else
    VALIDATION_STATUS="ready"
  fi

  [[ "$VALIDATION_STATUS" == "ready" ]]
}

validation_json() {
  jq -n -c \
    --arg provider "m365" \
    --arg mode "$MODE" \
    --arg tenant "$TENANT_ID" \
    --arg client "$CLIENT_ID" \
    --arg status "$VALIDATION_STATUS" \
    --arg checkedAt "$(now_utc)" \
    --argjson expected "$(json_array "${PERMISSIONS[@]}")" \
    --argjson configured "$(json_array "${PERMISSIONS_CONFIGURED[@]}")" \
    --argjson missing "$(json_array "${PERMISSIONS_MISSING[@]}")" \
    --argjson granted "$(json_array "${PERMISSIONS_GRANTED[@]}")" \
    --argjson pending "$(json_array "${PERMISSIONS_PENDING_CONSENT[@]}")" \
    '{provider:$provider,mode:$mode,m365TenantId:$tenant,m365ClientId:$client,validationStatus:$status,permissionsExpected:$expected,permissionsConfigured:$configured,permissionsMissing:$missing,permissionsGranted:$granted,permissionsPendingConsent:$pending,checkedAt:$checkedAt}'
}

try_auto_admin_consent() {
  if [[ "$SKIP_AUTO_CONSENT" == "true" ]]; then
    return 1
  fi

  log_info "Trying to grant admin consent automatically with Azure CLI..."
  if az ad app permission admin-consent --id "$CLIENT_ID" -o none >/dev/null 2>&1; then
    log_info "Admin consent command completed. Waiting for propagation..."
    sleep 10
    return 0
  fi

  log_warn "Automatic admin consent failed or was not allowed. Manual consent will be required."
  return 1
}

manual_admin_consent_loop() {
  local consent_url choice
  consent_url="$(admin_consent_url)"

  while true; do
    echo
    printf '\033[33m============================================================\033[0m\n'
    printf '\033[33mACTION REQUIRED: GRANT ADMINISTRATOR CONSENT\033[0m\n'
    printf '\033[33m============================================================\033[0m\n'
    echo "The App Registration exists in the Microsoft 365 tenant,"
    echo "but the requested Graph application permissions are not fully consented yet."
    echo
    echo "Open this URL in your browser, review the permissions, and click Accept:"
    printf '\033[36m%s\033[0m\n' "$consent_url"
    echo
    echo "After granting consent, return to this terminal and press ENTER."
    echo "The client secret will only be displayed after validation succeeds."
    printf '\033[33m============================================================\033[0m\n'
    echo

    read -r -p "Press ENTER after granting admin consent..." _

    # A few retries help with Microsoft Graph propagation delay.
    local attempt
    for attempt in 1 2 3 4 5; do
      if validate_onboarding; then
        return 0
      fi
      log_warn "Validation status: $VALIDATION_STATUS. Waiting for propagation ($attempt/5)..."
      sleep 8
    done

    log_err "Validation failed or is incomplete. Status: $VALIDATION_STATUS"
    if [[ ${#PERMISSIONS_PENDING_CONSENT[@]} -gt 0 ]]; then
      log_err "Permissions pending consent: ${PERMISSIONS_PENDING_CONSENT[*]}"
    fi
    if [[ ${#PERMISSIONS_MISSING[@]} -gt 0 ]]; then
      log_err "Permissions missing in app configuration: ${PERMISSIONS_MISSING[*]}"
    fi

    read -r -p "Do you want to retry after checking the consent screen? (Y/N): " choice
    if [[ ! "$choice" =~ ^[YySs]$ ]]; then
      log_warn "Onboarding suspended. The App Registration was created, but credentials were not validated."
      log_warn "For security, the generated client secret was not displayed."
      log_warn "To validate later: ./m365_onboarding.sh --validate-only --tenant-id $TENANT_ID --client-id $CLIENT_ID --mode $MODE"
      log_warn "If this terminal is closed and you need a new secret: ./m365_onboarding.sh --renew-secret --tenant-id $TENANT_ID --client-id $CLIENT_ID"
      exit 1
    fi
  done
}

write_env_file() {
  local env_path="$(pwd)/.env"
  log_warn "Writing .env file for controlled tests only: $env_path"
  {
    echo "M365_TENANT_ID=$TENANT_ID"
    echo "M365_CLIENT_ID=$CLIENT_ID"
    [[ -n "${M365_CLIENT_SECRET:-}" ]] && echo "M365_CLIENT_SECRET=$M365_CLIENT_SECRET"
    [[ -n "${SECRET_EXPIRES_AT:-}" ]] && echo "M365_SECRET_EXPIRES_AT=$SECRET_EXPIRES_AT"
    echo "M365_ONBOARDING_MODE=$MODE"
  } > "$env_path"
  chmod 600 "$env_path" || true
  log_warn "Never commit or share this .env file."
}

print_creation_json() {
  local consent_url created_at
  consent_url="$(admin_consent_url)"
  created_at="$(now_utc)"

  jq -n -c \
    --arg provider "m365" \
    --arg mode "$MODE" \
    --arg tenant "$TENANT_ID" \
    --arg client "$CLIENT_ID" \
    --arg secret "$M365_CLIENT_SECRET" \
    --arg secretDisplayName "$SECRET_DISPLAY_NAME" \
    --arg secretExpiresAt "$SECRET_EXPIRES_AT" \
    --arg createdAt "$created_at" \
    --arg consentUrl "$consent_url" \
    --arg onboardingStatus "ready" \
    --argjson permissions "$(json_array "${PERMISSIONS[@]}")" \
    '{provider:$provider,mode:$mode,m365TenantId:$tenant,m365ClientId:$client,m365ClientSecret:$secret,secretDisplayName:$secretDisplayName,secretExpiresAt:$secretExpiresAt,createdAt:$createdAt,permissionsRequested:$permissions,adminConsentUrl:$consentUrl,onboardingStatus:$onboardingStatus}'
}

print_renew_json() {
  jq -n -c \
    --arg provider "m365" \
    --arg tenant "$TENANT_ID" \
    --arg client "$CLIENT_ID" \
    --arg secret "$M365_CLIENT_SECRET" \
    --arg secretDisplayName "$SECRET_DISPLAY_NAME" \
    --arg secretExpiresAt "$SECRET_EXPIRES_AT" \
    --arg renewedAt "$(now_utc)" \
    --arg onboardingStatus "secret_renewed" \
    '{provider:$provider,m365TenantId:$tenant,m365ClientId:$client,m365ClientSecret:$secret,secretDisplayName:$secretDisplayName,secretExpiresAt:$secretExpiresAt,renewedAt:$renewedAt,onboardingStatus:$onboardingStatus}'
}

main() {
  print_header
  ensure_dependencies
  ensure_tenant_context
  load_permissions_for_mode
  resolve_graph_roles

  if [[ "$VALIDATE_ONLY" == "true" ]]; then
    validate_onboarding || true
    echo "============================================================"
    echo "VALIDATION RESULT (JSON):"
    validation_json
    echo "============================================================"
    exit 0
  fi

  if [[ "$RENEW_SECRET" == "true" ]]; then
    if ! az ad app show --id "$CLIENT_ID" >/dev/null 2>&1; then
      log_err "App Registration not found for client ID: $CLIENT_ID"
      exit 1
    fi
    create_client_secret
    echo
    log_warn "Remove old secrets in Entra only after validating the new credential on the Vulneri platform."
    echo "============================================================"
    echo "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:"
    print_renew_json
    echo "============================================================"
    [[ "$WRITE_ENV_FILE" == "true" ]] && write_env_file
    exit 0
  fi

  create_or_reuse_app
  ensure_service_principal
  configure_permissions
  create_client_secret

  # Try automatic admin consent first. If it does not work, fall back to manual URL.
  try_auto_admin_consent || true

  local attempt
  for attempt in 1 2 3 4 5; do
    if validate_onboarding; then
      break
    fi
    log_warn "Validation status: $VALIDATION_STATUS. Waiting for propagation ($attempt/5)..."
    sleep 8
  done

  if [[ "$VALIDATION_STATUS" != "ready" ]]; then
    manual_admin_consent_loop
  fi

  echo
  echo "============================================================"
  echo "SUCCESS: Microsoft 365 onboarding validated successfully."
  echo "============================================================"
  echo "M365 Tenant ID: $TENANT_ID"
  echo "M365 Client ID: $CLIENT_ID"
  echo "M365 Client Secret: will be displayed only in the JSON below. Save it now."
  echo
  echo "============================================================"
  echo "COPY AND PASTE THE JSON BELOW INTO THE VULNERI PLATFORM:"
  print_creation_json
  echo "============================================================"

  [[ "$WRITE_ENV_FILE" == "true" ]] && write_env_file
}

main "$@"

