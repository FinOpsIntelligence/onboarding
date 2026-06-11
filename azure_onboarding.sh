#!/usr/bin/env bash
# ==============================================================================
# FinOps Intelligence Azure Onboarding Bootstrap Script
# ==============================================================================
# This script is designed to run in Azure Cloud Shell (Bash) and automate:
#   1. Obtaining the active Tenant ID and Subscription ID.
#   2. Creating a Service Principal (App Registration) for FinOps Intelligence.
#   3. Assigning the "Reader" permission on the Subscription scope.
#   4. Assigning the "Cost Management Reader" permission on the Subscription scope.
#   5. Generating a JSON block with the credentials to be pasted into the Portal.
# ==============================================================================

set -euo pipefail

DISPLAY_NAME="FinOps-Intelligence-Portal"

echo -e "\e[1;36m== FinOps Intelligence Azure Setup ==\e[0m"
echo "Fetching active account context..."

# 1) Get Tenant ID and Subscription ID
TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || echo "")
SUB_ID=$(az account show --query id -o tsv 2>/dev/null || echo "")
SUB_NAME=$(az account show --query name -o tsv 2>/dev/null || echo "")

if [ -z "$TENANT_ID" ] || [ -z "$SUB_ID" ]; then
  echo -e "\e[1;31mError: Could not retrieve Azure account context.\e[0m"
  echo "Make sure you are logged in and have an active subscription selected."
  exit 1
fi

echo -e "  Tenant ID:           \e[1;33m$TENANT_ID\e[0m"
echo -e "  Active Subscription: \e[1;32m$SUB_NAME ($SUB_ID)\e[0m"
echo ""

# 2) Create Application Registration and Service Principal in Entra ID
echo "Creating Service Principal and Credentials..."
SP_INFO=""

# Try using the quick create-for-rbac command
if SP_INFO=$(az ad sp create-for-rbac --name "$DISPLAY_NAME" --role "Reader" --scopes "/subscriptions/$SUB_ID" --output json 2>/dev/null); then
  CLIENT_ID=$(echo "$SP_INFO" | jq -r .appId)
  CLIENT_SECRET=$(echo "$SP_INFO" | jq -r .password)
  echo -e "  \e[1;32m✓ Service Principal successfully created via RBAC.\e[0m"
else
  echo "Warning: az ad sp create-for-rbac failed or is restricted. Trying manual method..."
  
  # Create the application registration
  APP_JSON=$(az ad app create --display-name "$DISPLAY_NAME" --output json)
  CLIENT_ID=$(echo "$APP_JSON" | jq -r .appId)
  
  # Create the corresponding Service Principal
  az ad sp create --id "$CLIENT_ID" --output none
  
  # Generate the client secret
  SECRET_JSON=$(az ad app credential reset --id "$CLIENT_ID" --output json)
  CLIENT_SECRET=$(echo "$SECRET_JSON" | jq -r .password)
  
  # Assign the Reader permission
  az role assignment create --assignee "$CLIENT_ID" --role "Reader" --scope "/subscriptions/$SUB_ID" --output none
  echo -e "  \e[1;32m✓ Service Principal and 'Reader' role manually created.\e[0m"
fi

# 3) Assign the Cost Management Reader permission
echo "Assigning 'Cost Management Reader' role on the subscription..."
if az role assignment create --assignee "$CLIENT_ID" --role "Cost Management Reader" --scope "/subscriptions/$SUB_ID" --output none 2>/dev/null; then
  echo -e "  \e[1;32m✓ 'Cost Management Reader' role assigned successfully.\e[0m"
else
  echo -e "  \e[1;33m⚠️ Warning: Failed to assign 'Cost Management Reader' role.\e[0m"
  echo "  Make sure your user account has 'Owner' or 'User Access Administrator' permissions on this subscription."
  echo "  You can assign this role manually in the Azure Portal after onboarding if needed."
fi

# 4) Output the final JSON credentials block
echo ""
echo -e "\e[1;32m=== COPY THE ENTIRE JSON BLOCK BELOW AND PASTE IT IN FINOPS INTELLIGENCE ===\e[0m"
cat <<EOF
{
  "tenantId": "$TENANT_ID",
  "clientId": "$CLIENT_ID",
  "clientSecret": "$CLIENT_SECRET",
  "subscriptionId": "$SUB_ID"
}
EOF
echo -e "\e[1;32m============================================================================\e[0m"
echo ""
echo "Setup completed successfully."
