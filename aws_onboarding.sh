#!/usr/bin/env bash
# ==============================================================================
# FinOps Intelligence AWS Onboarding Bootstrap Script
# ==============================================================================
# This script is designed to run in AWS CloudShell (Bash) and automate:
#   1. Fetching the active AWS Account ID.
#   2. Creating an IAM User (FinOps-Intelligence-Portal).
#   3. Attaching the 'ReadOnlyAccess' and 'SecurityAudit' managed policies.
#   4. Attaching a 'DenySensitive' inline policy to restrict access to sensitive data (S3 objects, secrets, decrypt keys).
#   5. Creating programmatic Access Keys for this IAM User.
#   6. Generating a JSON block with the credentials to be pasted into the Portal.
# ==============================================================================

set -euo pipefail

IAM_USER_NAME="FinOps-Intelligence-Portal"

echo -e "\e[1;36m== FinOps Intelligence AWS Setup ==\e[0m"
echo "Fetching active AWS account context..."

# 1) Get Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")

if [ -z "$ACCOUNT_ID" ]; then
  echo -e "\e[1;31mError: Could not retrieve AWS account context.\e[0m"
  echo "Make sure you have active credentials and permission to call sts:GetCallerIdentity."
  exit 1
fi

echo -e "  AWS Account ID: \e[1;32m$ACCOUNT_ID\e[0m"
echo ""

# Cleanup existing user if it exists to ensure fresh credentials
if aws iam get-user --user-name "$IAM_USER_NAME" >/dev/null 2>&1; then
  echo "IAM User '$IAM_USER_NAME' already exists. Cleaning up existing resources..."
  
  # List and delete all access keys
  for key in $(aws iam list-access-keys --user-name "$IAM_USER_NAME" --query "AccessKeyMetadata[].AccessKeyId" --output text 2>/dev/null || true); do
    if [ -n "$key" ]; then
      echo "Deleting access key: $key"
      aws iam delete-access-key --user-name "$IAM_USER_NAME" --access-key-id "$key" >/dev/null
    fi
  done
  
  # Detach managed policies
  for policy in $(aws iam list-attached-user-policies --user-name "$IAM_USER_NAME" --query "AttachedPolicies[].PolicyArn" --output text 2>/dev/null || true); do
    if [ -n "$policy" ]; then
      echo "Detaching policy: $policy"
      aws iam detach-user-policy --user-name "$IAM_USER_NAME" --policy-arn "$policy" >/dev/null
    fi
  done

  # Delete inline policies
  for policy in $(aws iam list-user-policies --user-name "$IAM_USER_NAME" --query "PolicyNames[]" --output text 2>/dev/null || true); do
    if [ -n "$policy" ]; then
      echo "Deleting inline policy: $policy"
      aws iam delete-user-policy --user-name "$IAM_USER_NAME" --policy-name "$policy" >/dev/null
    fi
  done
  
  # Delete user
  echo "Deleting user: $IAM_USER_NAME"
  aws iam delete-user --user-name "$IAM_USER_NAME" >/dev/null
fi

# 2) Create IAM User
echo "Creating IAM User '$IAM_USER_NAME'..."
aws iam create-user --user-name "$IAM_USER_NAME" >/dev/null
echo -e "  \e[1;32m✓ User successfully created.\e[0m"

# 3) Attach ReadOnlyAccess & SecurityAudit Managed Policies
echo "Attaching 'ReadOnlyAccess' policy to '$IAM_USER_NAME'..."
aws iam attach-user-policy --user-name "$IAM_USER_NAME" --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess" >/dev/null
echo -e "  \e[1;32m✓ 'ReadOnlyAccess' policy attached successfully.\e[0m"

echo "Attaching 'SecurityAudit' policy to '$IAM_USER_NAME'..."
aws iam attach-user-policy --user-name "$IAM_USER_NAME" --policy-arn "arn:aws:iam::aws:policy/SecurityAudit" >/dev/null
echo -e "  \e[1;32m✓ 'SecurityAudit' policy attached successfully.\e[0m"

# 4) Attach DenySensitive Inline Policy for Security Hardening
echo "Attaching 'DenySensitive' inline policy to '$IAM_USER_NAME'..."
DENY_POLICY_JSON='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySensitive",
      "Effect": "Deny",
      "Resource": "*",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectAcl",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:GetParameterHistory"
      ]
    }
  ]
}'
aws iam put-user-policy --user-name "$IAM_USER_NAME" --policy-name "DenySensitiveData" --policy-document "$DENY_POLICY_JSON" >/dev/null
echo -e "  \e[1;32m✓ 'DenySensitive' inline policy attached successfully.\e[0m"

# 5) Create Access Key and Secret Key
echo "Generating API access keys..."
KEY_JSON=$(aws iam create-access-key --user-name "$IAM_USER_NAME" --output json)
ACCESS_KEY_ID=$(echo "$KEY_JSON" | jq -r .AccessKey.AccessKeyId)
SECRET_ACCESS_KEY=$(echo "$KEY_JSON" | jq -r .AccessKey.SecretAccessKey)

# 6) Output the final JSON credentials block
echo ""
echo -e "\e[1;32m=== COPY THE ENTIRE JSON BLOCK BELOW AND PASTE IT IN FINOPS INTELLIGENCE ===\e[0m"
cat <<EOF
{
  "accessKeyId": "$ACCESS_KEY_ID",
  "secretAccessKey": "$SECRET_ACCESS_KEY"
}
EOF
echo -e "\e[1;32m============================================================================\e[0m"
echo ""
echo "Setup completed successfully."
