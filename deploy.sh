#!/bin/bash

set -e

STAGE=$1

if [ -z "$STAGE" ]; then
  echo "Usage: ./deploy.sh alpha"
  exit 1
fi

case "$STAGE" in
  alpha)
    ACCOUNT_ID="007326679429"
    REGION="us-east-1"
    PROFILE="alpha"
    ;;
  *)
    echo "Invalid stage: $STAGE. Only 'alpha' is supported."
    exit 1
    ;;
esac

TEMPLATE_FILE="github-deploy-role.yaml"
TEMP_TEMPLATE=".temp-deploy.yaml"

# Inject account ID and stage
sed "s/{{ACCOUNT_ID}}/$ACCOUNT_ID/g; s/{{stage}}/$STAGE/g" \
  "$TEMPLATE_FILE" > "$TEMP_TEMPLATE"

# Deploy
if [ -z "$CI" ]; then
  # Local deploy (AWS CLI profile)
  aws cloudformation deploy \
    --stack-name github-deploy-role-$STAGE \
    --template-file "$TEMP_TEMPLATE" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION" \
    --profile "$PROFILE"
else
  # GitHub Actions (OIDC / env-based auth)
  aws cloudformation deploy \
    --stack-name github-deploy-role-$STAGE \
    --template-file "$TEMP_TEMPLATE" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION"
fi

rm "$TEMP_TEMPLATE"

echo "✅ Deployment to $STAGE complete"
