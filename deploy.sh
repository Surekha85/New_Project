#!/bin/bash

set -e

STAGE=$1

if [ -z "$STAGE" ]; then
  echo "❌ Usage: ./deploy.sh [beta|gamma|prod]"
  exit 1
fi

case "$STAGE" in
  beta)
    ACCOUNT_ID="513691871442"
    REGION="us-east-1"
    PROFILE="jobsyme-beta"
    ;;
  gamma)
    ACCOUNT_ID="513691871442"
    REGION="us-east-1"
    PROFILE="jobsyme-gamma"
    ;;
  prod)
    ACCOUNT_ID="513691871442"
    REGION="us-east-1"
    PROFILE="jobsyme-prod"
    ;;
  *)
    echo "❌ Invalid stage: $STAGE. Use beta, gamma, or prod."
    exit 1
    ;;
esac

TEMPLATE_FILE="github-deploy-role.yaml"
TEMP_TEMPLATE=".temp-deploy.yaml"

# Inject account ID dynamically
sed "s/{{ACCOUNT_ID}}/$ACCOUNT_ID/g; s/{{stage}}/$STAGE/g" "$TEMPLATE_FILE" > "$TEMP_TEMPLATE"

# Deploy using stage-specific AWS CLI profile
if [ -z "$CI" ]; then
  # Local deploy using named AWS CLI profile
  aws cloudformation deploy \
    --stack-name github-deploy-role-$STAGE \
    --template-file $TEMP_TEMPLATE \
    --capabilities CAPABILITY_NAMED_IAM \
    --region $REGION \
    --profile jobsyme-$STAGE
else
  # GitHub Actions: use env-based auth (no --profile)
  aws cloudformation deploy \
    --stack-name github-deploy-role-$STAGE \
    --template-file $TEMP_TEMPLATE \
    --capabilities CAPABILITY_NAMED_IAM \
    --region $REGION
fi

# Clean up temporary file
rm $TEMP_TEMPLATE

echo "✅ Deployment to $STAGE complete using profile: $PROFILE"