#!/bin/bash

set -e

STAGE=$1

if [ -z "$STAGE" ]; then
  echo "❌ Usage: ./deploy-assistants.sh [beta|gamma|prod]"
  exit 1
fi

case "$STAGE" in
  beta)
    ACCOUNT_ID="${ACCOUNT_ID:-513691871442}"
    REGION="us-east-1"
    PROFILE="jobsyme-beta"
    ;;
  gamma)
    ACCOUNT_ID="${ACCOUNT_ID:-513691871442}"
    REGION="us-east-1"
    PROFILE="jobsyme-gamma"
    ;;
  prod)
    ACCOUNT_ID="${ACCOUNT_ID:-513691871442}"
    REGION="us-east-1"
    PROFILE="jobsyme-prod"
    ;;
  *)
    echo "❌ Invalid stage: $STAGE. Use beta, gamma, or prod."
    exit 1
    ;;
esac


STACK_NAME="jobsyme-assistants-${STAGE}"
FINAL_TEMPLATE="infra/assistants.yaml"
S3_BUCKET="jobsyme-assitants-infra-${STAGE}"
S3_PREFIX="jobsyme-assitants/$STAGE"
PACKAGED_TEMPLATE=".packaged-auth-template.yaml"

# Helper function to run AWS CLI with or without --profile
aws_cmd() {
  if [ -z "$CI" ]; then
    aws "$@" --profile "$PROFILE"
  else
    aws "$@"
  fi
}

# 📦 Step 2: Intelligently package changed Lambda functions
echo "📦 Checking and zipping changed Lambda functions..."
./zip-all-lambdas.sh || { echo "❌ Failed to zip Lambda functions."; exit 1; }

# 🪣 Step 3: Ensure the S3 bucket exists
if ! aws_cmd s3 ls "s3://${S3_BUCKET}" --region "$REGION" > /dev/null 2>&1; then
  echo "Creating missing S3 bucket: $S3_BUCKET"
  aws_cmd s3 mb "s3://$S3_BUCKET" --region "$REGION" || { echo "❌ Failed to create S3 bucket."; exit 1; }
fi

# � Step : Upload Lambda zip files to S3
echo "📤 Uploading Lambda zip files to S3..."
if [ -d "lambdas" ]; then
  for zip_file in lambdas/*.zip; do
    if [ -f "$zip_file" ]; then
      filename=$(basename "$zip_file")
      echo "Uploading: $filename"
      aws_cmd s3 cp "$zip_file" "s3://${S3_BUCKET}/${S3_PREFIX}/${filename}" --region "$REGION" || { echo "❌ Failed to upload $zip_file"; exit 1; }
    fi
  done
  echo "All Lambda zips uploaded to S3"
else
  echo "No lambdas directory found. Skipping zip upload."
fi


# 📦 Step 4: Package the merged stack (CloudFormation will handle S3 uploads)
echo "📦 Packaging template..."
aws_cmd cloudformation package \
  --template-file "$FINAL_TEMPLATE" \
  --s3-bucket "$S3_BUCKET" \
  --s3-prefix "$S3_PREFIX" \
  --output-template-file "$PACKAGED_TEMPLATE" \
  --region "$REGION" || { echo "❌ Failed to package CloudFormation template."; exit 1; }

# 🚀 Step 5: Deploy the packaged stack
echo "🚀 Deploying stack: $STACK_NAME..."
aws_cmd cloudformation deploy \
  --template-file "$PACKAGED_TEMPLATE" \
  --stack-name "$STACK_NAME" \
  --parameter-overrides Stage="$STAGE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --s3-bucket "$S3_BUCKET" \
  --region "$REGION" || { echo "❌ Failed to deploy CloudFormation stack."; exit 1; }

# 🧹 Step 6: Clean up
rm -f "$PACKAGED_TEMPLATE"

echo "✅ Deployment successful: $STACK_NAME"
