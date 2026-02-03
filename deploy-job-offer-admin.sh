#!/bin/bash
set -e

STAGE=$1

if [ -z "$STAGE" ]; then
  echo "❌ Usage: ./deploy-job-offer-admin.sh alpha"
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

# DynamoDB table names (stage-safe)
CandidatesTableName="jobsyme-${STAGE}-candidates"
AssistantsTableName="jobsyme-${STAGE}-assistants"
JobApplicationsTableName="jobsyme-${STAGE}-job-applications"
PortfolioTableName="jobsyme-${STAGE}-portfolio"
GitHubActivitiesTableName="jobsyme-${STAGE}-github-activities"
LinkedInActivitiesTableName="jobsyme-${STAGE}-linkedin-activities"

STACK_NAME="admin-${STAGE}"
FINAL_TEMPLATE="infra/assistants.yaml"
S3_BUCKET="admin-infra-${STAGE}"
S3_PREFIX="admin/$STAGE"
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


# 📦 Step 4: Package the merged stack (CloudFormation will handle S3 uploads)
echo "📦 Packaging template..."
aws_cmd cloudformation package \
  --template-file "$FINAL_TEMPLATE" \
  --s3-bucket "$S3_BUCKET" \
  --s3-prefix "$S3_PREFIX" \
  --output-template-file "$PACKAGED_TEMPLATE" \
  --region "$REGION" || { echo "❌ Failed to package CloudFormation template."; exit 1; }

VERSION=$(date +"%d/%m/%Y %H:%M")
# 🚀 Step 5: Deploy the packaged stack
echo "🚀 Deploying stack: $STACK_NAME..."
aws_cmd cloudformation deploy \
  --template-file "$PACKAGED_TEMPLATE" \
  --stack-name "$STACK_NAME" \
  --parameter-overrides \
    Stage="$STAGE" \
    AdminApiDeploymentVersion="$VERSION" \
  --capabilities CAPABILITY_NAMED_IAM \
  --s3-bucket "$S3_BUCKET" \
  --region "$REGION" || { echo "❌ Failed to deploy CloudFormation stack."; exit 1; }

 echo "Deployed at $VERSION" 
# 🧹 Step 6: Clean up
rm -f "$PACKAGED_TEMPLATE"

echo "✅ Deployment successful: $STACK_NAME"
