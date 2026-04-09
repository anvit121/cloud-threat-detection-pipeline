#!/usr/bin/env bash
# deploy.sh - Builds and deploys the Cloud Threat Detection Pipeline
# Use: ./scripts/deploy.sh [environment] [aws-profile]
# Eg: ./scripts/deploy.sh prod my-aws-profile

set -euo pipefail

ENVIRONMENT=${1:-dev}
AWS_PROFILE=${2:-default}
AWS_REGION=${3:-us-east-1}
STACK_NAME="cloud-threat-detection-${ENVIRONMENT}"
LAMBDA_CODE_BUCKET="${LAMBDA_CODE_BUCKET:-}"

echo "=================================================="
echo " Cloud Threat Detection - Deploy Script"
echo " Environment : ${ENVIRONMENT}"
echo " AWS Profile : ${AWS_PROFILE}"
echo " Region      : ${AWS_REGION}"
echo "=================================================="

# Require S3 bucket
if [ -z "${LAMBDA_CODE_BUCKET}" ]; then
  echo "ERROR: LAMBDA_CODE_BUCKET environment variable is required"
  echo "  export LAMBDA_CODE_BUCKET=your-bucket-name"
  exit 1
fi

# Require alert email
ALERT_EMAIL=${ALERT_EMAIL:-}
if [ -z "${ALERT_EMAIL}" ]; then
  echo "ERROR: ALERT_EMAIL environment variable is required"
  echo "  export ALERT_EMAIL=security@yourcompany.com"
  exit 1
fi

echo ""
echo ">>> [1/5] Running tests..."
PYTHONPATH=src pytest tests/unit/ -q --tb=short
echo "✓ Tests passed"

echo ""
echo ">>> [2/5] Building Lambda package..."
rm -rf .build && mkdir -p .build/package
pip install boto3 botocore --target .build/package -q
cp -r src/* .build/package/
cd .build/package && zip -r ../../lambda-threat-detection.zip . -q && cd ../..
echo "✓ Lambda package created ($(du -sh lambda-threat-detection.zip | cut -f1))"

echo ""
echo ">>> [3/5] Uploading Lambda package to S3..."
aws s3 cp lambda-threat-detection.zip \
  "s3://${LAMBDA_CODE_BUCKET}/lambda/threat-detection.zip" \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}"
echo "✓ Uploaded to s3://${LAMBDA_CODE_BUCKET}/lambda/threat-detection.zip"

echo ""
echo ">>> [4/5] Deploying CloudFormation stack..."
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/threat-detection-stack.yaml \
  --stack-name "${STACK_NAME}" \
  --parameter-overrides \
    "Environment=${ENVIRONMENT}" \
    "AlertEmailAddress=${ALERT_EMAIL}" \
    "LambdaCodeBucket=${LAMBDA_CODE_BUCKET}" \
    "BaselineRegions=${BASELINE_REGIONS:-us-east-1,us-west-2}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}"
echo "✓ CloudFormation stack deployed"

echo ""
echo ">>> [5/5] Updating Lambda function code..."
aws lambda update-function-code \
  --function-name "cloud-threat-detection-${ENVIRONMENT}" \
  --s3-bucket "${LAMBDA_CODE_BUCKET}" \
  --s3-key "lambda/threat-detection.zip" \
  --profile "${AWS_PROFILE}" \
  --region "${AWS_REGION}" \
  --output text --query 'FunctionArn'
echo "✓ Lambda updated"

echo ""
echo "=================================================="
echo " DEPLOYMENT COMPLETE"
echo " Stack: ${STACK_NAME}"
echo " Check CloudFormation console for stack outputs"
echo "=================================================="

# Clean up
rm -f lambda-threat-detection.zip
rm -rf .build