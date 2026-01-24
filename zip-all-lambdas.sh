#!/bin/bash

set -e

APP_DIR="backend/lambda"
BUILD_DIR="lambda_builds"
ZIP_DIR="lambdas"
CACHE_DIR=".lambda_cache"

# Show usage if help requested
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Intelligently builds only changed Lambda functions"
  echo ""
  echo "Options:"
  echo "  --force, -f    Force rebuild all Lambda functions"
  echo "  --help, -h     Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0             # Build only changed Lambdas"
  echo "  $0 --force     # Force rebuild all Lambdas"
  exit 0
fi

# Parse command line arguments
FORCE_REBUILD=false
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
  FORCE_REBUILD=true
  echo "🔄 Force rebuild requested - will rebuild all Lambda functions"
fi

# Create necessary directories
mkdir -p "$BUILD_DIR"
mkdir -p "$ZIP_DIR"
mkdir -p "$CACHE_DIR"

if [ "$FORCE_REBUILD" = true ]; then
  echo "📦 Force rebuilding ALL Lambda functions in ${APP_DIR}..."
  rm -rf "$CACHE_DIR"/*.hash 2>/dev/null || true
else
  echo "📦 Intelligently packaging Lambda functions in ${APP_DIR}..."
  echo "🔍 Checking for changes since last build..."
fi

# Function to calculate directory hash
calculate_dir_hash() {
  local dir="$1"
  find "$dir" -type f \( -name "*.py" -o -name "requirements.txt" \) -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1
}

# Function to check if lambda needs rebuilding
needs_rebuild() {
  local lambda_name="$1"
  local src_path="$2"
  local zip_file="${ZIP_DIR}/${lambda_name}_lambda.zip"
  local cache_file="${CACHE_DIR}/${lambda_name}.hash"
  
  # Force rebuild if requested
  if [ "$FORCE_REBUILD" = true ]; then
    echo "🔄 $lambda_name: Force rebuilding"
    calculate_dir_hash "$src_path" > "$cache_file"
    return 0
  fi
  
  # If zip doesn't exist, needs rebuild
  if [ ! -f "$zip_file" ]; then
    echo "📦 $lambda_name: ZIP file missing"
    return 0
  fi
  
  # Calculate current hash
  local current_hash=$(calculate_dir_hash "$src_path")
  
  # If cache doesn't exist, needs rebuild
  if [ ! -f "$cache_file" ]; then
    echo "📦 $lambda_name: No cache found"
    echo "$current_hash" > "$cache_file"
    return 0
  fi
  
  # Compare hashes
  local cached_hash=$(cat "$cache_file")
  if [ "$current_hash" != "$cached_hash" ]; then
    echo "📦 $lambda_name: Source files changed"
    echo "$current_hash" > "$cache_file"
    return 0
  fi
  
  echo "✅ $lambda_name: No changes detected, skipping"
  return 1
}

changed_count=0
skipped_count=0

for dir in "$APP_DIR"/*/; do
  LAMBDA_NAME=$(basename "$dir")
  SRC_PATH="${APP_DIR}/${LAMBDA_NAME}"
  DEST_PATH="${BUILD_DIR}/${LAMBDA_NAME}"
  ZIP_FILE="${ZIP_DIR}/${LAMBDA_NAME}_lambda.zip"

  # Check if this lambda needs rebuilding
  if ! needs_rebuild "$LAMBDA_NAME" "$SRC_PATH"; then
    skipped_count=$((skipped_count + 1))
    continue
  fi

  echo "🔧 Building: ${LAMBDA_NAME} → ${ZIP_FILE}"
  changed_count=$((changed_count + 1))

  # Clean up existing build for this lambda
  if [ -d "$DEST_PATH" ]; then
    rm -rf "$DEST_PATH" 2>/dev/null || sudo rm -rf "$DEST_PATH"
  fi
  
  mkdir -p "$DEST_PATH"

  # Copy all files (not just Python files)
  cp -r "$SRC_PATH"/* "$DEST_PATH/" 2>/dev/null || {
    echo "⚠️  No files found in $SRC_PATH — skipping."
    continue
  }
  
  # Remove any unnecessary files
  find "$DEST_PATH" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
  find "$DEST_PATH" -name "*.pyc" -delete 2>/dev/null || true
  find "$DEST_PATH" -name ".DS_Store" -delete 2>/dev/null || true

  # Install dependencies if requirements.txt exists
  if [ -f "$SRC_PATH/requirements.txt" ]; then
    echo "📦 Installing dependencies for $LAMBDA_NAME using Docker..."
    docker run --rm -v "$(pwd)/$SRC_PATH":/var/task -v "$(pwd)/$DEST_PATH":/var/output \
      --platform linux/amd64 \
      --entrypoint="" \
      public.ecr.aws/lambda/python:3.10 \
      pip install -r /var/task/requirements.txt -t /var/output
    
    # Fix permissions after Docker (Docker may create files as root)
    sudo chown -R "$(whoami):$(id -gn)" "$DEST_PATH" 2>/dev/null || true
  fi

  # Create the ZIP file
  cd "$DEST_PATH"
  zip -r "../../${ZIP_FILE}" . > /dev/null
  cd - > /dev/null

  # Clean up the build directory for this lambda
  rm -rf "$DEST_PATH" 2>/dev/null || sudo rm -rf "$DEST_PATH"
done

# Summary
if [ $changed_count -eq 0 ] && [ $skipped_count -gt 0 ]; then
  echo "🎉 All $skipped_count Lambda functions are up to date! No rebuilding needed."
elif [ $changed_count -gt 0 ]; then
  echo "✅ Rebuilt $changed_count changed Lambda(s), skipped $skipped_count unchanged Lambda(s)"
  echo "📦 Updated ZIP files in '${ZIP_DIR}/'"
else
  echo "✅ No Lambda functions found to process"
fi
