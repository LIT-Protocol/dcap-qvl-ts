#!/bin/bash
set -e

# Ensure we are in the project root
dirname "${BASH_SOURCE[0]}" | grep -q '^\.' && cd "$(dirname "$0")"

# Check for correct package name
PKG_NAME=$(node -p "require('./package.json').name")
EXPECTED_NAME="@lit-protocol/dcap-qvl-ts"
if [ "$PKG_NAME" != "$EXPECTED_NAME" ]; then
  echo "ERROR: package.json name is '$PKG_NAME', expected '$EXPECTED_NAME'."
  echo "Please update your package.json before publishing."
  exit 1
fi

echo "Building package..."
npm run build

echo "Publishing to NPM as $EXPECTED_NAME..."
npm publish --access public

echo "Publish complete!" 