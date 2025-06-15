#!/bin/bash
set -e

# Ensure we are in the project root
dirname "${BASH_SOURCE[0]}" | grep -q '^\.' && cd "$(dirname "$0")"

# Check for correct package name
PKG_NAME=$(node -p "require('./package.json').name")
EXPECTED_NAME="@lit-protocol/dcap-qvl-ts"
if [ "$PKG_NAME" != "$EXPECTED_NAME" ]; then
  echo "\033[0;31mERROR: package.json name is '$PKG_NAME', expected '$EXPECTED_NAME'.\033[0m"
  echo "Please update your package.json before publishing."
  exit 1
fi

echo "\033[0;32mBuilding package...\033[0m"
npm run build

echo "\033[0;32mPublishing to NPM as $EXPECTED_NAME...\033[0m"
npm publish --access public

echo "\033[0;32mPublish complete!\033[0m" 