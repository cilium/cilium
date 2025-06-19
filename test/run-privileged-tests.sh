#!/bin/bash
# Script to run only tests that call PrivilegedTest

set -e

# Find all test files containing PrivilegedTest calls
echo "Finding test files with PrivilegedTest calls..."
# shellcheck disable=SC2046
TEST_FILES=$(grep -l "PrivilegedTest" $(find . -name "*_test.go"))

# Extract test function names from these files
TEST_PATTERN=""
for file in $TEST_FILES; do
  # Extract test functions that call PrivilegedTest
  funcs=$(grep -B 1 "PrivilegedTest" "$file" | grep -o "func Test[a-zA-Z0-9_]*" | sed 's/func //')
  for func in $funcs; do
    if [ -z "$TEST_PATTERN" ]; then
      TEST_PATTERN="$func"
    else
      TEST_PATTERN="$TEST_PATTERN|$func"
    fi
  done
done

if [ -z "$TEST_PATTERN" ]; then
  echo "No privileged tests found."
  exit 1
fi

TESTPKGS=${TESTPKGS:-"./..."}

${GO_TEST} "${TESTPKGS}" -run "$TEST_PATTERN" "$@"
