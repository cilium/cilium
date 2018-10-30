#!/usr/bin/env bash

set -e

if grep -L --include \*_test.go '// +build' . -r | grep -v vendor | grep -v test/ ; then
  echo "Test file(s) does not contain a tag privileged_tests or !privileged_tests tags"
  exit 1
fi
