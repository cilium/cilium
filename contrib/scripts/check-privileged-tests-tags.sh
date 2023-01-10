#!/usr/bin/env bash

g=$(grep -Elr '^//go:build.*privileged_tests' . --include \*_test.go \
    --exclude-dir={.git,_build,vendor,test})

if [ -n "$g" ]; then
  echo "Test file(s) containing deprecated privileged_tests tag:"
  echo $g
  echo
  echo "Use testutils.Privileged{Check,Test} for marking privileged tests."
  exit 1
fi
