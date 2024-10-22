#!/usr/bin/env bash

g=$(grep -Elr '^//go:build.*(privileged_tests|integration_tests)' . --include \*_test.go \
    --exclude-dir={.git,_build,vendor,test})

if [ -n "$g" ]; then
  echo "Test file(s) containing deprecated build tag:"
  echo $g
  echo
  echo "Use testutils.{Privileged,Integration}{Check,Test} for marking tests."
  exit 1
fi
