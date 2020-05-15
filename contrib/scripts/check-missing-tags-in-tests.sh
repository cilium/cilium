#!/usr/bin/env bash

files_missing_build_tag="`grep -L -r '// +build' . --include \*_test.go \
    --exclude-dir={.git,_build,vendor,test}`"
if [ -n "$files_missing_build_tag" ]; then
  echo "Test file(s) does not contain a tag privileged_tests or !privileged_tests tags:"
  echo $files_missing_build_tag
  exit 1
fi
