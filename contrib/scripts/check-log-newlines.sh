#!/usr/bin/env bash

set -e

if grep --include \*.go -r 'log\.' ./ \
  | grep -v -e vendor -e envoy -e contrib -e logging.go \
  | grep -F "\n"; then
  echo "found newline(s) in log call(s), please remove ending \n"
  exit 1
fi
