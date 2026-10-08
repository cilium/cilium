#!/usr/bin/env bash

set -e

if grep -r 'log\.' --include=\*.go --exclude-dir={.git,_build,vendor,envoy,contrib} . \
  | grep -v -e logging.go -e pkg/k8s/slim/k8s/apis/util/intstr/intstr.go \
  | grep -F "\n"; then
  echo "found newline(s) in log call(s), please remove ending \n"
  exit 1
fi
