#!/bin/bash

set -x
set -e

# Run connectivity test
cilium connectivity test --debug --all-flows --collect-sysdump-on-failure --external-target google.com.

# Run performance test
cilium connectivity perf --duration 1s
