#!/bin/sh

set -x
set -e

# Run connectivity test
cilium connectivity test --debug --all-flows
