#!/bin/sh

set -x
set -e

# Run connectivity test
cilium connectivity test --debug --all-flows

# Retrieve Cilium status
cilium status
cilium clustermesh status
cilium clustermesh vm status
