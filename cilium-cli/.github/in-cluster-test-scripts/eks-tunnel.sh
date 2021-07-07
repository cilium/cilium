#!/bin/sh

set -x
set -e

# Enable Relay
cilium hubble enable

# Wait for Cilium status to be ready
cilium status --wait

# Port forward Relay
cilium hubble port-forward&
sleep 10s

# Run connectivity test
cilium connectivity test --debug --all-flows

# Retrieve Cilium  status
cilium status
