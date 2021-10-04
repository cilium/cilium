#!/bin/sh

set -x
set -e

# Enable Relay
cilium hubble enable

# Port forward Relay
cilium hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium connectivity test --debug --all-flows

# Retrieve Cilium status
cilium status
