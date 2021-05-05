#!/bin/sh

set -x
set -e

cilium hubble enable

cilium status --wait

cilium hubble port-forward&

sleep 5

cilium connectivity test --test '!/pod-to-local-nodeport' --all-flows

cilium status
