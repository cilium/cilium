#!/bin/sh

set -x
set -e


cilium connectivity test --all-flows
cilium status
cilium clustermesh status
cilium clustermesh vm status
