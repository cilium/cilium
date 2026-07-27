#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-releases depName=mfridman/tparse
go install github.com/mfridman/tparse@baf229e8494613f134bc0e1f4cb9dc9b12f66442 # v0.14.0
# renovate: datasource=github-releases depName=cilium/go-junit-report/v2/cmd/go-junit-report
go install github.com/cilium/go-junit-report/v2/cmd/go-junit-report@4cdc5c96cb4e406fccf943536b5bfcae7a0fb826 # v2.3.1
