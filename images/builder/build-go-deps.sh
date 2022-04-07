#!/bin/bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

mkdir /src

cd /src

go install github.com/gordonklaus/ineffassign@1003c8bd00dc2869cb5ca5282e6ce33834fed514
