#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

make generate-bpf

test -z "$(git status bpf/ pkg/ --porcelain)" || (echo "please run 'make generate-bpf' and submit your changes"; exit 1)
