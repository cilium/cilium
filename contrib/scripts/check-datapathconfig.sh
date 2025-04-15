#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

make -C bpf generate

test -z "$(git status bpf/ --porcelain)" || (echo "please run 'make -C bpf generate' and submit your changes"; exit 1)
