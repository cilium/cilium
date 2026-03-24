#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

make -C pkg/bpf/testdata docker
make -C tools/stackwhere/testdata docker
test -z "$(git status pkg/bpf/testdata --porcelain)" || (echo "please run 'make -C pkg/bpf/testdata docker' and submit your changes"; exit 1)
test -z "$(git status tools/stackwhere/testdata --porcelain)" || (echo "please run 'make -C tools/stackwhere/testdata docker' and submit your changes"; exit 1)
