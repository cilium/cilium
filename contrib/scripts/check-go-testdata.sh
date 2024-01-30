# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

make -C pkg/bpf/testdata build
test -z "$(git status --porcelain)" || (echo "please run 'make -C pkg/bpf/testdata build' and submit your changes"; exit 1)
