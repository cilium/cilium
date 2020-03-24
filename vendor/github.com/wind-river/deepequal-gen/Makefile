# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Kubernetes Authors
# Copyright 2019 Wind River Systems, Inc.

TOOL=deepequal-gen
LOGLEVEL?=9

fmt:
	go fmt ./...
vet: fmt
	go vet ./...

test: vet
	@go build -o /tmp/$(TOOL)
	PKGS=$$(go list ./output_tests/...  | paste -sd' ' -); \
	/tmp/$(TOOL) --logtostderr --v=${LOGLEVEL} -i github.com/cilium/cilium/pkg/k8s/types -O zz_generated.deepequals --bounding-dirs github.com/cilium/cilium/pkg/k8s/types --go-header-file /home/aanm/git-repos/go/src/github.com/cilium/cilium/hack/custom-boilerplate.go.txt

