# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Kubernetes Authors
# Copyright 2019 Wind River Systems, Inc.

TOOL=deepequal-gen
LOGLEVEL?=0

fmt:
	go fmt ./...
vet: fmt
	go vet ./...

test: vet
	@if ! git diff --quiet HEAD; then \
	    echo "FAIL: git client is not clean"; \
	    false; \
	fi
	@go build -o /tmp/$(TOOL)
	$(eval TMPDIR := $(shell mktemp -d))
	PKGS=$$(go list ./output_tests/...  | paste -sd' ' -); \
	/tmp/$(TOOL) --logtostderr --v=${LOGLEVEL} -i $$(echo $$PKGS | sed 's/ /,/g') -O zz_generated -h hack/boilerplate.txt --output-base $(TMPDIR)
	cp -r "$(TMPDIR)/github.com/cilium/deepequal-gen/." ./
	rm -rf "$(TMPDIR)"
	@if ! git diff --quiet HEAD; then \
		echo "FAIL: output files changed; please verify output_tests.diff"; \
		git diff > output_tests.diff; \
		false; \
	else \
		echo "SUCCESS: no differences in generated output"; \
	fi

