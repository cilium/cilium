# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

PROTOC ?= protoc

HUBBLE_PROTO_SOURCES := \
	./flow/flow.proto \
	./peer/peer.proto \
	./observer/observer.proto \
	./relay/relay.proto

HUBBLE_GO_TARGETS := $(HUBBLE_PROTO_SOURCES:.proto=.pb.go) $(HUBBLE_PROTO_SOURCES:.proto=.pb.validate.go)

HUBBLE_PROTO_PATH := .

HUBBLE_PROTOC_PLUGINS := --plugin=../../tools/protoc-gen-go-grpc
HUBBLE_PROTOC_PLUGINS += --plugin=../../tools/protoc-gen-go-json
HUBBLE_PROTOC_PLUGINS += --plugin=../../tools/protoc-gen-validate

PROTO_DEPS = \
	-I external

$(HUBBLE_GO_TARGETS): $(HUBBLE_PROTO_SOURCES) Makefile deps
	@echo NOTE: The warning about package github.com/golang/protobuf/protoc-gen-go/generator can be ignored; \
	$(QUIET)set -e; \
	for proto in $(HUBBLE_PROTO_SOURCES) ; do \
		$(PROTOC) $(HUBBLE_PROTOC_PLUGINS) -I $(HUBBLE_PROTO_PATH) $(PROTO_DEPS) \
			--go_out=paths=source_relative:. \
			--go-grpc_out=paths=source_relative:. \
			--go-json_out=orig_name:. \
			--validate_out=lang=go,paths=source_relative:. \
			$${proto}; \
	done

.PHONY: all
all: $(HUBBLE_GO_TARGETS)

.PHONY: clean
clean:
	rm -f $(HUBBLE_GO_TARGETS)

.PHONY: deps
deps:
	@$(PROTOC) --version | grep 3.12.4 || (echo "Error: protoc 3.12.4 is required" && exit 1)
