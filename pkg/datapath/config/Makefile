# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# This Makefile is expected to run inside the cilium-builder image to generate
# the proto files.

PROTOC ?= protoc

CONFIG_PROTOC_PLUGINS := --plugin=$(GOPATH)/bin/protoc-gen-docMakefile
CONFIG_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go-grpc
CONFIG_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go-json
CONFIG_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go
CONFIG_DIR := ./latest

.PHONY: proto
proto:
	$(QUIET)set -e; \
	echo Generating config proto && \
	$(PROTOC) $(CONFIG_PROTOC_PLUGINS) -I $(CONFIG_DIR) \
		--doc_out=$(CONFIG_DIR) \
		--doc_opt=markdown,README.md,source_relative \
		--go_out=paths=source_relative:$(CONFIG_DIR) \
		--go-grpc_out=require_unimplemented_servers=false,paths=source_relative:$(CONFIG_DIR) \
		--go-json_out=orig_name=true,paths=source_relative:$(CONFIG_DIR) \
		$(CONFIG_DIR)/*.proto; \
