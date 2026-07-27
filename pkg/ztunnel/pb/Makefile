# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# This Makefile is expected to run inside the cilium-builder image to generate
# the proto files. Run `make proto` on ./Makefile to invoke run this inside a
# a container.

PROTOC ?= protoc

ZTUNNEL_PROTO_SOURCES := \
	./ca_ztunnel.proto \
	./workload_ztunnel.proto \
	./zds_ztunnel.proto

ZTUNNEL_GO_TARGETS := $(ZTUNNEL_PROTO_SOURCES:.proto=.pb.go) $(ZTUNNEL_PROTO_SOURCES:.proto=.pb.json.go)

ZTUNNEL_PROTO_PATH := .

ZTUNNEL_PROTOC_PLUGINS := --plugin=$(GOPATH)/bin/protoc-gen-doc
ZTUNNEL_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go-grpc
ZTUNNEL_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go-json
ZTUNNEL_PROTOC_PLUGINS += --plugin=$(GOPATH)/bin/protoc-gen-go

.PHONY: all
all:
	@echo NOTE: The warning about package github.com/golang/protobuf/protoc-gen-go/generator can be ignored
	$(QUIET)$(PROTOC) $(ZTUNNEL_PROTOC_PLUGINS) -I $(ZTUNNEL_PROTO_PATH) \
		--doc_out=./ \
		--doc_opt=markdown,README.md,source_relative \
		--go_out=paths=source_relative:. \
		--go-grpc_out=require_unimplemented_servers=false,paths=source_relative:. \
		--go-json_out=orig_name=true,paths=source_relative:. \
  		$(ZTUNNEL_PROTO_SOURCES)
