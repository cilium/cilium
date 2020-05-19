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

HUBBLE_PROTOC_PLUGINS := --plugin=../../tools/protoc-gen-go
HUBBLE_PROTOC_PLUGINS += --plugin=../../tools/protoc-gen-go-json
HUBBLE_PROTOC_PLUGINS += --plugin=../../tools/protoc-gen-validate

PROTO_DEPS = \
	-I external

RAW_GO_MAPPINGS += google/protobuf/timestamp.proto=github.com/golang/protobuf/ptypes/timestamp/
RAW_GO_MAPPINGS += flow/flow.proto=github.com/cilium/cilium/api/v1/flow/
RAW_GO_MAPPINGS += observer/observer.proto=github.com/cilium/cilium/api/v1/observer/
RAW_GO_MAPPINGS += relay/relay.proto=github.com/cilium/cilium/api/v1/relay/

# Add mapping separators and remove the trailing slash
# but first create "/ " and ",M"
null :=
space := ${null} ${null}
file_sep := /${space}
map_sep := ,M
GO_MAPPINGS := $(patsubst %/,%,$(map_sep)$(subst $(file_sep),$(map_sep),$(RAW_GO_MAPPINGS)))

$(HUBBLE_GO_TARGETS): $(HUBBLE_PROTO_SOURCES) Makefile deps
	$(QUIET)set -e; \
	for proto in $(HUBBLE_PROTO_SOURCES) ; do \
		$(PROTOC) $(HUBBLE_PROTOC_PLUGINS) -I $(HUBBLE_PROTO_PATH) $(PROTO_DEPS) \
			--go_out=plugins=grpc$(GO_MAPPINGS):. --validate_out=lang=go$(GO_MAPPINGS):. --go-json_out=orig_name:. \
			$${proto}; \
	done

.PHONY: all
all: $(HUBBLE_GO_TARGETS)

.PHONY: clean
clean:
	rm -f $(HUBBLE_GO_TARGETS)

.PHONY: deps
deps:
	@$(PROTOC) --version | grep 3.11.4 || (echo "Error: protoc 3.11.4 is required" && exit 1)
