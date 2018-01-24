# Copyright 2017 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include ../Makefile.defs

ENVOY_BIN = ./bazel-bin/envoy
ENVOY_BINS = $(ENVOY_BIN) ./bazel-bin/cilium_integration_test
CHECK_FORMAT ?= ./bazel-bin/check_format.py.runfiles/envoy/tools/check_format.py

BAZEL ?= bazel
BAZEL_OPTS ?= --batch
BAZEL_TEST_OPTS ?= 
BAZEL_CACHE ?= ~/.cache/bazel
BAZEL_ARCHIVE ?= ~/bazel-cache.tar.bz2
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
STRIP ?= strip

PROTOC ?= bazel-out/host/bin/external/com_google_protobuf/protoc
PROTO_DEPS= bazel-envoy/external/com_google_protobuf/src -I bazel-envoy/external/googleapis -I bazel-envoy/external/com_lyft_protoc_gen_validate
PROTO_PATH = bazel-envoy/external/envoy_api
GO_OUT = ../pkg/envoy

API_PROTOS := api/rds.proto api/lds.proto api/address.proto api/auth.proto api/base.proto api/discovery.proto api/sds.proto api/bootstrap.proto api/cds.proto api/health_check.proto api/protocol.proto

API_GOS = $(API_PROTOS:.proto=.pb.go)
API_SOURCES := $(addprefix $(PROTO_PATH)/,$(API_PROTOS))
API_TARGETS := $(addprefix $(GO_OUT)/,$(API_GOS))

FILTER_PROTOS := api/filter/network/http_connection_manager.proto
FILTER_GOS = $(FILTER_PROTOS:.proto=.pb.go)
FILTER_SOURCES := $(addprefix $(PROTO_PATH)/,$(FILTER_PROTOS))
FILTER_TARGETS := $(addprefix $(GO_OUT)/,$(FILTER_GOS))

CILIUM_PROTO_PATH = .

CILIUM_PROTOS := *.proto
CILIUM_GOS = $(CILIUM_PROTOS:.proto=.pb.go)
CILIUM_SOURCES := $(addprefix $(CILIUM_PROTO_PATH)/,$(CILIUM_PROTOS))
CILIUM_TARGETS := $(addprefix $(GO_OUT)/,$(CILIUM_GOS))

GO_TARGETS= $(API_TARGETS) $(CILIUM_TARGETS) $(FILTER_TARGETS)

# Dockerfile builds require special options
ifdef PKG_BUILD
BAZEL_BUILD_OPTS = --spawn_strategy=standalone --genrule_strategy=standalone
all: release
else
BAZEL_BUILD_OPTS =

all: envoy $(GO_TARGETS)
endif

debug: envoy-debug $(GO_TARGETS)

release: envoy-release $(GO_TARGETS)

envoy: force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:envoy

# Allow root build for release
$(ENVOY_BIN) envoy-release: force
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:envoy

envoy-debug: force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c dbg //:envoy

$(CHECK_FORMAT): force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:check_format.py

$(API_TARGETS): $(API_SOURCES)
	$(PROTOC) --proto_path=$(PROTO_PATH) -I $(PROTO_DEPS) --go_out=plugins=grpc:$(GO_OUT) $(API_SOURCES)

$(CILIUM_TARGETS): $(CILIUM_SOURCES)
	$(PROTOC) --proto_path=$(CILIUM_PROTO_PATH) -I $(PROTO_DEPS) --go_out=plugins=grpc:$(GO_OUT) $(CILIUM_SOURCES)

$(API_SOURCES): $(PROTO_PATH)

$(FILTER_TARGETS): $(FILTER_SOURCES)
	$(PROTOC) --proto_path=$(PROTO_PATH) -I $(PROTO_DEPS) --go_out=plugins=grpc:$(GO_OUT) $(FILTER_SOURCES)

install: force-root
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T $(ENVOY_BIN) $(DESTDIR)$(BINDIR)/cilium-envoy
# Strip only non-debug builds
ifeq "$(findstring -dbg,$(realpath bazel-bin))" ""
	$(STRIP) $(DESTDIR)$(BINDIR)/cilium-envoy
endif

bazel-archive: force-non-root tests clean-bins
	-sudo rm -f $(BAZEL_ARCHIVE)
	echo "Archiving bazel cache ($(BAZEL_CACHE)), this will take some time..."
	cd $(dir $(BAZEL_CACHE)) && sudo tar cjf $(BAZEL_ARCHIVE) --atime-preserve=system $(notdir $(BAZEL_CACHE))

bazel-clean-archive: force-non-root veryclean bazel-archive

bazel-restore: $(BAZEL_ARCHIVE)
	echo "Clearing & restoring bazel archive ($(BAZEL_ARCHIVE))..."
	-sudo rm -Rf $(BAZEL_CACHE)
	-mkdir $(dir $(BAZEL_CACHE))
	cd $(dir $(BAZEL_CACHE)) && sudo tar xjf $(BAZEL_ARCHIVE) --warning=no-timestamp

# Only remove the binaries, as relinking them takes minimal time, as this allows
# the bazel cache size to be a little smaller.
clean-bins: force
	-rm -f $(ENVOY_BINS)

clean: force
	echo "Bazel clean skipped, try \"make veryclean\" instead."

veryclean: force
	-sudo $(BAZEL) $(BAZEL_OPTS) clean
	-sudo rm -Rf $(BAZEL_CACHE)

check: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" check

fix: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" fix

# Run tests using the fastbuild by default.
tests: force-non-root
	$(BAZEL) $(BAZEL_OPTS) test -c fastbuild $(BAZEL_TEST_OPTS) //:envoy_binary_test
	$(BAZEL) $(BAZEL_OPTS) test -c fastbuild $(BAZEL_TEST_OPTS) //:cilium_integration_test

debug-tests: force-non-root
	$(BAZEL) $(BAZEL_OPTS) test -c debug $(BAZEL_TEST_OPTS) //:envoy_binary_test
	$(BAZEL) $(BAZEL_OPTS) test -c debug $(BAZEL_TEST_OPTS) //:cilium_integration_test

.PHONY: force force-root force-non-root
force :;

force-root:
ifndef PKG_BUILD
ifneq ($(USER),root)
	$(error This target must be run as root!)
endif
endif

force-non-root:
ifeq ($(USER),root)
	$(error This target cannot be run as root!)
endif
