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

ifndef CILIUM_USE_ENVOY
all .DEFAULT:
	echo "Envoy build skipped, define CILIUM_USE_ENVOY to build Envoy for Cilium."
else

include ../Makefile.defs

TARGET= ./bazel-out/local-fastbuild/bin/envoy
RELEASE_TARGET= ./bazel-out/local-opt/bin/envoy
DEBUG_TARGET=./bazel-out/local-dbg/bin/envoy
CHECK_FORMAT=./bazel-out/local-fastbuild/bin/check_format.py.runfiles/envoy/tools/check_format.py

BAZEL ?= bazel
BAZEL_OPTS = --batch
BAZEL_BUILD_OPTS = --spawn_strategy=standalone --genrule_strategy=standalone -c fastbuild
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
STRIP ?= strip

PROTOC ?= protoc
PROTO_PATH = bazel-envoy/external/envoy_api
GO_OUT = ../pkg/envoy

API_PROTOS := api/*.proto
API_GOS = $(API_PROTOS:.proto=.pb.go)
API_SOURCES := $(addprefix $(PROTO_PATH)/,$(API_PROTOS))
API_TARGETS := $(addprefix $(GO_OUT)/,$(API_GOS))

FILTER_PROTOS := api/filter/http_connection_manager.proto
FILTER_GOS = $(FILTER_PROTOS:.proto=.pb.go)
FILTER_SOURCES := $(addprefix $(PROTO_PATH)/,$(FILTER_PROTOS))
FILTER_TARGETS := $(addprefix $(GO_OUT)/,$(FILTER_GOS))

CILIUM_PROTO_PATH = .

CILIUM_PROTOS := *.proto
CILIUM_GOS = $(CILIUM_PROTOS:.proto=.pb.go)
CILIUM_SOURCES := $(addprefix $(CILIUM_PROTO_PATH)/,$(CILIUM_PROTOS))
CILIUM_TARGETS := $(addprefix $(GO_OUT)/,$(CILIUM_GOS))

all: $(TARGET) $(API_TARGETS) $(CILIUM_TARGETS) $(FILTER_TARGETS)

debug: $(DEBUG_TARGET)

release: $(RELEASE_TARGET)

$(TARGET): force
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:envoy

$(RELEASE_TARGET): force
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:envoy

$(DEBUG_TARGET): force
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c dbg //:envoy

$(CHECK_FORMAT):
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:check_format.py

$(API_TARGETS): $(API_SOURCES)
	protoc --proto_path=$(PROTO_PATH) -I bazel-envoy/external/envoy_deps/thirdparty/protobuf/src -I bazel-envoy/external/googleapis --go_out=plugins=grpc:$(GO_OUT) $(API_SOURCES)

$(CILIUM_TARGETS): $(CILIUM_SOURCES)
	protoc --proto_path=$(CILIUM_PROTO_PATH) -I bazel-envoy/external/envoy_deps/thirdparty/protobuf/src --go_out=plugins=grpc:$(GO_OUT) $(CILIUM_SOURCES)

$(API_SOURCES): $(PROTO_PATH)

$(FILTER_TARGETS): $(FILTER_SOURCES)
	protoc --proto_path=$(PROTO_PATH) -I bazel-envoy/external/envoy_deps/thirdparty/protobuf/src -I bazel-envoy/external/googleapis --go_out=plugins=grpc:$(GO_OUT) $(FILTER_SOURCES)

install: force
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	-rm $(DESTDIR)$(BINDIR)/cilium-envoy
	$(INSTALL) -m 0755 -T $(TARGET) $(DESTDIR)$(BINDIR)/cilium-envoy
	$(STRIP) $(DESTDIR)$(BINDIR)/cilium-envoy

install-release: force
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	-rm $(DESTDIR)$(BINDIR)/cilium-envoy
	$(INSTALL) -m 0755 -T $(RELEASE_TARGET) $(DESTDIR)$(BINDIR)/cilium-envoy
	$(STRIP) $(DESTDIR)$(BINDIR)/cilium-envoy

install-debug: force
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	-rm $(DESTDIR)$(BINDIR)/cilium-envoy-debug
	$(INSTALL) -m 0755 -T $(DEBUG_TARGET) $(DESTDIR)$(BINDIR)/cilium-envoy-debug

clean: force
	echo "Bazel clean skipped, try \"make distclean\" instead."

distclean: force
	$(BAZEL) $(BAZEL_OPTS) clean $(BAZEL_BUILD_OPTS)

check: $(CHECK_FORMAT) force
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" check

fix: $(CHECK_FORMAT) force
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" fix

tests: $(TARGET) force
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) //:envoy_binary_test
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) //:cilium_integration_test

.PHONY: force
force :;

endif
