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

CILIUM_ENVOY_BIN = ./bazel-bin/envoy
ISTIO_ENVOY_BIN = ./bazel-bin/istio-envoy
ISTIO_ENVOY_RELEASE_BIN = ./istio-envoy
ENVOY_BINS = \
	$(CILIUM_ENVOY_BIN) \
	$(ISTIO_ENVOY_BIN) \
	$(ISTIO_ENVOY_RELEASE_BIN) \
	./bazel-bin/cilium_integration_test
CHECK_FORMAT ?= ./bazel-bin/check_format.py.runfiles/envoy/tools/check_format.py

SHELL=/bin/bash -o pipefail
BAZEL ?= $(QUIET) bazel
BAZEL_FILTER ?= 2>&1 | grep -v -e "bazel-out/.*/genfiles/external/.*: warning: directory does not exist."
BAZEL_OPTS ?=
BAZEL_TEST_OPTS ?= --jobs=1
BAZEL_CACHE ?= ~/.cache/bazel
BAZEL_ARCHIVE ?= ~/bazel-cache.tar.bz2
CLANG ?= clang
CLANG_FORMAT ?= clang-format
BUILDIFIER ?= buildifier
STRIP ?= $(QUIET) strip

ISTIO_VERSION = 1.0.2

ifdef CILIUM_DISABLE_ENVOY_BUILD
all install clean:
	echo "Envoy build is disabled by environment variable CILIUM_DISABLE_ENVOY_BUILD"
else

# Dockerfile builds require special options
ifdef PKG_BUILD
BAZEL_BUILD_OPTS = --spawn_strategy=standalone --genrule_strategy=standalone --local_resources 4096,2.0,1.0 --jobs=3
all: clean-bins release shutdown-bazel
else
BAZEL_BUILD_OPTS = --experimental_strict_action_env --local_resources 4096,2.0,1.0 --jobs=3
all: clean-bins envoy-default api shutdown-bazel
endif

ifdef KEEP_BAZEL_RUNNING
shutdown-bazel:
else
shutdown-bazel:
	$(BAZEL) shutdown
endif

debug: envoy-debug api

release: envoy-release api

api: force-non-root Makefile.api
	$(MAKE) -f Makefile.api all

proxylib-hdrs: ../proxylib/libcilium.h ../proxylib/proxylib/types.h
	-mkdir proxylib
	cp $^ proxylib/.

proxylib-bin: ../proxylib/libcilium.so
	-mkdir proxylib
	cp $^ proxylib/.

envoy-default: force-non-root proxylib-hdrs
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-fastbuild/bin/_objs/envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:envoy $(BAZEL_FILTER)

# Allow root build for release
$(CILIUM_ENVOY_BIN) envoy-release: force proxylib-hdrs
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-opt/bin/_objs/envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:envoy $(BAZEL_FILTER)

# Allow root build for release
$(ISTIO_ENVOY_BIN) $(ISTIO_ENVOY_RELEASE_BIN): force proxylib-hdrs
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-opt/bin/_objs/istio-envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c opt //:istio-envoy $(BAZEL_FILTER)
	$(STRIP) -o $(ISTIO_ENVOY_RELEASE_BIN) $(ISTIO_ENVOY_BIN)

Dockerfile.%: Dockerfile.%.in
	-sed "s/@ISTIO_VERSION@/$(ISTIO_VERSION)/" <$< >$@

docker-istio-proxy: Dockerfile.istio_proxy $(ISTIO_ENVOY_RELEASE_BIN) envoy_bootstrap_tmpl.json
	-docker build -f $< -t cilium/istio_proxy:$(ISTIO_VERSION) .

docker-istio-proxy-debug: Dockerfile.istio_proxy_debug $(ISTIO_ENVOY_RELEASE_BIN) envoy_bootstrap_tmpl.json
	-docker build -f $< -t cilium/istio_proxy_debug:$(ISTIO_VERSION) .

envoy-debug: force-non-root proxylib-hdrs
	@$(ECHO_BAZEL)
	-rm -f bazel-out/k8-dbg/bin/_objs/envoy/external/envoy/source/common/common/version_linkstamp.o
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) -c dbg //:envoy $(BAZEL_FILTER)

$(CHECK_FORMAT): force-non-root
	$(BAZEL) $(BAZEL_OPTS) build $(BAZEL_BUILD_OPTS) //:check_format.py

install: force-root
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 -T $(CILIUM_ENVOY_BIN) $(DESTDIR)$(BINDIR)/cilium-envoy
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

# Remove the binaries to get fresh version SHA
clean-bins: force
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET) rm -f $(ENVOY_BINS) \
		Dockerfile.istio_proxy \
		Dockerfile.istio_proxy_debug

clean: force clean-bins
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	@echo "Bazel clean skipped, try 'make veryclean' instead."

veryclean: force clean-bins
	-sudo $(BAZEL) $(BAZEL_OPTS) clean
	-sudo rm -Rf $(BAZEL_CACHE)

check: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" check

fix: $(CHECK_FORMAT) force-non-root
	CLANG_FORMAT=$(CLANG_FORMAT) BUILDIFIER=$(BUILDIFIER) $(CHECK_FORMAT) --add-excluded-prefixes="./linux/" fix

# Run tests using the fastbuild by default.
tests: force-non-root proxylib-hdrs proxylib-bin
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c fastbuild $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

debug-tests: force-non-root proxylib-hdrs proxylib-bin
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:envoy_binary_test $(BAZEL_FILTER)
	$(BAZEL) $(BAZEL_OPTS) test $(BAZEL_BUILD_OPTS) -c debug $(BAZEL_TEST_OPTS) //:cilium_integration_test $(BAZEL_FILTER)

.PHONY: \
	bazel-restore \
	docker-istio-proxy \
	docker-istio-proxy-debug \
	docker-istio-proxy-init \
	force \
	force-non-root \
	force-root

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

endif
