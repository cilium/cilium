# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

include ../Makefile.defs

# Dockerfile builds require special options
ifdef PKG_BUILD

all:
	@echo "  SKIP  $(RELATIVE_DIR)/"
	@echo "cilium-envoy has been moved to github.com/cilium/proxy"

install:
	@echo "cilium-envoy must be installed separately"

install-binary: install

install-bash-completion:

clean:

else

all:
	@echo "  SKIP  $(RELATIVE_DIR)/"
	@echo "cilium-envoy has been moved to github.com/cilium/proxy"

install:
ifndef DISABLE_ENVOY_INSTALLATION
	docker create -ti --name cilium-envoy $(CILIUM_ENVOY_REF) bash
	docker cp cilium-envoy:/usr/bin/cilium-envoy $(BINDIR)/cilium-envoy
	docker rm -fv cilium-envoy
endif

install-binary: install

install-bash-completion:

clean:

endif
