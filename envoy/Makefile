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
	GLIBC_VERSION=$$(patchelf --print-interpreter /usr/bin/cilium-envoy | sed -n 's!\(.*\)/glibc-\([0-9.]*\)/ld-linux-.*!\2!p'); \
	if [ -n $${GLIBC_VERSION} ]; then \
	    docker cp cilium-envoy:/usr/lib/glibc-$${GLIBC_VERSION} $(LIBDIR); \
	    GLIBC_DIR=$(LIBDIR)/glibc-$${GLIBC_VERSION}; \
	    LD_LINUX=$$(patchelf --print-interpreter /usr/bin/cilium-envoy); \
	    if [ "$$(dirname $${LD_LINUX})" != "$${GLIBC_DIR}" ]; then \
	        patchelf --set-interpreter $${GLIBC_DIR}/$$(basename $${LD_LINUX}) --set-rpath $${GLIBC_DIR} $(BINDIR)/cilium-envoy; \
	    fi; \
	fi
	docker rm -fv cilium-envoy
endif

install-binary: install

install-bash-completion:

clean:

endif
