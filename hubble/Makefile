# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Hubble

.DEFAULT_GOAL := all

CURR_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")

include $(CURR_DIR)/../Makefile.defs
# Add the ability to override variables
-include $(CURR_DIR)/Makefile.override

TARGET := hubble

.PHONY: all
all: $(TARGET)

SUBDIRS_HUBBLE_CLI := .
TARGET_DIR=.
# homebrew uses the github release's tarball of the source that does not contain the '.git' directory.
GIT_BRANCH = $(shell command -v git >/dev/null 2>&1 && git rev-parse --abbrev-ref HEAD 2> /dev/null)
GIT_HASH = $(shell command -v git >/dev/null 2>&1 && git rev-parse --short HEAD 2> /dev/null)

GO_BUILD_LDFLAGS += -X "github.com/cilium/cilium/hubble/pkg.GitBranch=$(GIT_BRANCH)" \
					-X "github.com/cilium/cilium/hubble/pkg.GitHash=$(GIT_HASH)" \
					-X "github.com/cilium/cilium/hubble/pkg.Version=v$(VERSION)"

.PHONY: $(TARGET)
$(TARGET):
	$(GO_BUILD) -o $(TARGET_DIR)/$(@)$(EXT) $(SUBDIRS_HUBBLE_CLI)

.PHONY: release
release:
	cd $(CURR_DIR)/../ && \
	$(CONTAINER_ENGINE) run --rm --workdir /cilium --volume `pwd`:/cilium --user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) sh -c "$(MAKE) -C $(TARGET) local-release"

.PHONY: local-release
local-release: clean
	set -o errexit; \
	for OS in darwin linux windows; do \
		EXT=; \
		ARCHS=; \
		case $$OS in \
			darwin) \
				ARCHS='amd64 arm64'; \
				;; \
			linux) \
				ARCHS='amd64 arm64'; \
				;; \
			windows) \
				ARCHS='amd64 arm64'; \
				EXT=".exe"; \
				;; \
		esac; \
		for ARCH in $$ARCHS; do \
			echo Building release binary for $$OS/$$ARCH...; \
			test -d release/$$OS/$$ARCH|| mkdir -p release/$$OS/$$ARCH; \
			$(MAKE) $(TARGET) GOOS=$$OS GOARCH=$$ARCH EXT=$$EXT TARGET_DIR=release/$$OS/$$ARCH; \
			tar -czf release/$(TARGET)-$$OS-$$ARCH.tar.gz -C release/$$OS/$$ARCH $(TARGET)$$EXT; \
			(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.tar.gz > $(TARGET)-$$OS-$$ARCH.tar.gz.sha256sum); \
		done; \
		rm -r release/$$OS; \
	done;

.PHONY: install
install: install-binary install-bash-completion

.PHONY: install-binary
install-binary: $(TARGET)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

.PHONY: install-bash-completion
install-bash-completion: $(TARGET)
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(CONFDIR)/bash_completion.d
	./$(TARGET) completion bash > $(TARGET)_bash_completion
	$(QUIET)$(INSTALL) -m 0644 -T $(TARGET)_bash_completion $(DESTDIR)$(CONFDIR)/bash_completion.d/$(TARGET)

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)
