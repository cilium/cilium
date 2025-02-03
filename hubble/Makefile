GO := go
GO_BUILD_FLAGS =
GO_TEST_FLAGS =
GO_BUILD = CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS)
SUBDIRS_HUBBLE_CLI := .
TARGET=hubble
TARGET_DIR=.
VERSION=$(shell cat ../VERSION)
# homebrew uses the github release's tarball of the source that does not contain the '.git' directory.
GIT_BRANCH = $(shell command -v git >/dev/null 2>&1 && git rev-parse --abbrev-ref HEAD 2> /dev/null)
GIT_HASH = $(shell command -v git >/dev/null 2>&1 && git rev-parse --short HEAD 2> /dev/null)
GO_TAGS ?=
GOOS ?=
GOARCH ?=

include ../Makefile.defs
# Add the ability to override variables
-include Makefile.override

all: hubble

hubble:
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO_BUILD) $(if $(GO_TAGS),-tags $(GO_TAGS)) -ldflags "-w -s -X 'github.com/cilium/cilium/hubble/pkg.GitBranch=${GIT_BRANCH}' -X 'github.com/cilium/cilium/hubble/pkg.GitHash=$(GIT_HASH)' -X 'github.com/cilium/cilium/hubble/pkg.Version=v${VERSION}'" -o $(TARGET_DIR)/$(TARGET)$(EXT) $(SUBDIRS_HUBBLE_CLI)

release:
	cd ../ && \
	$(CONTAINER_ENGINE) run --rm --workdir /cilium --volume `pwd`:/cilium --user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) sh -c "make -C hubble local-release"

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
			$(MAKE) hubble GOOS=$$OS GOARCH=$$ARCH EXT=$$EXT TARGET_DIR=release/$$OS/$$ARCH; \
			tar -czf release/$(TARGET)-$$OS-$$ARCH.tar.gz -C release/$$OS/$$ARCH $(TARGET)$$EXT; \
			(cd release && sha256sum $(TARGET)-$$OS-$$ARCH.tar.gz > $(TARGET)-$$OS-$$ARCH.tar.gz.sha256sum); \
		done; \
		rm -r release/$$OS; \
	done;



clean:
	rm -f $(TARGET)

.PHONY: all hubble release
