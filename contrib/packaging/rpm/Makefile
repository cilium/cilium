# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../Makefile.defs

VERSION := $(shell git tag -l --sort=-v:refname | sed 's/v\([^-].*\)/\1/g' | head -1)
RELEASE := $(shell git describe --long --tags | sed 's/\([^-].*\)-\([0-9]*\)-\(g.*\)/\2/g')
BUILDDIR := "$(CURDIR)/cilium-$(VERSION)"
BASEDIR := "$(CURDIR)/../../../"
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT := $(shell git rev-parse HEAD)
SHORTCOMMIT := $(shell git rev-parse HEAD | cut -c1-7)

build: clean
	mkdir -p output
	echo "export VERSION=$(VERSION) RELEASE=$(RELEASE) COMMIT=$(COMMIT) SHORTCOMMIT=$(SHORTCOMMIT)" > env
	(cd $(BASEDIR) && git bundle create $(CURDIR)/version_$(VERSION) $(BRANCH) --tags)
	(cd $(CURDIR) && git clone $(CURDIR)/version_$(VERSION) cilium -b $(BRANCH))
	(cd $(CURDIR)/cilium/envoy && make BINDIR=$$PWD install)
	tar -c cilium --transform s/cilium/cilium-$(COMMIT)/ | gzip -9 &> cilium-$(SHORTCOMMIT).tar.gz
	docker build -t cilium:cilium-bin-rpm-$(VERSION) $(CURDIR)
	docker run --rm -v $(CURDIR)/output:/output cilium:cilium-bin-rpm-$(VERSION)
	echo -e "\nCilium version $(VERSION) packages are located here:\n$(CURDIR)/output/\n"

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -rf env cilium output version_* cilium-*.tar.gz

.PHONY: force build clean
force :;
