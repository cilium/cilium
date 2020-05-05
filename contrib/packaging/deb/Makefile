# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../Makefile.defs

BUILDDIR := "$(CURDIR)/cilium-$(VERSION)"
BASEDIR := "$(CURDIR)/../../../"
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

build: clean
	mkdir -p output
	(cd $(BASEDIR) && git bundle create $(CURDIR)/version_$(VERSION) $(BRANCH) --tags)
	(cd $(CURDIR) && git clone $(CURDIR)/version_$(VERSION) cilium -b $(BRANCH))
	docker build -t cilium:cilium-bin-deb-$(VERSION) $(CURDIR)
	docker run --rm -v $(CURDIR)/output:/output cilium:cilium-bin-deb-$(VERSION)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -rf cilium output version_*

release:
	cd $(BASEDIR)
	ln -sf $(CURDIR)/debian $(BASEDIR)/debian
	gbp dch --spawn-editor=never --git-author --upstream-tag="v.%(version)s" --ignore-branch \
        --debian-tag="v.%(version)s" -N "$(VERSION)" --since 1bfb6303f6fba25c4d22fbe4b7c35450055296b6
	git add $(CURDIR)/debian/changelog

.PHONY: force build clean
force :;

