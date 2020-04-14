# Copyright 2017-2019 Authors of Cilium
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

