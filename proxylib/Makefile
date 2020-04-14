# Copyright 2017-2020 Authors of Cilium
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

EXTRA_GO_BUILD_LDFLAGS = -extldflags -Wl,-soname,libcilium.so.$(VERSION_MAJOR)

TARGET := libcilium.so

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD_WITH_CGO) -o $@.$(VERSION_MAJOR) -buildmode=c-shared
	$(QUIET)ln -sf $@.$(VERSION_MAJOR) $@ || cp $@.$(VERSION_MAJOR) $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(LIBDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET).$(VERSION_MAJOR) $(DESTDIR)$(LIBDIR)
	ln -sf $(TARGET).$(VERSION_MAJOR) $(DESTDIR)$(LIBDIR)/$(TARGET)
