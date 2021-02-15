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
