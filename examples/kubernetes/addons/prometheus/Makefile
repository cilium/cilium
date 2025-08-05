# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../../Makefile.defs

DESTINATION= "monitoring-example.yaml"

create: clean
	helm template prometheus ./ > monitoring-example.yaml

clean:
	rm $(DESTINATION)

# Dashboard management tools
.PHONY: dashboard-tools
dashboard-tools:
	@$(MAKE) -C tools help

.PHONY: extract-dashboards
extract-dashboards:
	@$(MAKE) -C tools extract-dashboards

.PHONY: update-hubble
update-hubble:
	@$(MAKE) -C tools update-hubble HUBBLE_JSON=$(HUBBLE_JSON)

.PHONY: test-tools
test-tools:
	@$(MAKE) -C tools test

.PHONY: setup-tools
setup-tools:
	@$(MAKE) -C tools setup

.PHONY: create
