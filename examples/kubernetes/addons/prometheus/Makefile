# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../../../../Makefile.defs

DESTINATION= "monitoring-example.yaml"

create: clean
	helm template prometheus ./ > monitoring-example.yaml

clean:
	rm $(DESTINATION)

.PHONY: create
