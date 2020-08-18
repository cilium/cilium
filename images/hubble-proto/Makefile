# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.defs

.PHONY: image
image:
	docker build -t cilium/hubble-proto:${version} .

.PHONY: push
push: image
	docker push cilium/hubble-proto:${version}
