# Copyright 2017-2019 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

TAG=v1
IMAGE=docker.io/cilium/startup-script

.PHONY: build push

build:
	docker build --pull -t $(IMAGE):$(TAG) .

push: build
	docker push $(IMAGE):$(TAG)
