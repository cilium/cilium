# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= docker.io/cilium
# quay.io is not enabled, see https://github.com/cilium/image-tools/issues/11
# REGISTRIES ?= docker.io/cilium quay.io/cilium

PUSH ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

all-images: lint runtime-image builder-image cilium-image operator-image hubble-relay-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --platform linux/amd64,linux/arm64 --buildkitd-flags '--debug' > $@

runtime-image: .buildx_builder
	TEST=true scripts/build-image.sh cilium-runtime-dev images/runtime linux/amd64,linux/arm64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

builder-image: .buildx_builder
	TEST=true scripts/build-image.sh cilium-builder-dev images/builder linux/amd64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

cilium-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh cilium-dev images/cilium linux/amd64,linux/arm64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

operator-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh operator-dev images/operator linux/amd64,linux/arm64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)

hubble-relay-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh hubble-relay-dev images/hubble-relay linux/amd64,linux/arm64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)
