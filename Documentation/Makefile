# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs
include ../Makefile.quiet

HELM_VALUES := helm-values.rst

.PHONY: default clean help builder-image cilium-build cmdref epub latex html

##@ Targets (default: "html")

default: html

DOCS_BUILDER_IMG ?= cilium/docs-builder

builder-image: Dockerfile requirements.txt ## Build the docs-builder image for rendering and checking the documentation.
	$(ECHO_DOCKER)
	# Pre-pull FROM docker images due to Buildkit sometimes failing to pull them.
	grep "^FROM " $< | tr -d '\r' | cut -d ' ' -f2 | xargs -n1 $(CONTAINER_ENGINE) pull
	$(QUIET)tar c requirements.txt Dockerfile \
	  | $(CONTAINER_ENGINE) build $(DOCKER_BUILD_FLAGS) --tag $(DOCS_BUILDER_IMG) -

# cilium must have all build artifacts present for
# documentation to be generated correctly.
cilium-build:
	make -C ../ build

READTHEDOCS_VERSION:=$(READTHEDOCS_VERSION)
DOCKER_CTR_ROOT_DIR := /src
DOCKER_CTR := $(CONTAINER_ENGINE) container run --rm \
		--workdir $(DOCKER_CTR_ROOT_DIR)/Documentation \
		--volume $(CURDIR)/..:$(DOCKER_CTR_ROOT_DIR) \
		--env READTHEDOCS_VERSION=$(READTHEDOCS_VERSION) \
		--env SKIP_LINT=$(SKIP_LINT) \
		--user "$(shell id -u):$(shell id -g)"
DOCKER_RUN := $(DOCKER_CTR) $(DOCS_BUILDER_IMG)

update-cmdref: builder-image cilium-build ## Update the command reference documents (agent, bugtool, operators, etc.).
	@$(ECHO_GEN)cmdref
	-$(QUIET)rm -rf cmdref/cilium*.md
	$(QUIET)$(DOCKER_RUN) ./update-cmdref.sh

check: builder-image update-cmdref update-helm-values ## Validate command and Helm references, as well as policy examples.
	@$(ECHO_CHECK) cmdref
	$(QUIET) ./check-cmdref.sh
	@$(ECHO_CHECK) $(HELM_VALUES)
	$(QUIET) ./check-helmvalues.sh
	@$(ECHO_CHECK) examples
	$(QUIET)$(DOCKER_RUN) ./check-examples.sh

ifeq ($(V),0)
SPHINX_OPTS += -q
endif

copy-api:
	@$(ECHO_GEN)_api
	$(QUIET)cp -T -r ../api _api

# $(HELM_DOCS_IMAGE), necessary to update the reference for Helm values,
# attempts to run a Go binary compiled for x86_64. Skip the update on other
# architectures by making update-helm-values an empty target, unless the user
# passes a compatible image.
HELM_VALUES_DEP := $(HELM_VALUES)
ifneq ($(shell uname -m),x86_64)
  ifeq ($(origin HELM_DOCS_IMAGE), file)
    $(info Documentation: skipping update for the Helm reference (image needs x86_64))
    HELM_VALUES_DEP :=
  endif
endif
update-helm-values: $(HELM_VALUES_DEP) ## Update the Helm reference documentation.

HELM_DOCS_ROOT_PATH := $(DOCKER_CTR_ROOT_DIR)
HELM_DOCS_CHARTS_DIR := $(HELM_DOCS_ROOT_PATH)/install/kubernetes
HELM_DOCS_OUTPUT_DIR := $(HELM_DOCS_ROOT_PATH)/Documentation
HELM_DOCS := $(DOCKER_CTR) $(HELM_DOCS_IMAGE)

M2R_VERSION := 0.2.1
M2R_SHA := a3dc2c3fcdc31260dcb7cd42e39763281a6fdce4ca59b4c150fb3bfff5be9eb7
M2R_IMAGE := docker.io/bmcustodio/m2r:$(M2R_VERSION)@sha256:$(M2R_SHA)
M2R := $(DOCKER_CTR) $(M2R_IMAGE) m2r

.PHONY: update-helm-values FORCE
$(HELM_VALUES): TMP_FILE_1 := helm-values.tmp
$(HELM_VALUES): TMP_FILE_2 := helm-values.awk
$(HELM_VALUES): FORCE
	$(QUIET)$(HELM_DOCS) -d -c $(HELM_DOCS_CHARTS_DIR) -t $(HELM_DOCS_OUTPUT_DIR)/$(TMP_FILE_1).tmpl > $(TMP_FILE_1)
	$(QUIET)awk -F'|' '{print "|"$$2"|"$$5"|"$$3"|"$$4"|"}' $(TMP_FILE_1) > $(TMP_FILE_2)
	$(QUIET)$(M2R) --overwrite $(TMP_FILE_2)
	$(QUIET)printf '..\n  %s\n\n%s\n' "AUTO-GENERATED. Please DO NOT edit manually." "$$(cat $@)" > $@
	$(QUIET)$(RM) -- $(TMP_FILE_1) $(TMP_FILE_2)

epub latex html: builder-image copy-api update-helm-values ## Check documentation and render it under the specified format.
	@$(ECHO_GEN)_build/$@
	$(QUIET)$(DOCKER_RUN) ./check-build.sh $(@) $(SPHINX_OPTS)

html-netlify: copy-api
	@$(ECHO_GEN)_build/$@
	$(QUIET) SKIP_LINT=1 ./check-build.sh html $(SPHINX_OPTS)

DOCS_PORT = 9081

live-preview: builder-image ## Build and serve the documentation locally.
	@echo "$$(tput setaf 2)Running at http://localhost:$(DOCS_PORT)$$(tput sgr0)"
	$(QUIET)$(DOCKER_CTR) \
		--publish $(DOCS_PORT):8000 \
			$(DOCS_BUILDER_IMG) \
		sphinx-autobuild --open-browser --host 0.0.0.0 $(SPHINX_OPTS) --ignore *.swp -Q . _preview

clean: ## Clean up all artefacts from documentation.
	-$(QUIET)rm -rf _build _api _exts/__pycache__ _preview Pipfile Pipfile.lock

help: ## Display help for the Makefile.
	$(call print_help_from_makefile)
