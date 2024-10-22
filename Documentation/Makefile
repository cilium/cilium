# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs
include ../Makefile.quiet

HELM_VALUES := helm-values.rst
REQUIREMENTS_NODEP := requirements-min/requirements.txt
REQUIREMENTS := requirements.txt
SPHINX_OPTS := "-j=auto"

.PHONY: default clean help builder-image cilium-build cmdref epub latex html

##@ Targets (default: "html")

default: html

define build_image
  $(ECHO_DOCKER) $(3)
  # Pre-pull FROM docker image due to Buildkit sometimes failing to pull them.
  grep -m 1 "^FROM " $(1) | tr -d '\r' | cut -d ' ' -f2 | xargs -n1 $(CONTAINER_ENGINE) pull
  $(QUIET)tar c $(REQUIREMENTS) Dockerfile \
    | $(CONTAINER_ENGINE) build $(DOCKER_BUILD_FLAGS) \
                          --build-arg READTHEDOCS_VERSION \
                          --target $(2) --tag $(3) -
endef

##@ Development Images

DOCS_BASE_IMG ?= cilium/docs-base
base-image: Dockerfile ## Build the docs-base image for updating the requirements.txt file.
	$(call build_image,$<,docs-base,$(DOCS_BASE_IMG))

DOCS_BUILDER_IMG ?= cilium/docs-builder
ifndef SKIP_BUILDER_IMAGE
builder-image: Dockerfile $(REQUIREMENTS) ## Build the docs-builder image for rendering and checking the documentation.
	$(call build_image,$<,docs-builder,$(DOCS_BUILDER_IMG))
else
builder-image:
	@echo "SKIP_BUILDER_IMAGE set, assuming image is already present and up-to-date."
endif

# cilium must have all build artifacts present for
# documentation to be generated correctly.
cilium-build:
ifndef SKIP_BUILD
	$(MAKE) builder-image
	../contrib/scripts/builder.sh env MAKEFLAGS="$(MAKEFLAGS)" make build
else
	echo "SKIP_BUILD set, assuming all build artifacts are already present."
endif

READTHEDOCS_VERSION ?= latest
DOCKER_CTR_ROOT_DIR := /src
DOCKER_CTR_BASE := $(CONTAINER_ENGINE) container run --rm \
		--workdir $(DOCKER_CTR_ROOT_DIR)/Documentation \
		--env GIT_CONFIG_COUNT=1 \
		--env GIT_CONFIG_KEY_0=safe.directory \
		--env GIT_CONFIG_VALUE_0=$(DOCKER_CTR_ROOT_DIR) \
		--volume $(CURDIR)/..:$(DOCKER_CTR_ROOT_DIR) \
		--user "$(shell id -u):$(shell id -g)"
DOCKER_CTR := $(DOCKER_CTR_BASE) \
		--env READTHEDOCS_VERSION=$(READTHEDOCS_VERSION) \
		--env SKIP_LINT=$(SKIP_LINT) \
		--env INCREMENTAL=$(INCREMENTAL)
DOCKER_RUN := $(DOCKER_CTR) $(DOCS_BUILDER_IMG)

##@ Auto-generated Contents Updates and Validation

.PHONY: api-flaggen
api-flaggen: ## Update the table of API flags restrictions.
	@$(ECHO_GEN) api-flags
	$(QUIET)$(GO) run $(ROOT_DIR)/tools/api-flaggen \
		2>/dev/null \
		> configuration/api-restrictions-table.rst

.PHONY: update-cmdref
update-cmdref: cilium-build ## Update the command reference documents (agent, bugtool, operators, etc.).
	@$(ECHO_GEN)cmdref
	-$(QUIET)rm -rf cmdref/cilium*.md
	$(QUIET)$(DOCKER_RUN) ./update-cmdref.sh

.PHONY: codeowners.rst
codeowners.rst:
	@$(ECHO_GEN)$@
	$(QUIET)$(DOCKER_RUN) ./update-codeowners.sh

.PHONY: update-codeowners
update-codeowners: codeowners.rst ## Update the description of the code owner teams.

.PHONY: update-crdlist
update-crdlist: ## Update the list of CRDs.
	@$(ECHO_GEN)crdlist
	make -C ../ generate-crd-docs

update-helm-values: $(HELM_VALUES) ## Update the Helm reference documentation.

HELM_DOCS_ROOT_PATH := $(DOCKER_CTR_ROOT_DIR)
HELM_DOCS_CHARTS_DIR := $(HELM_DOCS_ROOT_PATH)/install/kubernetes
HELM_DOCS_OUTPUT_DIR := $(HELM_DOCS_ROOT_PATH)/Documentation
HELM_DOCS := $(DOCKER_CTR) $(HELM_TOOLBOX_IMAGE) helm-docs

M2R := $(DOCKER_CTR) $(HELM_TOOLBOX_IMAGE) python3 /usr/bin/m2r2

.PHONY: update-helm-values FORCE
$(HELM_VALUES): TMP_FILE_1 := helm-values.tmp
$(HELM_VALUES): TMP_FILE_2 := helm-values.awk
$(HELM_VALUES): TMP_FILE_3 := helm-values.sed
$(HELM_VALUES): FORCE
	$(QUIET)$(HELM_DOCS) -d -c $(HELM_DOCS_CHARTS_DIR) -t $(HELM_DOCS_OUTPUT_DIR)/$(TMP_FILE_1).tmpl > $(TMP_FILE_1)
	$(QUIET)awk -F'|' '{print "|"$$2"|"$$5"|"$$3"|"$$4"|"}' $(TMP_FILE_1) > $(TMP_FILE_2)
	$(QUIET)$(M2R) --overwrite $(TMP_FILE_2)
	$(QUIET)$(SED) 's/^\(   \* - \)\([[:print:]]\{1,\}\)$$/\1:spelling:ignore:`\2`/' $@ > $(TMP_FILE_3)
	$(QUIET)printf '..\n  %s\n\n%s\n' "AUTO-GENERATED. Please DO NOT edit manually." "$$(cat $(TMP_FILE_3))" > $@
	$(QUIET)$(RM) -- $(TMP_FILE_1) $(TMP_FILE_2) $(TMP_FILE_3)

check: builder-image api-flaggen update-cmdref update-crdlist update-helm-values update-codeowners update-redirects ## Validate command and Helm references, policy examples, and others.
	@$(ECHO_CHECK) cmdref
	$(QUIET) ./check-cmdref.sh
	@$(ECHO_CHECK) $(HELM_VALUES)
	$(QUIET) ./check-helmvalues.sh
	@$(ECHO_CHECK) examples
	$(QUIET)$(DOCKER_RUN) ./check-examples.sh
	@$(ECHO_CHECK) codeowners.rst
	$(QUIET) ./check-codeowners.sh
	@$(ECHO_CHECK) configuration/api-restrictions-table.rst
	$(QUIET) ./check-flaggen.sh
	@$(ECHO_CHECK) crdlist.rst
	$(QUIET) ./check-crdlist.sh
	@$(ECHO_CHECK) redirects.txt
	$(QUIET) ./check-redirects.sh

##@ Build

ifeq ($(V),0)
SPHINX_OPTS += -q
endif

html epub latex: builder-image ## Check documentation and render it under the specified format.
	@$(ECHO_GEN)_build/$@
	$(QUIET)$(DOCKER_RUN) ./check-build.sh $(@) $(SPHINX_OPTS)

html-netlify:
	@$(ECHO_GEN)_build/$@
	$(QUIET) SKIP_LINT=1 ./check-build.sh html $(SPHINX_OPTS)

DOCS_PORT = 9081

live-preview: builder-image ## Build and serve the documentation locally.
	@echo "$$(tput setaf 2)Running at http://localhost:$(DOCS_PORT)$$(tput sgr0)"
	$(QUIET)$(DOCKER_CTR) \
		--publish $(DOCS_PORT):$(DOCS_PORT) \
			$(DOCS_BUILDER_IMG) \
		sphinx-autobuild --open-browser --host 0.0.0.0 --port $(DOCS_PORT) $(SPHINX_OPTS) --ignore *.swp -Q . _preview

update-redirects: builder-image ## Build and serve the documentation locally.
	@echo "$$(tput setaf 2)Writing redirects$$(tput sgr0)"
	$(QUIET)$(DOCKER_CTR) \
		$(DOCS_BUILDER_IMG) \
		sphinx-build -M rediraffewritediff . _preview

##@ Development

update-requirements: base-image $(REQUIREMENTS_NODEP) ## Regenerate the requirements.txt file from requirements-min/requirements.txt.
	@echo '## Auto-generated from $(REQUIREMENTS_NODEP) with "make update-requirements"' > $(REQUIREMENTS)
	$(QUIET)$(DOCKER_CTR_BASE) $(DOCS_BASE_IMG) \
		bash -c "export HOME=/tmp && pip install --no-warn-script-location -r $(REQUIREMENTS_NODEP) && pip freeze -r $(REQUIREMENTS_NODEP) >> $(REQUIREMENTS)"

clean: ## Clean up all artefacts from documentation.
	-$(QUIET)rm -rf _build _exts/__pycache__ _preview Pipfile Pipfile.lock

help: ## Display help for the Makefile.
	$(call print_help_from_makefile)
