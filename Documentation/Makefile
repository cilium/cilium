# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

##@ Targets (default: "html")

default: html

# NB: Top-level includes are performed from images/Makefile.docs.
include ../images/Makefile.docs

HELM_VALUES := helm-values.rst
DOCS_REQUIREMENTS_NODEP:=requirements-min/requirements.txt
SPHINX_OPTS := "-j=auto"

.PHONY: default clean help cilium-build cmdref epub latex html

DOCS_BUILDER_IMG ?= quay.io/cilium/docs-builder:e6773ed21ab03066c0f24e68f342f18804a8ee0a@sha256:d3beff6d6408c09f6e1dbc637f7e98962b7d1fd2a81bf1d2a27ff8817dafb51f

.PHONY: update-docs-builder-image
update-docs-builder-image: DOCS_BUILDER_TAG=$(word 3,$(shell git ls-tree --full-tree HEAD -- $(DOCS_BUILDER_DIR)))
update-docs-builder-image:
	if [ -z "$(findstring $(DOCS_BUILDER_TAG),$(DOCS_BUILDER_IMG))" ]; then \
		$(ROOT_DIR)/Documentation/update-docs-builder-image.sh '$(DOCS_BUILDER_REPO):$(DOCS_BUILDER_TAG)'; \
	fi

.PHONY: builder-image
builder-image:
	$(MAKE) -C ../images -f Makefile.docs docs-builder-image
	$(MAKE) update-docs-builder-image

# cilium must have all build artifacts present for
# documentation to be generated correctly.
cilium-build:
ifndef SKIP_BUILD
	$(MAKE) builder-image
	../contrib/scripts/builder.sh env MAKEFLAGS="$(filter-out --jobserver-auth=%,$(MAKEFLAGS))" make build
else
	echo "SKIP_BUILD set, assuming all build artifacts are already present."
endif

READTHEDOCS_VERSION ?= latest
DOCKER_CTR := $(DOCKER_CTR_BASE) \
		--workdir $(DOCKER_CTR_ROOT_DIR)/Documentation \
		--env READTHEDOCS_VERSION=$(READTHEDOCS_VERSION) \
		--env SKIP_LINT=$(SKIP_LINT) \
		--env INCREMENTAL=$(INCREMENTAL)
DOCKER_RUN := $(DOCKER_CTR) $(DOCS_BUILDER_IMG)

# Sphinx loads the Rediraffe extension, which needs access to git metadata. In a git worktree, .git points outside the mounted source tree.
# Mount the common git dir at a well known path, and set GIT_DIR to the corresponding directory within that mount.
HOST_GIT_DIR := $(shell git rev-parse --absolute-git-dir 2>/dev/null)
HOST_GIT_COMMON_DIR := $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
DOCKER_SPHINX_CTR := $(DOCKER_CTR) \
	--volume $(HOST_GIT_COMMON_DIR):/git-common-dir:ro \
	--env GIT_WORK_TREE=$(DOCKER_CTR_ROOT_DIR) \
	--env GIT_DIR=/git-common-dir$(patsubst $(HOST_GIT_COMMON_DIR)%,%,$(HOST_GIT_DIR)) # Preserve the GIT_DIR path within the common-dir mount so commondir resolves correctly.
DOCKER_SPHINX_RUN := $(DOCKER_SPHINX_CTR) $(DOCS_BUILDER_IMG)

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
DOCKER_AWK := $(DOCKER_CTR) busybox awk
DOCKER_SED := $(DOCKER_CTR) busybox sed

.PHONY: update-helm-values FORCE
$(HELM_VALUES): TMP_FILE_1 := helm-values.tmp
$(HELM_VALUES): TMP_FILE_2 := helm-values.awk
$(HELM_VALUES): TMP_FILE_3 := helm-values.sed
$(HELM_VALUES): FORCE
	$(QUIET)$(HELM_DOCS) -d -c $(HELM_DOCS_CHARTS_DIR) -t $(HELM_DOCS_OUTPUT_DIR)/$(TMP_FILE_1).tmpl > $(TMP_FILE_1)
	$(QUIET)$(DOCKER_AWK) -F'|' '{print "|"$$2"|"$$5"|"$$3"|"$$4"|"}' $(HELM_DOCS_OUTPUT_DIR)/$(TMP_FILE_1) > $(TMP_FILE_2)
	$(QUIET)$(M2R) --overwrite $(TMP_FILE_2)
	$(QUIET)$(DOCKER_SED) 's/^\(   \* - \)\([[:print:]]\{1,\}\)$$/\1:spelling:ignore:`\2`/' $(HELM_DOCS_OUTPUT_DIR)/$(HELM_VALUES) > $(TMP_FILE_3)
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
	$(QUIET)$(DOCKER_SPHINX_RUN) ./check-build.sh $(@) $(SPHINX_OPTS)

html-netlify:
	@$(ECHO_GEN)_build/$@
	$(QUIET) SKIP_LINT=1 ./check-build.sh html $(SPHINX_OPTS)

DOCS_PORT = 9081

live-preview: builder-image ## Build and serve the documentation locally.
	@echo "$$(tput setaf 2)Running at http://localhost:$(DOCS_PORT)$$(tput sgr0)"
	$(QUIET)$(DOCKER_SPHINX_CTR) \
		--publish $(DOCS_PORT):$(DOCS_PORT) \
			$(DOCS_BUILDER_IMG) \
		sphinx-autobuild --open-browser --host 0.0.0.0 --port $(DOCS_PORT) $(SPHINX_OPTS) --ignore "*.swp" -Q . _preview

update-redirects: builder-image ## Build and serve the documentation locally.
	@echo "$$(tput setaf 2)Writing redirects$$(tput sgr0)"
	$(QUIET)$(DOCKER_SPHINX_CTR) \
		$(DOCS_BUILDER_IMG) \
		sphinx-build -M rediraffewritediff . _preview

##@ Development

.PHONY: update-requirements
update-requirements: docs-base-image $(DOCS_REQUIREMENTS_NODEP) ## Regenerate the requirements.txt file from requirements-min/requirements.txt.
	@echo '## Auto-generated from Documentation/$(DOCS_REQUIREMENTS_NODEP) with "make update-requirements"' > $(DOCS_BUILDER_DIR)/$(DOCS_REQUIREMENTS)
	$(QUIET)$(DOCKER_CTR_BASE) $(DOCS_BASE_IMG) \
		bash -c "export HOME=/tmp && pip install --no-warn-script-location -r ../../Documentation/$(DOCS_REQUIREMENTS_NODEP) && pip freeze -r ../../$(DOCS_REQUIREMENTS_NODEP) >> $(DOCS_REQUIREMENTS)"

clean: ## Clean up all artefacts from documentation.
	-$(QUIET)rm -rf _build _exts/__pycache__ _preview Pipfile Pipfile.lock

help: ## Display help for the Makefile.
	$(call print_help_from_makefile)
