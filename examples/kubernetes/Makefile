include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "v$(shell cat ../../VERSION)"
endif

K8S_VERSIONS = 1.8 1.9 1.10 1.11 1.12

# make_concat creates a concatenated YAML file specific for a K8s version.
# $(1) is the K8s version. $(2) is the concatenated file.
define make_concat
all: $(1)/$(2)
$(1)/$(2):
	@$(ECHO_GEN)$$@
	-$(QUIET)for f in $$^ ; do cat "$$$${f}"; done >$$@
endef

# make_yaml creates a YAML specific for a K8s version.
# $(1) is the K8s version. $(2) is the source file.
define make_yaml
$(1)/$(patsubst templates/v1/%,%,$(patsubst %.yaml.sed,%.yaml,$(2))):
	@$(ECHO_GEN)$$@
	@echo "$(CILIUM_VERSION)" | egrep -Eq '(v[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(-.+)?)|(latest)' || \
	(echo "\"$(CILIUM_VERSION)\" is not a valid version. Must match regexp '(v[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(-.+)?)|(latest)'. Please fix VERSION file" && false)
	-$(QUIET)sed -f $(1)/transforms2sed.sed -e s+__CILIUM_VERSION__+$$(CILIUM_VERSION)+ <$$< >$$@
endef

SOURCES = $(wildcard templates/v1/*.yaml*)
YAMLS = $(patsubst templates/v1/%,%,$(patsubst %.yaml.sed,%.yaml,$(SOURCES)))
NON_DAEMONSET_YAMLS = $(filter-out %-ds.yaml,$(YAMLS))
DAEMONSET_YAMLS = $(filter %-ds.yaml,$(YAMLS))
CONCAT_FILES = $(patsubst %-ds.yaml,%.yaml,$(DAEMONSET_YAMLS))

# Add the concatenated files as a dependency of all.
# Build the concatenated files.
$(foreach K8S_VERSION,$(K8S_VERSIONS), \
	$(foreach CONCAT_FILE,$(CONCAT_FILES), \
		$(eval $(call make_concat,$(K8S_VERSION),$(CONCAT_FILE)))))

# Add all YAML files as dependencies of concatenated files.
$(foreach K8S_VERSION,$(K8S_VERSIONS), \
	$(foreach CONCAT_FILE,$(CONCAT_FILES), \
		$(eval $(K8S_VERSION)/$(CONCAT_FILE): $(sort    $(patsubst %,$(K8S_VERSION)/%,$(NON_DAEMONSET_YAMLS)) \
														$(K8S_VERSION)/$(patsubst %.yaml,%-ds.yaml,$(CONCAT_FILE)))) \
	))

# Add dependencies for individual YAML files.
$(foreach K8S_VERSION,$(K8S_VERSIONS), \
	$(foreach SOURCE,$(SOURCES), \
		$(eval $(K8S_VERSION)/$(patsubst templates/v1/%,%,$(patsubst %.yaml.sed,%.yaml,$(SOURCE))): $(SOURCE) $(K8S_VERSION)/transforms2sed.sed)))

# Build the individual YAML files.
$(foreach K8S_VERSION,$(K8S_VERSIONS), \
	$(foreach SOURCE,$(SOURCES), \
		$(eval $(call make_yaml,$(K8S_VERSION),$(SOURCE)))))

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	-$(QUIET)for k8s_version in $(K8S_VERSIONS); do  rm -f ./$$k8s_version/*.yaml; done

.PHONY: all clean
