include ../../Makefile.defs
include $(ROOT_DIR)/Makefile.quiet

MANAGED_ETCD_VERSION := "v2.0.7"
NODEINIT_VERSION := "v1"

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
MANAGED_ETCD_PATH := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium/charts/managed-etcd/values.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium/"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_TAG_REGEX := '\(tag:\) \(v'$(VERSION_REGEX)'\|latest\)'
CILIUM_PULLPOLICY_REGEX := '\(pullPolicy:\) .*'

all: update-versions $(QUICK_INSTALL)

$(QUICK_INSTALL): $(shell find cilium/ -type f)
	$(QUIET)helm template cilium --namespace=kube-system $(OPTS) > $(QUICK_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS) | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g'
	@# Fix up the cilium tag
	$(QUIET)if echo $(VERSION) | grep -q $(LATEST_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 latest/' $(CILIUM_VALUES);			\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $(CILIUM_VALUES);		\
		elif echo $(VERSION) | grep -q $(DEV_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(subst -dev,,$(VERSION))/' $$chart;	\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $$chart;			\
		else											\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(VERSION)/' $(CILIUM_VALUES);		\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 IfNotPresent/' $(CILIUM_VALUES);	\
		fi
	@# Fix up the managed etcd version, as that has its own scheme
	$(QUIET)sed -i 's/'$(VERSION)'/'$(MANAGED_ETCD_VERSION)'/' $(MANAGED_ETCD_PATH)

clean:
	$(RM) $(QUICK_INSTALL)

check-docker-images:
	$(QUIET) \
		MANAGED_ETCD_VERSION=$(MANAGED_ETCD_VERSION) \
		NODEINIT_VERSION=$(NODEINIT_VERSION) \
		$(ROOT_DIR)/contrib/release/check-docker-images.sh "v$(VERSION)"

.phony: all check-docker-images clean update-versions
