# Copyright 2017-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include Makefile.digests ../../Makefile.defs

MANAGED_ETCD_VERSION := "v2.0.7"
NODEINIT_VERSION := "62bfbe88c17778aad7bef9fa57ff9e2d4a9ba0d8"
HUBBLE_UI_VERSION := "v0.6.1"

QUICK_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/quick-install.yaml"
EXPERIMENTAL_INSTALL := "$(ROOT_DIR)/$(RELATIVE_DIR)/experimental-install.yaml"
MANAGED_ETCD_PATH := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium/charts/managed-etcd/values.yaml"
CILIUM_CHARTS := "$(ROOT_DIR)/$(RELATIVE_DIR)/cilium"
CILIUM_VALUES := "$(CILIUM_CHARTS)/values.yaml" "$(CILIUM_CHARTS)/charts/hubble-relay/values.yaml"

VERSION_REGEX := '[0-9]\+\.[0-9]\+\.[0-9]\+.*'
LATEST_VERSION_REGEX := '[0-9]\+\.[0-9]\+\.90'
DEV_VERSION_REGEX := '[0-9]\+\.[0-9]\+-dev'
CILIUM_CHART_REGEX := '\([vV]ersion:\) '$(VERSION_REGEX)
CILIUM_TAG_REGEX := '\(tag:\) \(v'$(VERSION_REGEX)'\|latest\)'
CILIUM_PULLPOLICY_REGEX := '\([pP]ullPolicy:\) .*'
EXPERIMENTAL_OPTIONS := \
    --set global.hubble.enabled=true \
    --set global.hubble.listenAddress=":4244" \
    --set global.hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
    --set global.hubble.relay.enabled=true \
    --set global.hubble.ui.enabled=true

all: update-versions $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

# FIXME change the useDigest to 'true' once images were released by GH actions
$(QUICK_INSTALL): $(shell find cilium/ -type f)
	$(QUIET)helm template cilium --namespace=kube-system \
     --set agent.useDigest=false \
     --set hubble-relay.useDigest=false \
     --set operator.useDigest=false \
     --set preflight.useDigest=false \
     $(OPTS) > $(QUICK_INSTALL)

# FIXME change the useDigest to 'true' once images were released by GH actions
$(EXPERIMENTAL_INSTALL): $(shell find cilium/ -type f)
	$(QUIET)helm template cilium --namespace=kube-system \
     --set agent.useDigest=false \
     --set hubble-relay.useDigest=false \
     --set operator.useDigest=false \
     --set preflight.useDigest=false \
     $(EXPERIMENTAL_OPTIONS) > $(EXPERIMENTAL_INSTALL)

update-versions:
	$(ECHO_GEN) " -> Updating version to $(VERSION)"
	@# Update chart versions to point to the current version.
	$(QUIET)grep -lRZ -e "version:" -e "appVersion:" $(CILIUM_CHARTS)/ | \
		xargs -0 -l sed -i -e 's/'$(CILIUM_CHART_REGEX)'/\1 $(VERSION)/g'
	@# Fix up the cilium tag
	$(QUIET)for chart in $(CILIUM_VALUES); do							\
		if echo $(VERSION) | grep -q $(LATEST_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 latest/' $$chart;				\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $$chart;			\
		elif echo $(VERSION) | grep -q $(DEV_VERSION_REGEX); then				\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(subst -dev,,$(VERSION))/' $$chart;	\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 Always/' $$chart;			\
		else											\
			sed -i 's/'$(CILIUM_TAG_REGEX)'/\1 v$(VERSION)/' $$chart;			\
			sed -i 's/'$(CILIUM_PULLPOLICY_REGEX)'/\1 IfNotPresent/' $$chart;		\
		fi; done
	$(QUIET)for chart in $(shell find -type f -name values.yaml); do								\
		sed -i '/# cilium-digest.*/{!b;n;s/digest.*/digest: "'$(CILIUM_DIGEST)'"/}' $$chart; 					\
		sed -i '/# hubble-relay-digest.*/{!b;n;s/digest.*/digest: "'$(HUBBLE_RELAY_DIGEST)'"/}' $$chart;			\
		sed -i '/# operator-aws-digest.*/{!b;n;s/awsDigest.*/awsDigest: "'$(OPERATOR_AWS_DIGEST)'"/}' $$chart; 			\
		sed -i '/# operator-azure-digest.*/{!b;n;s/azureDigest.*/azureDigest: "'$(OPERATOR_AZURE_DIGEST)'"/}' $$chart; 		\
		sed -i '/# operator-generic-digest.*/{!b;n;s/genericDigest.*/genericDigest: "'$(OPERATOR_GENERIC_DIGEST)'"/}' $$chart;  \
		sed -i '/# operator-legacy-digest.*/{!b;n;s/legacyDigest.*/legacyDigest: "'$(OPERATOR_DIGEST)'"/}' $$chart; 		\
	done
	@# Fix up the managed etcd version, as that has its own scheme
	$(QUIET)sed -i 's/'$(VERSION)'/'$(MANAGED_ETCD_VERSION)'/' $(MANAGED_ETCD_PATH)

clean:
	$(RM) $(QUICK_INSTALL) $(EXPERIMENTAL_INSTALL)

docs:
	$(QUIET)$(HELM_DOCS)

check-docker-images:
	$(QUIET)\
		HUBBLE_UI_VERSION=$(HUBBLE_UI_VERSION) \
		MANAGED_ETCD_VERSION=$(MANAGED_ETCD_VERSION) \
		NODEINIT_VERSION=$(NODEINIT_VERSION) \
		$(ROOT_DIR)/contrib/release/check-docker-images.sh "v$(VERSION)"

.PHONY: all check-docker-images clean docs experimental-install lint quick-install update-versions
