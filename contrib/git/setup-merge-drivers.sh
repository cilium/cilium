#!/bin/bash
# Script to configure Git merge drivers

# Configure Go modules driver
git config merge.go-mod-tidy.name "Go Modules Merge Driver"
git config merge.go-mod-tidy.driver "go mod tidy && go mod vendor"

# Configure Kubernetes update driver
git config merge.kubernetes-update.name "Kubernetes Update Merge Driver"
git config merge.kubernetes-update.driver "make -C install/kubernetes && make -C Documentation update-helm-values"

# Configure Helm values update driver
git config merge.helm-values-update.name "Helm Values Update Merge Driver"
git config merge.helm-values-update.driver "make -C install/kubernetes && make -C Documentation update-helm-values"

# Configure Images update driver
git config merge.images-update.name "Images Update Merge Driver"
git config merge.images-update.driver "make -C images update-builder-image update-runtime-image"

# Configure cmdref update driver
git config merge.cmdref-update.name "cmdref Update Merge Driver"
git config merge.cmdref-update.driver "make -C Documentation update-cmdref"

# Configure Schema permissions driver
git config merge.schema-permissions.name "Schema Permissions Merge Driver"
git config merge.schema-permissions.driver "chmod 644 install/kubernetes/cilium/values.schema.json"

# Configure API generation driver
git config merge.generate-apis.name "API Generation Merge Driver"
git config merge.generate-apis.driver "make generate-apis"

echo "Git merge drivers configured successfully!"
