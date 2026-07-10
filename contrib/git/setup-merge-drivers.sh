#!/bin/bash
# Script to configure Git merge drivers

# Configure Go modules driver
git config merge.go-mod-tidy.name "Go Modules Merge Driver"
git config merge.go-mod-tidy.driver "go mod tidy && go mod vendor"

# Configure Kubernetes update driver
git config merge.kubernetes-update.name "Kubernetes Update Merge Driver"
# Intead of running the default target in install/k8s, we just run targets that
# completely regenerate files in the helm charts, and we avoid linting the template
# files as this will not solve merge conflicts there.
git config merge.kubernetes-update.driver "make -C install/kubernetes update-versions cilium/values.yaml docs && make -C Documentation update-helm-values"

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

# Configure API generation drivers
git config merge.generate-api.name "OpenAPI REST API Generation Merge Driver"
git config merge.generate-api.driver "make generate-api"

git config merge.generate-health-api.name "Health API Generation Merge Driver"
git config merge.generate-health-api.driver "make generate-health-api"

git config merge.generate-kvstoremesh-api.name "KVStoreMesh API Generation Merge Driver"
git config merge.generate-kvstoremesh-api.driver "make generate-kvstoremesh-api"

git config merge.generate-hubble-api.name "Hubble API Generation Merge Driver"
git config merge.generate-hubble-api.driver "make generate-hubble-api"

git config merge.generate-operator-api.name "Operator API Generation Merge Driver"
git config merge.generate-operator-api.driver "make generate-hubble-api"

git config merge.generate-sdp-api.name "Operator API Generation Merge Driver"
git config merge.generate-sdp-api.driver "make generate-sdp-api"

echo "Git merge drivers configured successfully!"
