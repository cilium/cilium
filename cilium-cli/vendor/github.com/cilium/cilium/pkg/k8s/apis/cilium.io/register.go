// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumio

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = "cilium.io"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "io.cilium.k8s.crd.schema.version"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	//
	// Maintainers: Run ./Documentation/check-crd-compat-table.sh for each release
	// Developers: Bump patch for each change in the CRD schema.
	CustomResourceDefinitionSchemaVersion = "1.26.11"
)
