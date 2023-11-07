// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
// Used to determine if CRD needs to be updated in cluster
//
// Developers: Bump patch for each change in the CRD schema.
const CustomResourceDefinitionSchemaVersion = "1.1.0"
