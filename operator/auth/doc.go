// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package auth provides routines to manage mutual authentication identities in Cilium.
// If enabled, the operator will watch for CiliumIdentity resources and provision
// corresponding external identities such as SPIFFE identities.
package auth
