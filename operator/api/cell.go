// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

// SharedConfig contains the configuration that is shared between
// this module and others.
// This is done to avoid polluting this module with a direct dependency
// on global operator configuration.
type SharedConfig struct {
	EnableK8s bool
}
