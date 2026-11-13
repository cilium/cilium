// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

// ResourceConfig stores what optional functionality is available.
// Sometimes Resources need to know if they or an interaction of
// theirs with another feature is enabled.
type ResourceConfig struct {
	IncludeTCPRoutes        bool
	IncludeUDPRoutes        bool
	IncludeServiceImports   bool
	IncludeListenerSets     bool
	IncludeInferencePools   bool
	TCPRouteUDPRouteSupport bool
	TCPUDPUnsupportedReason string
}
