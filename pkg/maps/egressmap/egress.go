// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

const (
	PolicyMapName = "cilium_egress_gw_policy_v4"

	MaxPolicyEntries = 1 << 14
)

var (
	EgressPolicyMap *egressPolicyMap
)

// InitEgressMaps initializes the egress policy map.
func InitEgressMaps() error {
	return initEgressPolicyMap(PolicyMapName, true)
}

// OpenEgressMaps initializes the egress policy map.
func OpenEgressMaps() error {
	return initEgressPolicyMap(PolicyMapName, false)
}
