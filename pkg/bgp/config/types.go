// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

const (
	// BGPRouterIDAllocationModeDefault means the router-id is allocated per node
	BGPRouterIDAllocationModeDefault BGPRouterIDAllocationModeType = "default"

	// BGPRouterIDAllocationModeIPPool means the router-id is allocated per IP pool
	BGPRouterIDAllocationModeIPPool BGPRouterIDAllocationModeType = "ip-pool"
)

type BGPRouterIDAllocationModeType string

func (t *BGPRouterIDAllocationModeType) Set(value string) error {
	*t = BGPRouterIDAllocationModeType(value)

	return nil
}

func (t *BGPRouterIDAllocationModeType) String() string {
	return string(*t)
}

func (t *BGPRouterIDAllocationModeType) Type() string {
	return "string"
}
