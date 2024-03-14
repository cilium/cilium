// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package instance

import (
	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// NewFakeBGPInstance is fake BGP instance, to be used in unit tests.
func NewFakeBGPInstance() *BGPInstance {
	return &BGPInstance{
		Config:   nil,
		Router:   types.NewFakeRouter(),
		Metadata: make(map[string]any),
	}
}
