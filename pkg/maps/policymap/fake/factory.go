// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"iter"

	"github.com/cilium/cilium/pkg/maps/policymap"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

var _ policymap.Factory = (*Factory)(nil)

type Factory struct{}

func (*Factory) OpenEndpoint(id uint16) (policymap.PolicyMap, error) {
	return NewFakePolicyMap(), nil
}
func (*Factory) RemoveEndpoint(id uint16) error { return nil }
func (*Factory) PolicyMaxEntries() int          { return 0 }
func (*Factory) StatsMaxEntries() int           { return 0 }
func (*Factory) SharedPolicyEnabled() bool      { return false }
func (*Factory) SyncEndpointOverlay(uint16, iter.Seq2[policyTypes.Key, policyTypes.MapStateEntry]) error {
	return nil
}
func (*Factory) DumpEndpointSharedEntries(uint16) (policymap.PolicyEntriesDump, error) {
	return nil, nil
}
func (*Factory) HasEndpointOverlay(uint16) bool                      { return false }
func (*Factory) RemoveStaleEndpointOverlays(func(uint16) bool) error { return nil }
