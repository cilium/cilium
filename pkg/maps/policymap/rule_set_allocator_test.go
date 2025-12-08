// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"testing"

	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/stretchr/testify/assert"
)

func TestRuleSetAllocator_Hash(t *testing.T) {
	// 1. Verify exact same rules produce same hash
	keys1 := []SharedPolicyKey{
		{Identity: 100, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80},
		{Identity: 200, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80},
	}
	hash1 := ComputeRuleSetHash(keys1)

	keys2 := []SharedPolicyKey{
		{Identity: 100, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80},
		{Identity: 200, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80},
	}
	hash2 := ComputeRuleSetHash(keys2)

	assert.Equal(t, hash1, hash2, "Identical rule sets must produce identical hashes")

	// 2. Verify order independence (ComputeRuleSetHash should sort)
	keysUnsorted := []SharedPolicyKey{
		{Identity: 200, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80}, // 200 first
		{Identity: 100, Direction: trafficdirection.Ingress, Nexthdr: u8proto.TCP, DestPortNetwork: 80},
	}
	hashUnsorted := ComputeRuleSetHash(keysUnsorted)

	assert.Equal(t, hash1, hashUnsorted, "Different input order must produce identical hashes (deduplication)")
}

func TestRuleSetAllocator_Allocation(t *testing.T) {
	alloc := NewRuleSetAllocator(10, nil)
	_ = alloc

	// 1. Allocate first set
	keys1 := []ArenaRuleWithEntry{
		{
			Key: policyTypes.KeyForDirection(trafficdirection.Ingress).
				WithIdentity(100).
				WithPortProto(u8proto.TCP, 80),
		},
	}
	id1, err := alloc.GetOrAllocate(keys1)
	assert.Error(t, err) // Expect error with nil arena
	assert.Zero(t, id1)
}

func TestRuleSetAllocator_Release(t *testing.T) {
	alloc := NewRuleSetAllocator(10, nil)
	_ = alloc
	// ...
}

func TestRuleSetAllocator_ReleaseByID(t *testing.T) {
	alloc := NewRuleSetAllocator(10, nil)
	_ = alloc
	// ...
}
