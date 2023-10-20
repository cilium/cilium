// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	TestGroupV4OuterMapName = "test_cilium_mcast_group_v4_outer"
)

func TestSubscriberMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.NoError(t, rlimit.RemoveMemlock())

	groupMapEBPF := NewGroupV4OuterMap(TestGroupV4OuterMapName)
	err := groupMapEBPF.OpenOrCreate()
	groupMapEBPF.Unpin()
	assert.NoError(t, err)

	t.Cleanup(func() {
		t.Logf("Cleaning up GroupV4OuterMap")
		if err := groupMapEBPF.Close(); err != nil {
			t.Logf("Failed to cleanup Multicast Subscriber map: %v", err)
		}
	})

	// Cast to our interface to get a useful method set.
	groupMap := GroupV4Map(groupMapEBPF)

	// Multicast group1 to insert
	group1 := netip.MustParseAddr("229.0.0.1")

	group2 := netip.MustParseAddr("229.0.0.2")

	// Insert group, no error expected
	assert.NoError(t, groupMap.Insert(group1))

	// Insert group2, no error expected
	assert.NoError(t, groupMap.Insert(group2))

	// Insert duplicate group, should detect error
	assert.Error(t, groupMap.Insert(group1))

	// Check we can list created multicast groups
	groups, err := groupMap.List()
	assert.NoError(t, err)
	assert.Len(t, groups, 2)
	// eBPF map iteration is non-deterministic, so check in a loop
	for _, group := range groups {
		if (group1.Compare(group) != 0) && (group2.Compare(group) != 0) {
			t.Fatalf("group %v did not match either of our created multicast groups", group)
		}
	}

	// Lookup first subscriber
	subMap, err := groupMap.Lookup(group1)
	assert.NoError(t, err)

	// Lookup second subscriber
	_, err = groupMap.Lookup(group1)
	assert.NoError(t, err)

	// Insert a subscriber into subscriber inner map
	src := netip.MustParseAddr("192.168.0.1")
	subscriber := SubscriberV4{
		SAddr:    src,
		Ifindex:  1,
		IsRemote: true,
	}

	assert.NoError(t, subMap.Insert(&subscriber))

	// Lookup subscriber
	var subFound *SubscriberV4
	subFound, err = subMap.Lookup(src)
	assert.NoError(t, err)

	// Subscriber should be equal
	assert.Equal(t, subscriber, *subFound)

	// Check we can list created subscriber
	subs, err := subMap.List()
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, subscriber, *subs[0])

	// Delete the subscriber
	assert.NoError(t, subMap.Delete(src))

	// Ensure deletion
	_, err = subMap.Lookup(src)
	assert.Error(t, err)

	// Delete multicast group
	groupMap.Delete(group1)
	groupMap.Delete(group2)

	// ensure multicast group deletion
	_, err = groupMap.Lookup(group1)
	assert.Error(t, err)
	_, err = groupMap.Lookup(group2)
	assert.Error(t, err)
}
