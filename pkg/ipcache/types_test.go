// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/ipcache/types"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
)

func Test_sortedByResourceIDsAndSource(t *testing.T) {
	pi := newPrefixInfo()
	pim := pi.byResource
	pim["a-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pim["b-restored-uid"] = &resourceInfo{
		source: source.Restored,
	}
	pim["node-uid"] = &resourceInfo{
		source: source.CustomResource,
	}
	pim["node2-uid"] = &resourceInfo{
		source: source.Local,
	}
	pim["daemon-uid"] = &resourceInfo{
		source: source.Local,
	}
	pim["endpoints-uid"] = &resourceInfo{
		source: source.KubeAPIServer,
	}
	pim["2-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pim["1-identity-uid"] = &resourceInfo{
		source: source.Kubernetes,
	}
	pim["generated-uid"] = &resourceInfo{
		source: source.Generated,
	}
	pim["kvstore-uid"] = &resourceInfo{
		source: source.KVStore,
	}

	expected := []types.ResourceID{
		"endpoints-uid",
		"daemon-uid",
		"node2-uid",
		"kvstore-uid",
		"node-uid",
		"1-identity-uid",
		"2-identity-uid",
		"generated-uid",
		"a-restored-uid",
		"b-restored-uid",
	}
	assert.Equal(t, expected, pi.sortedBySourceThenResourceID())
}

func TestFlatten(t *testing.T) {
	ipA := netip.MustParseAddr("1.2.3.4")
	ipB := netip.MustParseAddr("1.2.3.5")

	flagsT := ipcacheTypes.EndpointFlags{}
	flagsT.SetSkipTunnel(true)

	flagsF := ipcacheTypes.EndpointFlags{}
	flagsF.SetSkipTunnel(false)

	tests := []struct {
		resourceA *resourceInfo
		resourceB *resourceInfo
		expected  *resourceInfo
	}{
		{
			resourceA: &resourceInfo{
				source: source.Local,
				labels: labels.NewLabelsFromSortedList("source:a=b;source:k=v;"),
			},
			resourceB: &resourceInfo{
				source: source.Generated,
				labels: labels.NewLabelsFromSortedList("source:c=d;source:k=x"),
			},
			expected: &resourceInfo{
				source: source.Local,
				labels: labels.NewLabelsFromSortedList("source:a=b;source:c=d;source:k=v"),
			},
		},
		{
			resourceA: &resourceInfo{
				source: source.Local,
				labels: labels.NewLabelsFromSortedList("source:a=b;source:k=v;"),
			},
			resourceB: &resourceInfo{
				source:           source.Generated,
				labels:           labels.NewLabelsFromSortedList("source:c=d;source:k=x"),
				identityOverride: true,
			},
			expected: &resourceInfo{
				source:           source.Local,
				labels:           labels.NewLabelsFromSortedList("source:c=d;source:k=x"),
				identityOverride: true,
			},
		},
		// all conflicts
		{
			resourceA: &resourceInfo{
				source:            source.Local,
				tunnelPeer:        types.TunnelPeer{Addr: ipA},
				encryptKey:        types.EncryptKey(1),
				requestedIdentity: types.RequestedIdentity(10),
				endpointFlags:     flagsF,
			},
			resourceB: &resourceInfo{
				source:            source.Generated,
				tunnelPeer:        types.TunnelPeer{Addr: ipB},
				encryptKey:        types.EncryptKey(2),
				requestedIdentity: types.RequestedIdentity(11),
				endpointFlags:     flagsT,
			},
			expected: &resourceInfo{
				source:            source.Local,
				tunnelPeer:        types.TunnelPeer{Addr: ipA},
				encryptKey:        types.EncryptKey(1),
				requestedIdentity: types.RequestedIdentity(10),
				endpointFlags:     flagsF,
			},
		},
		// half and half, no conflicts
		{
			resourceA: &resourceInfo{
				source:     source.Local,
				tunnelPeer: types.TunnelPeer{Addr: ipA},
				encryptKey: types.EncryptKey(1),
			},
			resourceB: &resourceInfo{
				requestedIdentity: types.RequestedIdentity(11),
				endpointFlags:     flagsT,
				labels:            labels.NewLabelsFromSortedList("source:a=b;source:k=v;"),
			},
			expected: &resourceInfo{
				labels:            labels.NewLabelsFromSortedList("source:a=b;source:k=v;"),
				source:            source.Local,
				tunnelPeer:        types.TunnelPeer{Addr: ipA},
				encryptKey:        types.EncryptKey(1),
				requestedIdentity: types.RequestedIdentity(11),
				endpointFlags:     flagsT,
			},
		},
		// identity override from higher precedence
		{
			resourceA: &resourceInfo{
				source:           source.Local,
				labels:           labels.NewLabelsFromSortedList("source:a=b;"),
				identityOverride: true,
			},
			resourceB: &resourceInfo{
				source: source.Generated,
				labels: labels.NewLabelsFromSortedList("source:a=x;source:c=d;"),
			},
			expected: &resourceInfo{
				source:           source.Local,
				labels:           labels.NewLabelsFromSortedList("source:a=b"),
				identityOverride: true,
			},
		},
		// identity override from lower precedence
		{
			resourceA: &resourceInfo{
				source: source.Local, // Local has higher precedence, but we will override it
				labels: labels.NewLabelsFromSortedList("source:a=b;"),
			},
			resourceB: &resourceInfo{
				source:           source.Generated,
				labels:           labels.NewLabelsFromSortedList("source:a=x;source:c=d;"),
				identityOverride: true,
			},
			expected: &resourceInfo{
				source:           source.Local,
				labels:           labels.NewLabelsFromSortedList("source:a=x;source:c=d;"),
				identityOverride: true,
			},
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			logger := hivetest.Logger(t)
			logger.Info("warnings are expected here")
			pi := newPrefixInfo()

			// resources are prioritized by source and lexicographical resource ordering.
			pi.byResource["resourceA"] = test.resourceA
			pi.byResource["resourceB"] = test.resourceB
			pi.flattened = pi.flatten(logger)
			assert.Equal(t, test.expected, pi.flattened)

			// Test that one resource is exactly copied
			pi = newPrefixInfo()
			pi.byResource["resourceA"] = test.resourceA
			pi.flattened = pi.flatten(logger)
			assert.Equal(t, test.resourceA, pi.flattened)

			pi = newPrefixInfo()
			pi.byResource["resourceA"] = test.resourceB
			pi.flattened = pi.flatten(logger)
			assert.Equal(t, test.resourceB, pi.flattened)

			// also test that merging two identical resources is sane.
			pi = newPrefixInfo()
			pi.byResource["resourceA"] = test.resourceA
			pi.byResource["resourceB"] = test.resourceA
			pi.flattened = pi.flatten(logger)
			assert.Equal(t, test.resourceA, pi.flattened)

			pi = newPrefixInfo()
			pi.byResource["resourceA"] = test.resourceB
			pi.byResource["resourceB"] = test.resourceB
			pi.flattened = pi.flatten(logger)
			assert.Equal(t, test.resourceB, pi.flattened)

		})
	}
}

func TestResourceHas(t *testing.T) {
	flagsT := ipcacheTypes.EndpointFlags{}
	flagsT.SetSkipTunnel(true)

	flagsF := ipcacheTypes.EndpointFlags{}
	flagsF.SetSkipTunnel(false)

	tests := []struct {
		existing []IPMetadata
		new      []IPMetadata
		expected bool
	}{

		// Note: we test every metadata set with itself, so there's
		// no need to supply any cases where existing == new

		{
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b;c=d"), ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("1.1.1.1")}},
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b")},
			true,
		},

		{
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b")},
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b;c=d")},
			false,
		},
		{
			[]IPMetadata{overrideIdentity(true), labels.NewLabelsFromSortedList("a=b")},
			[]IPMetadata{overrideIdentity(false), labels.NewLabelsFromSortedList("a=b")},
			false,
		},
		{
			[]IPMetadata{overrideIdentity(true), ipcacheTypes.EncryptKey(1)},
			[]IPMetadata{overrideIdentity(true)},
			true,
		},
		{
			[]IPMetadata{ipcacheTypes.EncryptKey(1)},
			[]IPMetadata{ipcacheTypes.EncryptKey(2)},
			false,
		},
		{
			[]IPMetadata{ipcacheTypes.RequestedIdentity(1)},
			[]IPMetadata{ipcacheTypes.RequestedIdentity(2)},
			false,
		},
		{
			[]IPMetadata{flagsF},
			[]IPMetadata{flagsT},
			false,
		},
		{
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b;c=d")},
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b")},
			true,
		},
		{
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b;c=d")},
			[]IPMetadata{labels.NewLabelsFromSortedList("a=b"), ipcacheTypes.EncryptKey(42)},
			false,
		},
	}

	logger := hivetest.Logger(t)

	for i, tc := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			ri := &resourceInfo{}
			for _, meta := range tc.existing {
				ri.merge(logger, meta, source.KVStore)
			}

			assert.Equal(t, tc.expected, ri.has(source.KVStore, tc.new))

			// Ensure that merging from existing is always true
			assert.True(t, ri.has(source.KVStore, tc.existing))

			// ensure that merging from empty is always false
			ri = &resourceInfo{source: source.KVStore}
			assert.False(t, ri.has(source.KVStore, tc.new))
			assert.False(t, ri.has(source.KVStore, tc.existing))

			for _, meta := range tc.new {
				ri.merge(logger, meta, source.KVStore)
			}
			assert.True(t, ri.has(source.KVStore, tc.new))
		})
	}
}
