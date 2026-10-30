// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/endpoint"
	resolverTypes "github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
)

func TestResolveEndpointPodMetadata(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")

	t.Run("local endpoint", func(t *testing.T) {
		endpointGetter := &testutils.FakeEndpointManager{
			OnLookupIP: func(ip netip.Addr) *endpoint.Endpoint {
				return &endpoint.Endpoint{K8sUID: "local-pod-uid"}
			},
		}
		resolver := NewEndpointGetter(hivetest.Logger(t), nil, nil, endpointGetter)

		endpoint := resolver.ResolveEndpoint(ip, 0, resolverTypes.DatapathContext{})

		assert.Equal(t, "local-pod-uid", endpoint.GetPodUid())
	})

	t.Run("local endpoint Pod fallback", func(t *testing.T) {
		endpointGetter := &testutils.FakeEndpointManager{
			OnLookupIP: func(ip netip.Addr) *endpoint.Endpoint {
				return &endpoint.Endpoint{K8sUID: "cached-pod-uid"}
			},
		}
		resolver := NewEndpointGetter(hivetest.Logger(t), nil, nil, endpointGetter)

		endpoint := resolver.ResolveEndpoint(ip, 0, resolverTypes.DatapathContext{})

		assert.Equal(t, "cached-pod-uid", endpoint.GetPodUid())
	})

	t.Run("remote endpoint", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
				return &ipcache.K8sMetadata{
					PodUID: "remote-pod-uid",
					Workload: &ipcache.K8sWorkload{
						Name: "remote-workload",
						Kind: "Deployment",
					},
				}
			},
			OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
				return ipcache.Identity{}, false
			},
		}
		resolver := NewEndpointGetter(hivetest.Logger(t), nil, ipGetter, nil)

		endpoint := resolver.ResolveEndpoint(ip, 0, resolverTypes.DatapathContext{})

		assert.Equal(t, "remote-pod-uid", endpoint.GetPodUid())
		assert.Equal(t, []*flowpb.Workload{{Name: "remote-workload", Kind: "Deployment"}}, endpoint.GetWorkloads())
	})

	t.Run("unknown UID", func(t *testing.T) {
		resolver := NewEndpointGetter(hivetest.Logger(t), nil, nil, nil)

		endpoint := resolver.ResolveEndpoint(ip, 0, resolverTypes.DatapathContext{})

		assert.Empty(t, endpoint.GetPodUid())
	})
}
