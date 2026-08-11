// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestResolveEndpointPodUID(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")

	t.Run("local endpoint", func(t *testing.T) {
		endpointGetter := &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
				return &testutils.FakeEndpointInfo{PodUID: "local-pod-uid"}, true
			},
		}
		resolver := NewEndpointResolver(hivetest.Logger(t), endpointGetter, nil, nil)

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Equal(t, "local-pod-uid", endpoint.GetPodUid())
	})

	t.Run("local endpoint Pod fallback", func(t *testing.T) {
		endpointGetter := &testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
				return &testutils.FakeEndpointInfo{Pod: &slim_corev1.Pod{
					ObjectMeta: slim_metav1.ObjectMeta{
						UID: k8sTypes.UID("cached-pod-uid"),
					},
				}}, true
			},
		}
		resolver := NewEndpointResolver(hivetest.Logger(t), endpointGetter, nil, nil)

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Equal(t, "cached-pod-uid", endpoint.GetPodUid())
	})

	t.Run("remote endpoint", func(t *testing.T) {
		ipGetter := &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
				return &ipcache.K8sMetadata{PodUID: "remote-pod-uid"}
			},
			OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
				return ipcache.Identity{}, false
			},
		}
		resolver := NewEndpointResolver(hivetest.Logger(t), nil, nil, ipGetter)

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Equal(t, "remote-pod-uid", endpoint.GetPodUid())
	})

	t.Run("unknown UID", func(t *testing.T) {
		resolver := NewEndpointResolver(hivetest.Logger(t), nil, nil, nil)

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Empty(t, endpoint.GetPodUid())
	})
}
