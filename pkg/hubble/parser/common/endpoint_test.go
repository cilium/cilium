// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
)

func TestEndpointResolverResolveEndpoint(t *testing.T) {
	const (
		clusterName = "my-cluster"

		// xwing is on the local node
		xwingIdentity     = 1111
		xwingEndpoint     = 110
		xwingIPv4         = "192.168.10.10"
		xwingIPv6         = "f00d::a10:0:0:10"
		xwingPodName      = "xwing-aaa11"
		xwingPodNamespace = "default"

		// deathstar is on a remote node
		deathstarIdentity     = 2222
		deathstarEndpoint     = 220
		deathstarIPv4         = "192.168.20.20"
		deathstarIPv6         = "f00d::20:20"
		deathstarPodName      = "deathstar-1"
		deathstarPodNamespace = "default"
	)
	var (
		clusterNameLabel  = "k8s:io.cilium.k8s.policy.cluster=" + clusterName
		xwingWorkload     = &flowpb.Workload{Kind: "Deployment", Name: "xwing"}
		xwingLabels       = []string{clusterNameLabel, "k8s:org=alliance"}
		deathstarWorkload = &flowpb.Workload{Kind: "Statefulset", Name: "deathstar"}
		deathstarLabels   = []string{clusterNameLabel, "k8s:org=empire"}
	)

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return &testutils.FakeEndpointInfo{
					ID:           xwingEndpoint,
					Identity:     xwingIdentity,
					IPv4:         net.ParseIP(xwingIPv4),
					IPv6:         net.ParseIP(xwingIPv6),
					Labels:       xwingLabels,
					PodName:      xwingPodName,
					PodNamespace: xwingPodNamespace,
					Workload: &models.Workload{
						Name: xwingWorkload.Name,
						Kind: xwingWorkload.Kind,
					},
				}, true
			}
			return nil, false
		},
	}
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
			switch securityIdentity {
			case xwingIdentity:
				return &identity.Identity{
					ID:     xwingIdentity,
					Labels: labels.NewLabelsFromModel(xwingLabels),
				}, nil
			case deathstarIdentity:
				return &identity.Identity{
					ID:     deathstarIdentity,
					Labels: labels.NewLabelsFromModel(deathstarLabels),
				}, nil
			}
			return nil, errors.New("identity not found")
		},
	}
	ipGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return &ipcache.K8sMetadata{
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
				}
			case deathstarIPv4, deathstarIPv6:
				return &ipcache.K8sMetadata{
					PodName:   deathstarPodName,
					Namespace: deathstarPodNamespace,
					Workload: &models.Workload{
						Name: deathstarWorkload.Name,
						Kind: deathstarWorkload.Kind,
					},
				}
			}
			return nil
		},
		OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return ipcache.Identity{
					ID: xwingIdentity,
				}, true
			case deathstarIPv4, deathstarIPv6:
				return ipcache.Identity{
					ID: deathstarIdentity,
				}, true
			}
			return ipcache.Identity{}, false
		},
	}

	tt := []struct {
		name                     string
		ip                       string
		datapathSecurityIdentity identity.NumericIdentity
		context                  DatapathContext
		want                     *flowpb.Endpoint
	}{
		{
			name: "ip not found",
			ip:   "1.2.3.4",
			want: &flowpb.Endpoint{},
		},
		{
			name:                     "local datapath identity is forwarded",
			ip:                       xwingIPv4,
			datapathSecurityIdentity: 1234,
			want: &flowpb.Endpoint{
				ID:          xwingEndpoint,
				Identity:    1234,
				ClusterName: clusterName,
				Namespace:   xwingPodNamespace,
				PodName:     xwingPodName,
				Labels:      xwingLabels,
				Workloads:   []*flowpb.Workload{xwingWorkload},
			},
		},
		{
			name:                     "local unknown identity resolves to userspace identity",
			ip:                       xwingIPv4,
			datapathSecurityIdentity: identity.IdentityUnknown,
			want: &flowpb.Endpoint{
				ID:          xwingEndpoint,
				Identity:    xwingIdentity,
				ClusterName: clusterName,
				Namespace:   xwingPodNamespace,
				PodName:     xwingPodName,
				Labels:      xwingLabels,
				Workloads:   []*flowpb.Workload{xwingWorkload},
			},
		},
		{
			name:                     "remote datapath identity is always forwarded",
			ip:                       deathstarIPv4,
			datapathSecurityIdentity: deathstarIdentity,
			want: &flowpb.Endpoint{
				// ID is always unset for remote
				Identity:    deathstarIdentity,
				ClusterName: clusterName,
				Namespace:   deathstarPodNamespace,
				PodName:     deathstarPodName,
				Labels:      deathstarLabels,
				Workloads:   []*flowpb.Workload{deathstarWorkload},
			},
		},
		{
			name:                     "remote unknown identity resolves to userspace identity",
			ip:                       deathstarIPv4,
			datapathSecurityIdentity: identity.IdentityUnknown,
			want: &flowpb.Endpoint{
				// ID is always unset for remote
				Identity:    deathstarIdentity,
				ClusterName: clusterName,
				Namespace:   deathstarPodNamespace,
				PodName:     deathstarPodName,
				Labels:      deathstarLabels,
				Workloads:   []*flowpb.Workload{deathstarWorkload},
			},
		},
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	endpointResolver := NewEndpointResolver(log, endpointGetter, identityGetter, ipGetter)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.ip)
			datapathSecurityIdentity := uint32(tc.datapathSecurityIdentity)
			endpoint := endpointResolver.ResolveEndpoint(ip, datapathSecurityIdentity, tc.context)
			assert.Equal(t, tc.want, endpoint)
		})
	}
}
