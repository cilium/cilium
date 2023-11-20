// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// We use similar local listen ports as the tests in the pkg/bgpv1/test package.
// It is important to NOT use ports from the /proc/sys/net/ipv4/ip_local_port_range
// (defaulted to 32768-60999 on most Linux distributions) to avoid collisions with
// the ephemeral (source) ports. As this range is configurable, ideally, we should
// use the IANA-assigned ports below 1024 (e.g. 179) or mock GoBGP in these tests.
// See https://github.com/cilium/cilium/issues/26209 for more info.
const (
	localListenPort  = 1793
	localListenPort2 = 1794
)

// TestPreflightReconciler ensures if a BgpServer must be recreated, due to
// permanent configuration of the said server changing, its done so correctly.
func TestPreflightReconciler(t *testing.T) {
	var table = []struct {
		// name of test
		name string
		// routerID of original server
		routerID string
		// routerID to reconcile
		newRouterID string
		// local listen port of original server
		localPort int32
		// local listen port to reconcile
		newLocalPort int32
		// virtual router configuration to reconcile, used mostly for pointer
		// comparison
		config *v2alpha1api.CiliumBGPVirtualRouter
		// should a recreation of the BgpServer
		shouldRecreate bool
		// export a nil error or not
		err error
	}{
		{
			name:           "no change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.1",
			localPort:      localListenPort,
			newLocalPort:   localListenPort,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: false,
			err:            nil,
		},
		{
			name:           "router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      localListenPort,
			newLocalPort:   localListenPort,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.1",
			localPort:      localListenPort,
			newLocalPort:   localListenPort2,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port, router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      localListenPort,
			newLocalPort:   localListenPort2,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   tt.routerID,
					ListenPort: tt.localPort,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test BgpServer: %v", err)
			}

			// keep a pointer to the original server to avoid gc and to check
			// later
			originalServer := testSC.Server
			t.Cleanup(func() {
				originalServer.Stop() // stop our test server
				testSC.Server.Stop()  // stop any recreated server
			})

			// attach original config
			testSC.Config = tt.config
			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN: 64125,
			}

			preflightReconciler := NewPreflightReconciler().Reconciler
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "Test Node",
						Annotations: map[string]string{
							"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", tt.newRouterID, tt.newLocalPort),
						},
					},
				},
			}

			err = preflightReconciler.Reconcile(context.Background(), params)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("wanted error: %v", (tt.err == nil))
			}
			if tt.shouldRecreate && testSC.Server == originalServer {
				t.Fatalf("preflightReconciler did not recreate server")
			}
			getBgpResp, err := testSC.Server.GetBGP(context.Background())
			if err != nil {
				t.Fatalf("failed to retrieve BGP Info for BgpServer under test: %v", err)
			}
			bgpInfo := getBgpResp.Global
			if bgpInfo.RouterID != tt.newRouterID {
				t.Fatalf("got: %v, want: %v", bgpInfo.RouterID, tt.newRouterID)
			}
			if bgpInfo.ListenPort != int32(tt.newLocalPort) {
				t.Fatalf("got: %v, want: %v", bgpInfo.ListenPort, tt.newLocalPort)
			}
		})
	}
}

// TestReconcileAfterServerReinit reproduces issue #24975, validates service reconcile works after router-id is
// modified.
func TestReconcileAfterServerReinit(t *testing.T) {
	var (
		routerID        = "192.168.0.1"
		localPort       = int32(localListenPort)
		localASN        = int64(64125)
		newRouterID     = "192.168.0.2"
		diffstore       = newFakeDiffStore[*slim_corev1.Service]()
		epDiffStore     = newFakeDiffStore[*k8s.Endpoints]()
		serviceSelector = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
		obj             = &slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "svc-1",
				Namespace: "default",
				Labels: map[string]string{
					"color": "blue",
				},
			},
			Spec: slim_corev1.ServiceSpec{
				Type: slim_corev1.ServiceTypeLoadBalancer,
			},
			Status: slim_corev1.ServiceStatus{
				LoadBalancer: slim_corev1.LoadBalancerStatus{
					Ingress: []slim_corev1.LoadBalancerIngress{
						{
							IP: "1.2.3.4",
						},
					},
				},
			},
		}
	)

	// Initial router configuration
	srvParams := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        64125,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	}

	testSC, err := NewServerWithConfig(context.Background(), srvParams)
	require.NoError(t, err)

	originalServer := testSC.Server
	t.Cleanup(func() {
		originalServer.Stop() // stop our test server
		testSC.Server.Stop()  // stop any recreated server
	})

	// Validate pod CIDR and service announcements work as expected
	newc := &v2alpha1api.CiliumBGPVirtualRouter{
		LocalASN:        localASN,
		ExportPodCIDR:   pointer.Bool(true),
		Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
		ServiceSelector: serviceSelector,
	}

	exportPodCIDRReconciler := NewExportPodCIDRReconciler().Reconciler
	params := ReconcileParams{
		CurrentServer: testSC,
		DesiredConfig: newc,
		CiliumNode: &v2api.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "Test Node",
				Annotations: map[string]string{
					"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", routerID, localPort),
				},
			},
		},
	}

	err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	diffstore.Upsert(obj)
	reconciler := NewLBServiceReconciler(diffstore, epDiffStore)
	err = reconciler.Reconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// update server config, this is done outside of reconcilers
	testSC.Config = newc

	params.CiliumNode.Annotations = map[string]string{
		"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", newRouterID, localPort),
	}

	preflightReconciler := NewPreflightReconciler().Reconciler

	// Trigger pre flight reconciler
	err = preflightReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// Test pod CIDR reconciler is working
	err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// Update LB service
	reconciler = NewLBServiceReconciler(diffstore, epDiffStore)
	err = reconciler.Reconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)
}
