// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
		localPort int
		// local listen port to reconcile
		newLocalPort int
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
			localPort:      45450,
			newLocalPort:   45450,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: false,
			err:            nil,
		},
		{
			name:           "router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      45450,
			newLocalPort:   45450,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.1",
			localPort:      45450,
			newLocalPort:   45451,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port, router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      45450,
			newLocalPort:   45451,
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
					ListenPort: int32(tt.localPort),
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
			cstate := &agent.ControlPlaneState{
				Annotations: agent.AnnotationMap{
					64125: agent.Attributes{
						RouterID:  tt.newRouterID,
						LocalPort: tt.newLocalPort,
					},
				},
			}

			err = preflightReconciler(context.Background(), testSC, newc, cstate)
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

// TestNeighborReconciler confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration.
func TestNeighborReconciler(t *testing.T) {
	var table = []struct {
		// name of the test
		name string
		// existing neighbors, expanded to CiliumBGPNeighbor during test
		neighbors []v2alpha1api.CiliumBGPNeighbor
		// new neighbors to configure, expanded into CiliumBGPNeighbor.
		//
		// this is the resulting neighbors we expect on the BgpServer.
		newNeighbors []v2alpha1api.CiliumBGPNeighbor
		// error provided or nil
		err error
	}{
		{
			name: "no change",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			err: nil,
		},
		{
			name: "additional neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32"},
			},
			err: nil,
		},
		{
			name: "remove neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			err: nil,
		},
		{
			name: "update neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", ConnectRetryTime: metav1.Duration{Duration: 120 * time.Second}},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", ConnectRetryTime: metav1.Duration{Duration: 120 * time.Second}},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", ConnectRetryTime: metav1.Duration{Duration: 120 * time.Second}},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", ConnectRetryTime: metav1.Duration{Duration: 99 * time.Second}},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", ConnectRetryTime: metav1.Duration{Duration: 120 * time.Second}},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", ConnectRetryTime: metav1.Duration{Duration: 120 * time.Second}},
			},
			err: nil,
		},
		{
			name: "remove all neighbors",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test BgpServer: %v", err)
			}
			t.Cleanup(func() {
				testSC.Server.Stop()
			})
			// create current vRouter config and add neighbors
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  64125,
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			for _, n := range tt.neighbors {
				oldc.Neighbors = append(oldc.Neighbors, n)
				testSC.Server.AddNeighbor(context.Background(), types.NeighborRequest{
					Neighbor: &n,
				})
			}
			testSC.Config = oldc

			// create new virtual router config with desired neighbors
			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  64125,
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			for _, n := range tt.newNeighbors {
				newc.Neighbors = append(newc.Neighbors, n)
			}

			err = neighborReconciler(context.Background(), testSC, newc, nil)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want error: %v, got: %v", (tt.err == nil), err)
			}

			// check testSC for desired neighbors
			var getPeerResp types.GetPeerStateResponse
			getPeerResp, err = testSC.Server.GetPeerState(context.Background())
			if err != nil {
				t.Fatalf("failed creating test BgpServer: %v", err)
			}
			peers := getPeerResp.Peers

			if len(tt.newNeighbors) == 0 && len(peers) > 0 {
				t.Fatalf("got: %v, want: %v", len(peers), len(tt.newNeighbors))
			}

			for _, n := range tt.newNeighbors {
				prefix := netip.MustParsePrefix(n.PeerAddress)
				var seen bool
				for _, p := range peers {
					addr := netip.MustParseAddr(p.PeerAddress)
					if prefix.Addr() == addr {
						seen = true
						if n.ConnectRetryTime.Duration != 0 && int64(n.ConnectRetryTime.Seconds()) != p.ConnectRetryTimeSeconds {
							t.Fatalf("ConnectRetryTime does not match: wanted: %d, got: %d", int64(n.ConnectRetryTime.Seconds()), p.ConnectRetryTimeSeconds)
						}
					}
				}
				if !seen {
					t.Fatalf("wanted neighbor %v, not present", n)
				}
			}

			for _, p := range peers {
				paddr := netip.MustParseAddr(p.PeerAddress)
				var seen bool
				for _, n := range tt.newNeighbors {
					addr := netip.MustParsePrefix(n.PeerAddress)
					if paddr == addr.Addr() {
						seen = true
						if n.ConnectRetryTime.Duration != 0 && int64(n.ConnectRetryTime.Seconds()) != p.ConnectRetryTimeSeconds {
							t.Fatalf("ConnectRetryTime does not match: wanted: %d, got: %d", int64(n.ConnectRetryTime.Seconds()), p.ConnectRetryTimeSeconds)
						}
					}
				}
				if !seen {
					t.Fatalf("wanted peer %v, not present", p.PeerAddress)
				}
			}
		})
	}
}

func TestExportPodCIDRReconciler(t *testing.T) {
	var table = []struct {
		// name of the test case
		name string
		// whether ExportPodCIDR is enabled at start of test
		enabled bool
		// whether ExportPodCIDR should be enabled before reconciliation
		shouldEnable bool
		// the advertised PodCIDR blocks the test begins with, these are encoded
		// into Golang structs for the convenience of passing directly to the
		// ServerWithConfig.AdvertisePath() method.
		advertised []netip.Prefix
		// the updated PodCIDR blocks to reconcile, these are string encoded
		// for the convenience of attaching directly to the NodeSpec.PodCIDRs
		// field.
		updated []string
		// error nil or not
		err error
	}{
		{
			name:         "disable",
			enabled:      true,
			shouldEnable: false,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
		},
		{
			name:         "enable",
			enabled:      false,
			shouldEnable: true,
			updated:      []string{"192.168.0.0/24"},
		},
		{
			name:         "no change",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			updated: []string{"192.168.0.0/24"},
		},
		{
			name:         "additional network",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			updated: []string{"192.168.0.0/24", "192.168.1.0/24"},
		},
		{
			name:         "removal of both networks",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			updated: []string{},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: tt.enabled,
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc
			for _, cidr := range tt.advertised {
				advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
					Advert: types.Advertisement{
						Prefix: cidr,
					},
				})
				if err != nil {
					t.Fatalf("failed to advertise initial pod cidr routes: %v", err)
				}
				testSC.PodCIDRAnnouncements = append(testSC.PodCIDRAnnouncements, advrtResp.Advert)
			}

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: tt.shouldEnable,
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			newcstate := agent.ControlPlaneState{
				PodCIDRs: tt.updated,
				IPv4:     netip.MustParseAddr("127.0.0.1"),
			}

			err = exportPodCIDRReconciler(context.Background(), testSC, newc, &newcstate)
			if err != nil {
				t.Fatalf("failed to reconcile new pod cidr advertisements: %v", err)
			}

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.shouldEnable == false {
				if len(testSC.PodCIDRAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements till present")
				}
			}

			log.Printf("%+v %+v", testSC.PodCIDRAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.PodCIDRAnnoucements
			for _, cidr := range tt.updated {
				prefix := netip.MustParsePrefix(cidr)
				var seen bool
				for _, advrt := range testSC.PodCIDRAnnouncements {
					if advrt.Prefix == prefix {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("failed to advertise %v", cidr)
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for _, advrt := range testSC.PodCIDRAnnouncements {
				var seen bool
				for _, cidr := range tt.updated {
					if advrt.Prefix == netip.MustParsePrefix(cidr) {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("unwanted advert %+v", advrt)
				}
			}

		})
	}
}

func TestLBServiceReconciler(t *testing.T) {
	var table = []struct {
		// name of the test case
		name string
		// The service selector of the vRouter
		oldServiceSelector *slim_metav1.LabelSelector
		// The service selector of the vRouter
		newServiceSelector *slim_metav1.LabelSelector
		// the advertised PodCIDR blocks the test begins with
		advertised map[resource.Key][]string
		// the services which will be "upserted" in the diffstore
		upsertedServices []*slim_corev1.Service
		// the services which will be "deleted" in the diffstore
		deletedServices []resource.Key
		// the updated PodCIDR blocks to reconcile, these are string encoded
		// for the convenience of attaching directly to the NodeSpec.PodCIDRs
		// field.
		updated map[resource.Key][]string
		// error nil or not
		err error
	}{
		// Add 1 ingress
		{
			name:               "lb-svc-1-ingress",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised:         make(map[resource.Key][]string),
			upsertedServices: []*slim_corev1.Service{
				{
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
				},
			},
			updated: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
		},
		// Add 2 ingress
		{
			name:               "lb-svc-2-ingress",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised:         make(map[resource.Key][]string),
			upsertedServices: []*slim_corev1.Service{
				{
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
								{
									IP: "ff::2.3.4.5",
								},
							},
						},
					},
				},
			},
			updated: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
					"ff::2.3.4.5/128",
				},
			},
		},
		// Delete service
		{
			name:               "delete-svc",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
			deletedServices: []resource.Key{
				{Name: "svc-1", Namespace: "default"},
			},
			updated: map[resource.Key][]string{},
		},
		// Update service to no longer match
		{
			name:               "update-service-no-match",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
			upsertedServices: []*slim_corev1.Service{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"color": "red",
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
				},
			},
			updated: map[resource.Key][]string{},
		},
		// Update vRouter to no longer match
		{
			name:               "update-vrouter-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}},
			advertised: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
			upsertedServices: []*slim_corev1.Service{
				{
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
				},
			},
			updated: map[resource.Key][]string{},
		},
		// 1 -> 2 ingress
		{
			name:               "update-1-to-2-ingress",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
			upsertedServices: []*slim_corev1.Service{
				{
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
								{
									IP: "2.3.4.5",
								},
							},
						},
					},
				},
			},
			updated: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
					"2.3.4.5/32",
				},
			},
		},
		// No selector
		{
			name:               "no-selector",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				{
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
				},
			},
			updated: map[resource.Key][]string{},
		},
		// Namespace selector
		{
			name:               "svc-namespace-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				{
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
				},
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "svc-2",
						Namespace: "non-default",
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
									IP: "2.3.4.5",
								},
							},
						},
					},
				},
			},
			updated: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
			},
		},
		// Service name selector
		{
			name:               "svc-name-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				{
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
				},
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "non-default",
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
									IP: "2.3.4.5",
								},
							},
						},
					},
				},
			},
			updated: map[resource.Key][]string{
				{Name: "svc-1", Namespace: "default"}: {
					"1.2.3.4/32",
				},
				{Name: "svc-1", Namespace: "non-default"}: {
					"2.3.4.5/32",
				},
			},
		},
		// No-LB service
		{
			name:               "non-lb svc",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				{
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
						Labels: map[string]string{
							"color": "blue",
						},
					},
					Spec: slim_corev1.ServiceSpec{
						Type: slim_corev1.ServiceTypeClusterIP,
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
				},
			},
			updated: map[resource.Key][]string{},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.oldServiceSelector,
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc
			for svcKey, cidrs := range tt.advertised {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
						Advert: types.Advertisement{
							Prefix: prefix,
						},
					})
					if err != nil {
						t.Fatalf("failed to advertise initial svc lb cidr routes: %v", err)
					}

					testSC.ServiceAnnouncements[svcKey] = append(testSC.ServiceAnnouncements[svcKey], advrtResp.Advert)
				}
			}

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.newServiceSelector,
			}
			newcstate := agent.ControlPlaneState{
				IPv4: netip.MustParseAddr("127.0.0.1"),
			}

			diffstore := newFakeDiffStore[*slim_corev1.Service]()
			for _, obj := range tt.upsertedServices {
				diffstore.Upsert(obj)
			}
			for _, key := range tt.deletedServices {
				diffstore.Delete(key)
			}

			reconciler := NewLBServiceReconciler(diffstore)
			err = reconciler.Reconciler.Reconcile(context.Background(), ReconcileParams{
				Server: testSC,
				NewC:   newc,
				CState: &newcstate,
			})
			if err != nil {
				t.Fatalf("failed to reconcile new lb svc advertisements: %v", err)
			}

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.newServiceSelector == nil {
				if len(testSC.ServiceAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements till present")
				}
			}

			log.Printf("%+v %+v", testSC.ServiceAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.ServiceAnnouncements
			for svcKey, cidrs := range tt.updated {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					var seen bool
					for _, advrt := range testSC.ServiceAnnouncements[svcKey] {
						if advrt.Prefix == prefix {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("failed to advertise %v", cidr)
					}
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for svcKey, advrts := range testSC.ServiceAnnouncements {
				for _, advrt := range advrts {
					var seen bool
					for _, cidr := range tt.updated[svcKey] {
						if advrt.Prefix == netip.MustParsePrefix(cidr) {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("unwanted advert %+v", advrt)
					}
				}
			}

		})
	}
}

// TestReconcileAfterServerReinit reproduces issue #24975, validates service reconcile works after router-id is
// modified.
func TestReconcileAfterServerReinit(t *testing.T) {
	var (
		routerID        = "192.168.0.1"
		localPort       = 45450
		localASN        = 64125
		newRouterID     = "192.168.0.2"
		diffstore       = newFakeDiffStore[*slim_corev1.Service]()
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
		ExportPodCIDR:   true,
		Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
		ServiceSelector: serviceSelector,
	}

	cstate := &agent.ControlPlaneState{
		Annotations: agent.AnnotationMap{
			localASN: agent.Attributes{
				RouterID:  routerID,
				LocalPort: localPort,
			},
		},
	}

	err = exportPodCIDRReconciler(context.Background(), testSC, newc, cstate)
	require.NoError(t, err)

	diffstore.Upsert(obj)
	reconciler := NewLBServiceReconciler(diffstore)
	err = reconciler.Reconciler.Reconcile(context.Background(), ReconcileParams{
		Server: testSC,
		NewC:   newc,
		CState: cstate,
	})
	require.NoError(t, err)

	// update server config, this is done outside of reconcilers
	testSC.Config = newc

	// Update router-ID
	cstate = &agent.ControlPlaneState{
		Annotations: agent.AnnotationMap{
			localASN: agent.Attributes{
				RouterID:  newRouterID,
				LocalPort: localPort,
			},
		},
	}

	// Trigger pre flight reconciler
	err = preflightReconciler(context.Background(), testSC, newc, cstate)
	require.NoError(t, err)

	// Test pod CIDR reconciler is working
	err = exportPodCIDRReconciler(context.Background(), testSC, newc, cstate)
	require.NoError(t, err)

	// Update LB service
	reconciler = NewLBServiceReconciler(diffstore)
	err = reconciler.Reconciler.Reconcile(context.Background(), ReconcileParams{
		Server: testSC,
		NewC:   newc,
		CState: cstate,
	})
	require.NoError(t, err)
}
