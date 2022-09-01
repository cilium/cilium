// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package gobgp

import (
	"context"
	"net"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"

	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
			startReq := &gobgp.StartBgpRequest{
				Global: &gobgp.Global{
					Asn:        64125,
					RouterId:   tt.routerID,
					ListenPort: int32(tt.localPort),
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), startReq)
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
				Annotations: bgpv1.AnnotationMap{
					64125: bgpv1.Attributes{
						RouterID:  tt.newRouterID,
						LocalPort: tt.newLocalPort,
					},
				},
			}

			err = preflightReconciler(context.Background(), nil, testSC, newc, cstate)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("wanted error: %v", (tt.err == nil))
			}
			if tt.shouldRecreate && testSC.Server == originalServer {
				t.Fatalf("preflightReconciler did not recreate server")
			}
			bgpInfo, err := testSC.Server.GetBgp(context.Background(), &gobgp.GetBgpRequest{})
			if err != nil {
				t.Fatalf("failed to retrieve BGP Info for BgpServer under test: %v", err)
			}
			if bgpInfo.Global.RouterId != tt.newRouterID {
				t.Fatalf("got: %v, want: %v", bgpInfo.Global.RouterId, tt.newRouterID)
			}
			if bgpInfo.Global.ListenPort != int32(tt.newLocalPort) {
				t.Fatalf("got: %v, want: %v", bgpInfo.Global.ListenPort, tt.newLocalPort)
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
		neighbors []string
		// new neighbors to configure, expanded into CiliumBGPNeighbor.
		//
		// this is the resulting neighbors we expect on the BgpServer.
		newNeighbors []string
		// error provided or nil
		err error
	}{
		{
			name: "no change",
			neighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
			},
			newNeighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
			},
			err: nil,
		},
		{
			name: "additional neighbor",
			neighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
			},
			newNeighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
				"192.168.0.3/32",
			},
			err: nil,
		},
		{
			name: "remove neighbor",
			neighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
				"192.168.0.3/32",
			},
			newNeighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
			},
			err: nil,
		},
		{
			name: "remove all neighbor",
			neighbors: []string{
				"192.168.0.1/32",
				"192.168.0.2/32",
				"192.168.0.3/32",
			},
			newNeighbors: []string{},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			startReq := &gobgp.StartBgpRequest{
				Global: &gobgp.Global{
					Asn:        64125,
					RouterId:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), startReq)
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
				oldc.Neighbors = append(oldc.Neighbors, v2alpha1api.CiliumBGPNeighbor{
					PeerAddress: n,
					PeerASN:     64124,
				})
				testSC.AddNeighbor(context.Background(), &v2alpha1api.CiliumBGPNeighbor{
					PeerAddress: n,
					PeerASN:     64124,
				})
			}
			testSC.Config = oldc

			// create new virtual router config with desired neighbors
			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  64125,
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			for _, n := range tt.newNeighbors {
				newc.Neighbors = append(newc.Neighbors, v2alpha1api.CiliumBGPNeighbor{
					PeerAddress: n,
					PeerASN:     64124,
				})
			}

			err = neighborReconciler(context.Background(), nil, testSC, newc, nil)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want error: %v, got: %v", (tt.err == nil), err)
			}

			// check testSC for desired neighbors
			var peers []*gobgp.Peer
			err = testSC.Server.ListPeer(context.Background(), &gobgp.ListPeerRequest{}, func(peer *gobgp.Peer) {
				peers = append(peers, peer)
			})
			if err != nil {
				t.Fatalf("failed creating test BgpServer: %v", err)
			}

			if len(tt.newNeighbors) == 0 && len(peers) > 0 {
				t.Fatalf("got: %v, want: %v", len(peers), len(tt.newNeighbors))
			}

			for _, n := range tt.newNeighbors {
				ip, _, err := net.ParseCIDR(n)
				if err != nil {
					t.Fatalf("failed to parse neighbor ip: %v", err)
				}
				var seen bool
				for _, p := range peers {
					ipp := net.ParseIP(p.Conf.NeighborAddress)
					if ip.Equal(ipp) {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("wanted neighbor %v, not present", n)
				}
			}

			for _, p := range peers {
				ip := net.ParseIP(p.Conf.NeighborAddress)
				var seen bool
				for _, n := range tt.newNeighbors {
					ipp, _, err := net.ParseCIDR(n)
					if err != nil {
						t.Fatalf("failed to parse peer ip: %v", err)
					}
					if ip.Equal(ipp) {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("wanted peer %v, not present", p.Conf.NeighborAddress)
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
		advertised []*net.IPNet
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
			advertised: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
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
			advertised: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
			updated: []string{"192.168.0.0/24"},
		},
		{
			name:         "additional network",
			enabled:      true,
			shouldEnable: true,
			advertised: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
			updated: []string{"192.168.0.0/24", "192.168.1.0/24"},
		},
		{
			name:         "removal of network",
			enabled:      true,
			shouldEnable: true,
			advertised: []*net.IPNet{
				{
					IP:   net.ParseIP("192.168.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
				{
					IP:   net.ParseIP("192.168.1.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
			updated: []string{"192.168.0.0/24"},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			startReq := &gobgp.StartBgpRequest{
				Global: &gobgp.Global{
					Asn:        64125,
					RouterId:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: tt.enabled,
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			testSC, err := NewServerWithConfig(context.Background(), startReq)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc
			for _, cidr := range tt.advertised {
				advrt, err := testSC.AdvertisePath(context.Background(), cidr)
				if err != nil {
					t.Fatalf("failed to advertise initial pod cidr routes: %v", err)
				}
				testSC.PodCIDRAnnouncements = append(testSC.PodCIDRAnnouncements, advrt)
			}

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: tt.shouldEnable,
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			newcstate := agent.ControlPlaneState{
				PodCIDRs: tt.updated,
				IPv4:     net.ParseIP("127.0.0.1"),
			}

			err = exportPodCIDRReconciler(context.Background(), nil, testSC, newc, &newcstate)
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
				_, parsed, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatalf("failed to parse updated cidr: %v", err)
				}
				var seen bool
				for _, advrt := range testSC.PodCIDRAnnouncements {
					if advrt.Net.String() == parsed.String() {
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
					_, parsed, err := net.ParseCIDR(cidr)
					if err != nil {
						t.Fatalf("failed to parse updated cidr: %v", err)
					}
					if advrt.Net.String() == parsed.String() {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("unwated advert %+v", advrt)
				}
			}

		})
	}
}
