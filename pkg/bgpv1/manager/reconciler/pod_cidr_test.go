// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"net/netip"
	"testing"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

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
		// the updated PodCIDR blocks to reconcile.
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

	// Dummy daemon config and logger
	daemonConfig := &option.DaemonConfig{IPAM: "Kubernetes"}

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
				ExportPodCIDR: ptr.To[bool](tt.enabled),
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			testSC, err := instance.NewServerWithConfig(context.Background(), log, srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc
			reconciler := NewExportPodCIDRReconciler(daemonConfig).Reconciler.(*ExportPodCIDRReconciler)
			podCIDRAnnouncements := reconciler.getMetadata(testSC)
			for _, cidr := range tt.advertised {
				advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
					Path: types.NewPathForPrefix(cidr),
				})
				if err != nil {
					t.Fatalf("failed to advertise initial pod cidr routes: %v", err)
				}
				podCIDRAnnouncements = append(podCIDRAnnouncements, advrtResp.Path)
			}
			reconciler.storeMetadata(testSC, podCIDRAnnouncements)

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: ptr.To[bool](tt.shouldEnable),
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}

			exportPodCIDRReconciler := NewExportPodCIDRReconciler(daemonConfig).Reconciler
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "Test Node",
					},
					Spec: v2api.NodeSpec{
						IPAM: ipamtypes.IPAMSpec{
							PodCIDRs: tt.updated,
						},
					},
				},
			}

			// Run the reconciler twice to ensure idempotency. This
			// simulates the retrying behavior of the controller.
			for i := 0; i < 2; i++ {
				t.Run(tt.name, func(t *testing.T) {
					err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
					if err != nil {
						t.Fatalf("failed to reconcile new pod cidr advertisements: %v", err)
					}
				})
			}
			podCIDRAnnouncements = reconciler.getMetadata(testSC)

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.shouldEnable == false {
				if len(podCIDRAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements till present")
				}
			}

			log.Printf("%+v %+v", podCIDRAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.PodCIDRAnnouncements
			for _, cidr := range tt.updated {
				prefix := netip.MustParsePrefix(cidr)
				var seen bool
				for _, advrt := range podCIDRAnnouncements {
					if advrt.NLRI.String() == prefix.String() {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("failed to advertise %v", cidr)
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for _, advrt := range podCIDRAnnouncements {
				var seen bool
				for _, cidr := range tt.updated {
					if advrt.NLRI.String() == cidr {
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
