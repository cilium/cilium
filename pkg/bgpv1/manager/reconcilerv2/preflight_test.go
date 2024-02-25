// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/node/addressing"
)

// We use similar local listen ports as the tests in the pkg/bgpv1/test package.
// It is important to NOT use ports from the /proc/sys/net/ipv4/ip_local_port_range
// (defaulted to 32768-60999 on most Linux distributions) to avoid collisions with
// the ephemeral (source) ports. As this range is configurable, ideally, we should
// use the IANA-assigned ports below 1024 (e.g. 179) or mock GoBGP in these tests.
// See https://github.com/cilium/cilium/issues/26209 for more info.
// Note these ports should be different from the ports used in the pkg/bgpv1/manager/reconciler
const (
	localListenPort  = 1780
	localListenPort2 = 1781
	localListenPort3 = 1782
)

// TestPreflightReconciler ensures if a BgpServer must be recreated, due to
// permanent configuration of the said server changing, its done so correctly.
func TestPreflightReconciler(t *testing.T) {
	req := require.New(t)

	var table = []struct {
		// modified BGPNodeInstance config
		configModified bool
		// name of test
		name string
		// ASN of original server
		asn int64
		// routerID of original server
		routerID string
		// routerID to reconcile
		newAnnoRouterID string
		// local node IP, from which router id will be generated as last resort
		nodeIP string
		// local annotation listen port of original server
		localPort int32
		// local annotation listen port to reconcile
		newLocalPort int32
		// virtual router configuration to reconcile
		config *v2alpha1api.CiliumBGPNodeInstance
		// should a recreation of the BgpServer
		shouldRecreate bool
		// export a nil error or not
		err error
	}{
		{
			name:            "no change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
			},
			shouldRecreate: false,
			err:            nil,
		},
		{
			name:            "router-id annotation change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.2",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:         "router-id from node IP",
			asn:          64125,
			routerID:     "192.168.0.1",
			nodeIP:       "192.168.0.3",
			localPort:    localListenPort,
			newLocalPort: localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "router-id config change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
				RouterID: ptr.To[string]("192.168.0.3"),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "router-id annotation and config change", // config change takes precedence
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.2",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
				RouterID: ptr.To[string]("192.168.0.3"),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:            "local-port annotation change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort2,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "local-port config change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:      "test-instance",
				LocalASN:  ptr.To[int64](64125),
				LocalPort: ptr.To[int32](localListenPort2),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "local-port annotation and config change", // config change takes precedence
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort2,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:      "test-instance",
				LocalASN:  ptr.To[int64](64125),
				LocalPort: ptr.To[int32](localListenPort3),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:            "local-port, router-id annotation change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.2",
			localPort:       localListenPort,
			newLocalPort:    localListenPort2,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:     "test-instance",
				LocalASN: ptr.To[int64](64125),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "local-port, router-id config change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:      "test-instance",
				LocalASN:  ptr.To[int64](64125),
				RouterID:  ptr.To[string]("192.168.0.3"),
				LocalPort: ptr.To[int32](localListenPort2),
			},
			shouldRecreate: true,
			err:            nil,
		},
		{
			configModified:  true,
			name:            "ASN in config change",
			asn:             64125,
			routerID:        "192.168.0.1",
			newAnnoRouterID: "192.168.0.1",
			localPort:       localListenPort,
			newLocalPort:    localListenPort,
			config: &v2alpha1api.CiliumBGPNodeInstance{
				Name:      "test-instance",
				LocalASN:  ptr.To[int64](64126),
				RouterID:  ptr.To[string]("192.168.0.1"),
				LocalPort: ptr.To[int32](localListenPort),
			},
			shouldRecreate: true,
			err:            nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        uint32(tt.asn),
					RouterID:   tt.routerID,
					ListenPort: tt.localPort,
				},
			}
			testInstance, err := instance.NewBGPInstance(context.Background(), logrus.WithField("unit_test", "preflight"), srvParams)
			if err != nil {
				req.NoError(err)
			}

			// keep a pointer to the original server to avoid gc and to check
			// later
			originalRouter := testInstance.Router
			t.Cleanup(func() {
				originalRouter.Stop()      // stop our test server
				testInstance.Router.Stop() // stop any recreated server
			})

			preflightReconciler := NewPreflightReconciler(PreflightReconcilerIn{
				Logger: logrus.WithField("unit_test", "preflight"),
			}).Reconciler

			annotationMap := ""
			if tt.newAnnoRouterID != "" && tt.newLocalPort != 0 {
				annotationMap = fmt.Sprintf("router-id=%s,local-port=%d", tt.newAnnoRouterID, tt.newLocalPort)
			} else if tt.newAnnoRouterID != "" {
				annotationMap = fmt.Sprintf("router-id=%s", tt.newAnnoRouterID)
			} else if tt.newLocalPort != 0 {
				annotationMap = fmt.Sprintf("local-port=%d", tt.newLocalPort)
			}

			ciliumNode := &v2api.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: "Test Node",
					Annotations: map[string]string{
						fmt.Sprintf("cilium.io/bgp-virtual-router.%d", tt.asn): annotationMap,
					},
				},
				Spec: v2api.NodeSpec{
					Addresses: []v2api.NodeAddress{
						{
							Type: addressing.NodeInternalIP,
							IP:   tt.nodeIP,
						},
					},
				},
			}

			testInstance.Config = tt.config

			params := ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: tt.config,
				CiliumNode:    ciliumNode,
			}

			err = preflightReconciler.Reconcile(context.Background(), params)
			req.Equal(tt.err == nil, err == nil)

			if tt.shouldRecreate && testInstance.Router == originalRouter {
				req.Fail("preflightReconciler did not recreate router")
			}

			getBgpResp, err := testInstance.Router.GetBGP(context.Background())
			req.NoError(err)

			bgpInfo := getBgpResp.Global

			if tt.configModified {
				if tt.config.LocalASN != nil {
					req.Equal(*tt.config.LocalASN, int64(bgpInfo.ASN))
				}
				if tt.config.RouterID != nil {
					req.Equal(*tt.config.RouterID, bgpInfo.RouterID)
				}
				if tt.config.LocalPort != nil {
					req.Equal(*tt.config.LocalPort, bgpInfo.ListenPort)
				}
			} else {
				// check router ID is as expected (either from annotation or node IP)
				if tt.newAnnoRouterID == "" && tt.nodeIP != "" {
					req.Equal(tt.nodeIP, bgpInfo.RouterID)
				} else {
					req.Equal(tt.newAnnoRouterID, bgpInfo.RouterID)
				}
				req.Equal(tt.newLocalPort, bgpInfo.ListenPort)
			}
		})
	}
}
