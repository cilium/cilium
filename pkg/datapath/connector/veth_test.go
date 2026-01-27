// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedSetupVethPair(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	tests := []struct {
		name              string
		cfg               types.LinkConfig
		expectedHwAddrLen int
	}{
		{
			name:              "veth",
			cfg:               NamedLinkConfig,
			expectedHwAddrLen: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h *netlink.Handle
			var hostLink *netlink.Veth
			var peerLink netlink.Link

			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				var err error

				ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
				hostLink, peerLink, err = setupVethPair(log, tt.cfg, ctl)
				if err != nil {
					return err
				}

				h, err = safenetlink.NewHandle(nil)
				return err
			}))

			require.NotNil(t, hostLink)
			require.NotNil(t, peerLink)
			require.NotNil(t, h)

			hostLink2 := queryLinkSafe(t, h, tt.cfg.HostIfName)
			hostVeth, hostOk := hostLink2.(*netlink.Veth)
			require.True(t, hostOk, "expected hostLink2 to be *netlink.Veth")
			require.NotNil(t, hostVeth)
			assert.Len(t, hostLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)

			peerLink2 := queryLinkSafe(t, h, tt.cfg.PeerIfName)
			peerVeth, peerOk := peerLink2.(*netlink.Veth)
			require.True(t, peerOk, "expected peerLink2 to be *netlink.Veth")
			require.NotNil(t, peerVeth)
			assert.Len(t, peerLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)
		})
	}
}
