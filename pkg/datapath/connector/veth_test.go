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

			assert.NotNil(t, hostLink)
			assert.NotNil(t, peerLink)
			assert.NotNil(t, h)

			// Re-query the kernel for the created interfaces

			hostLink2, peerLink2, err := queryFakePair(h, tt.cfg.HostIfName, tt.cfg.PeerIfName)
			assert.NoError(t, err)
			if assert.NotNil(t, hostLink2) {
				hostVeth, hostOk := hostLink2.(*netlink.Veth)
				assert.True(t, hostOk, "expected hostLink2 to be *netlink.Veth")
				assert.NotNil(t, hostVeth)
				assert.Len(t, hostLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)
			}
			if assert.NotNil(t, peerLink2) {
				peerVeth, peerOk := peerLink2.(*netlink.Veth)
				assert.True(t, peerOk, "expected peerLink2 to be *netlink.Veth")
				assert.NotNil(t, peerVeth)
				assert.Len(t, peerLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)
			}
		})
	}
}
