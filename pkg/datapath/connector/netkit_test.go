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

func TestPrivilegedSetupNetkitPair(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	tests := []struct {
		name              string
		l2mode            bool
		cfg               types.LinkConfig
		expectedMode      netlink.NetkitMode
		expectedHwAddrLen int
		shouldSkip        bool
	}{
		{
			name:              "netkit",
			l2mode:            false,
			cfg:               NamedLinkConfig,
			expectedMode:      netlink.NETKIT_MODE_L3,
			expectedHwAddrLen: 0,
			shouldSkip:        !hostSupportsNetkit(),
		},
		{
			name:              "netkit+tbm",
			l2mode:            false,
			cfg:               NamedLinkConfigTBM,
			expectedMode:      netlink.NETKIT_MODE_L3,
			expectedHwAddrLen: 0,
			shouldSkip:        !hostSupportsNetkitTunedBufferMargins(),
		},
		{
			name:              "netkit-l2",
			l2mode:            true,
			cfg:               NamedLinkConfig,
			expectedMode:      netlink.NETKIT_MODE_L2,
			expectedHwAddrLen: 6,
			shouldSkip:        !hostSupportsNetkit(),
		},
		{
			name:              "netkit-l2+tbm",
			l2mode:            true,
			cfg:               NamedLinkConfigTBM,
			expectedMode:      netlink.NETKIT_MODE_L2,
			expectedHwAddrLen: 6,
			shouldSkip:        !hostSupportsNetkitTunedBufferMargins(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			var h *netlink.Handle
			var hostLink *netlink.Netkit
			var peerLink netlink.Link

			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				var err error

				ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
				hostLink, peerLink, err = setupNetkitPair(logger, tt.cfg, tt.l2mode, ctl)
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
				hostNetkit, hostOk := hostLink2.(*netlink.Netkit)
				assert.True(t, hostOk, "expected hostLink2 to be *netlink.Netkit")
				if assert.NotNil(t, hostNetkit) {
					assert.Equal(t, tt.expectedMode, hostNetkit.Mode)
					assert.Equal(t, netlink.NETKIT_POLICY_FORWARD, hostNetkit.Policy)
					assert.Equal(t, netlink.NETKIT_SCRUB_NONE, hostNetkit.Scrub)
					assert.Equal(t, tt.cfg.DeviceHeadroom, hostNetkit.Headroom)
					assert.Equal(t, tt.cfg.DeviceTailroom, hostNetkit.Tailroom)
				}
				assert.Len(t, hostLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)
			}
			if assert.NotNil(t, peerLink2) {
				peerNetkit, peerOk := peerLink2.(*netlink.Netkit)
				assert.True(t, peerOk, "expected peerLink2 to be *netlink.Netkit")
				if assert.NotNil(t, peerNetkit) {
					assert.Equal(t, tt.expectedMode, peerNetkit.Mode)
					assert.Equal(t, netlink.NETKIT_POLICY_BLACKHOLE, peerNetkit.Policy)
					assert.Equal(t, netlink.NETKIT_SCRUB_DEFAULT, peerNetkit.Scrub)
					assert.Equal(t, tt.cfg.DeviceHeadroom, peerNetkit.Headroom)
					assert.Equal(t, tt.cfg.DeviceTailroom, peerNetkit.Tailroom)
				}
				assert.Len(t, peerLink2.Attrs().HardwareAddr, tt.expectedHwAddrLen)
			}
		})
	}
}
