// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

var (
	TestHostIfName          = string("cheese")
	TestPeerIfName          = string("toast")
	TestEndpointID          = string("d34db33fc4f3:linkpeertest0")
	TestEndpointTmpIfName   = string("tmpd34db")
	TestEndpointFinalIfName = string("linkpeertest0")

	// MTU values
	TestStandardMTU = int(1500)
	TestSmallMTU    = int(1200)

	// GRO values
	TestGROMaxSize = int(16384)
	TestGSOMaxSize = int(8192)

	NamedLinkConfig = types.LinkConfig{
		HostIfName: TestHostIfName,
		PeerIfName: TestPeerIfName,
		DeviceMTU:  TestStandardMTU,
	}
	EndpointLinkConfig = types.LinkConfig{
		EndpointID: TestEndpointID,
		DeviceMTU:  TestStandardMTU,
	}
)

func createFakePair(h *netlink.Handle, hostIfName string, peerIfName string) error {
	if h == nil {
		return fmt.Errorf("bad netlink handle")
	}
	if hostIfName == "" || peerIfName == "" {
		return fmt.Errorf("no ifnames supplied")
	}

	hostMacAddr, err := mac.GenerateRandMAC()
	if err != nil {
		return fmt.Errorf("error generating host mac addr: %w", err)
	}

	peerMacAddr, err := mac.GenerateRandMAC()
	if err != nil {
		return fmt.Errorf("error generating fake peer mac addr: %w", err)
	}

	hostVeth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         hostIfName,
			HardwareAddr: net.HardwareAddr(hostMacAddr),
			TxQLen:       1000,
		},
		PeerName:         peerIfName,
		PeerHardwareAddr: net.HardwareAddr(peerMacAddr),
	}
	if err := h.LinkAdd(hostVeth); err != nil {
		return fmt.Errorf("error creating fake veth pair: %w", err)
	}

	return nil
}

func queryLinkSafe(h *netlink.Handle, ifName string) (netlink.Link, error) {
	if h == nil {
		return nil, fmt.Errorf("bad netlink handle")
	}
	return safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return h.LinkByName(ifName)
	})
}

func queryFakePair(h *netlink.Handle, hostIfName string, peerIfName string) (netlink.Link, netlink.Link, error) {
	hostLink, err := queryLinkSafe(h, hostIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("error querying fake host interface: %w", err)
	}

	peerLink, err := queryLinkSafe(h, peerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("error querying fake peer interface: %w", err)
	}

	return hostLink, peerLink, nil
}

func TestPrivilegedNewLinkPair(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	tests := []struct {
		name        string
		mode        types.ConnectorMode
		cfg         types.LinkConfig
		shouldSkip  bool
		shouldError bool
	}{
		// mode=unspec
		{
			name:        "mode-unspec+named",
			mode:        types.ConnectorModeUnspec,
			cfg:         NamedLinkConfig,
			shouldSkip:  false,
			shouldError: true,
		},
		{
			name:        "mode-unspec+endpoint",
			mode:        types.ConnectorModeUnspec,
			cfg:         EndpointLinkConfig,
			shouldSkip:  false,
			shouldError: true,
		},

		// mode=veth, missing names and endpoint ID
		{
			name: "mode-veth+no-names-and-endpoint",
			mode: types.ConnectorModeVeth,
			cfg: types.LinkConfig{
				DeviceMTU: TestStandardMTU,
			},
			shouldSkip:  false,
			shouldError: true,
		},

		// mode=veth, only with HostIfName
		{
			name: "mode-veth+hostifname-only",
			mode: types.ConnectorModeVeth,
			cfg: types.LinkConfig{
				HostIfName: "hostifnameonly",
				DeviceMTU:  TestStandardMTU,
			},
			shouldSkip:  false,
			shouldError: true,
		},

		// mode=veth, only with PeerIfName
		{
			name: "mode-veth+peerifname-only",
			mode: types.ConnectorModeVeth,
			cfg: types.LinkConfig{
				PeerIfName: "peerifnameonly",
				DeviceMTU:  TestStandardMTU,
			},
			shouldSkip:  false,
			shouldError: true,
		},

		// mode=veth
		{
			name:        "mode-veth+named",
			mode:        types.ConnectorModeVeth,
			cfg:         NamedLinkConfig,
			shouldSkip:  false,
			shouldError: false,
		},
		{
			name:        "mode-veth+endpoint",
			mode:        types.ConnectorModeVeth,
			cfg:         EndpointLinkConfig,
			shouldSkip:  false,
			shouldError: false,
		},

		// mode=netkit
		{
			name:        "mode-netkit+named",
			mode:        types.ConnectorModeNetkit,
			cfg:         NamedLinkConfig,
			shouldSkip:  !hostSupportsNetkit(),
			shouldError: false,
		},
		{
			name:        "mode-netkit+endpoint",
			mode:        types.ConnectorModeNetkit,
			cfg:         EndpointLinkConfig,
			shouldSkip:  !hostSupportsNetkit(),
			shouldError: false,
		},

		// mode=netkit-l2
		{
			name:        "mode-netkit-l2+named",
			mode:        types.ConnectorModeNetkitL2,
			cfg:         NamedLinkConfig,
			shouldSkip:  !hostSupportsNetkit(),
			shouldError: false,
		},
		{
			name:        "mode-netkit-l2+endpoint",
			mode:        types.ConnectorModeNetkitL2,
			cfg:         EndpointLinkConfig,
			shouldSkip:  !hostSupportsNetkit(),
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			var linkPair *LinkPair

			ns := netns.NewNetNS(t)
			assert.NoError(t, ns.Do(func() error {
				ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

				var err error
				linkPair, err = NewLinkPair(log, tt.mode, tt.cfg, ctl)

				if tt.shouldError && err != nil {
					return nil
				}
				return err
			}))

			if tt.shouldError {
				assert.Nil(t, linkPair)
			} else if assert.NotNil(t, linkPair) {
				assert.NotNil(t, linkPair.hostLink)
				assert.NotNil(t, linkPair.peerLink)
				assert.Equal(t, linkPair.mode, tt.mode)
			}
		})
	}
}

func TestPrivilegedConfigureLinkPair(t *testing.T) {
	testutils.PrivilegedTest(t)

	cfg := types.LinkConfig{
		DeviceMTU:      TestSmallMTU,
		GROIPv4MaxSize: TestGROMaxSize,
		GROIPv6MaxSize: TestGROMaxSize,
		GSOIPv4MaxSize: TestGSOMaxSize,
		GSOIPv6MaxSize: TestGSOMaxSize,
	}

	var h *netlink.Handle
	ns := netns.NewNetNS(t)

	require.NoError(t, ns.Do(func() error {
		var err error

		h, err = safenetlink.NewHandle(nil)
		if err != nil {
			return fmt.Errorf("bad netlink handle: %w", err)
		}

		// For the purposes of this test, we will operate on a dummy veth pair.
		if err := createFakePair(h, TestHostIfName, TestPeerIfName); err != nil {
			return err
		}

		hostLink, peerLink, err := queryFakePair(h, TestHostIfName, TestPeerIfName)
		if err != nil {
			return err
		}

		if err := configureLinkPair(hostLink, peerLink, cfg); err != nil {
			return err
		}

		return nil
	}))

	// Query the kernel to read our changes back to verify they applied
	newHostLink, newPeerLink, err := queryFakePair(h, TestHostIfName, TestPeerIfName)
	if assert.NoError(t, err) {
		assertLinkConfig := func(attrs *netlink.LinkAttrs, cfg *types.LinkConfig) {
			// MTU
			assert.Equal(t, attrs.MTU, cfg.DeviceMTU)

			// GRO
			assert.Equal(t, attrs.GROIPv4MaxSize, uint32(cfg.GROIPv4MaxSize))
			assert.Equal(t, attrs.GROMaxSize, uint32(cfg.GROIPv6MaxSize))

			// GSO
			assert.Equal(t, attrs.GSOIPv4MaxSize, uint32(cfg.GSOIPv4MaxSize))
			assert.Equal(t, attrs.GSOMaxSize, uint32(cfg.GSOIPv6MaxSize))
		}
		if assert.NotNil(t, newHostLink) {
			assertLinkConfig(newHostLink.Attrs(), &cfg)
		}
		if assert.NotNil(t, newPeerLink) {
			assertLinkConfig(newPeerLink.Attrs(), &cfg)
		}
	}
}

func TestPrivilegedLinkPairDelete(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	tests := []struct {
		name        string
		mode        types.ConnectorMode
		cfg         types.LinkConfig
		shouldError bool
	}{
		// mode=veth
		{
			name:        "mode-veth+named",
			mode:        types.ConnectorModeVeth,
			cfg:         NamedLinkConfig,
			shouldError: false,
		},
		{
			name:        "mode-veth+endpoint",
			mode:        types.ConnectorModeVeth,
			cfg:         EndpointLinkConfig,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var linkPair *LinkPair

			ns := netns.NewNetNS(t)
			require.NoError(t, ns.Do(func() error {
				var err error

				ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
				linkPair, err = NewLinkPair(log, tt.mode, tt.cfg, ctl)

				if tt.shouldError && err != nil {
					return nil
				}
				return err
			}))

			if assert.NotNil(t, linkPair) {
				assert.NotNil(t, linkPair.hostLink)
				assert.NotNil(t, linkPair.peerLink)

				require.NoError(t, ns.Do(func() error {
					return linkPair.Delete()
				}))

				assert.Nil(t, linkPair.hostLink)
				assert.Nil(t, linkPair.peerLink)
			}
		})
	}
}
