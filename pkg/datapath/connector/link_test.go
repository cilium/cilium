// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	TestHostIfName          = string("cheese")
	TestPeerIfName          = string("toast")
	TestEndpointID          = string("d34db33fc4f3:linkpeertest0")
	TestEndpointTmpIfName   = string("tmpd34db")
	TestEndpointFinalIfName = string("linkpeertest0")
	TestMTU                 = int(1500)

	NamedLinkConfig = types.LinkConfig{
		HostIfName: TestHostIfName,
		PeerIfName: TestPeerIfName,
		DeviceMTU:  TestMTU,
	}
	EndpointLinkConfig = types.LinkConfig{
		EndpointID: TestEndpointID,
		DeviceMTU:  TestMTU,
	}
)

func deleteInterfaces(log *slog.Logger, ifNames []string) {
	for _, ifName := range ifNames {
		iface, err := safenetlink.LinkByName(ifName)
		if err != nil {
			if !errors.As(err, &netlink.LinkNotFoundError{}) {
				log.Error("Failed to lookup test interface",
					logfields.Interface, ifName,
					logfields.Error, err,
				)
			}
		} else if err = netlink.LinkDel(iface); err != nil {
			if !errors.As(err, &netlink.LinkNotFoundError{}) {
				log.Error("Failed to delete test interface",
					logfields.Interface, ifName,
					logfields.Error, err,
				)
			}
		}
	}
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
				DeviceMTU: TestMTU,
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
				DeviceMTU:  TestMTU,
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
				DeviceMTU:  TestMTU,
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

	testInterfaces := []string{
		TestHostIfName,
		TestEndpointTmpIfName,
		TestEndpointFinalIfName,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSkip {
				t.Skip()
			}

			ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
			linkPair, err := NewLinkPair(log, tt.mode, tt.cfg, ctl)

			switch tt.shouldError {
			case true:
				assert.Error(t, err)
				assert.Nil(t, linkPair)

			case false:
				// Ensure we cleanup before we assert
				t.Cleanup(func() { deleteInterfaces(log, testInterfaces) })

				assert.NoError(t, err)
				if assert.NotNil(t, linkPair) {
					assert.Equal(t, linkPair.mode, tt.mode)
				}
			}
		})
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
			ctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
			linkPair, err := NewLinkPair(log, tt.mode, tt.cfg, ctl)

			assert.NoError(t, err)
			if assert.NotNil(t, linkPair) {
				// Check we can delete this interface pair
				err := linkPair.Delete()
				if assert.NoError(t, err) {
					// Check we can't delete it twice
					err := linkPair.Delete()
					assert.NoError(t, err)
				}
			}
		})
	}
}
