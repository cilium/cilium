// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
)

var (
	primaryMAC   = mac.MustParseMAC("0a:00:00:00:00:01")
	secondaryMAC = mac.MustParseMAC("0a:00:00:00:00:02")
)

func hwAddr(m mac.MAC) tables.HardwareAddr {
	return tables.HardwareAddr(m.HardwareAddr())
}

func mustParseAddr(t *testing.T, s string) iputil.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return iputil.AddrFrom(addr)
}

func eniNode(t *testing.T) *v2.CiliumNode {
	t.Helper()
	return &v2.CiliumNode{
		Spec: v2.NodeSpec{
			Addresses: []v2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "fd00::1"},
				{Type: addressing.NodeInternalIP, IP: "192.168.0.1"},
			},
		},
		Status: v2.NodeStatus{
			ENI: awsTypes.ENIStatus{
				ENIs: map[string]awsTypes.ENI{
					"eni-primary": {
						ID:     "eni-primary",
						Number: 0,
						IP:     mustParseAddr(t, "192.168.0.1"),
						MAC:    primaryMAC,
					},
					"eni-secondary": {
						ID:     "eni-secondary",
						Number: 1,
						IP:     mustParseAddr(t, "192.168.0.2"),
						MAC:    secondaryMAC,
					},
				},
			},
		},
	}
}

func TestConsideredDevices(t *testing.T) {
	tests := []struct {
		name       string
		ipam       string
		localNode  func(*testing.T) *v2.CiliumNode
		devices    func(*testing.T) []*tables.Device
		wantDevice []string
	}{
		{
			name:      "ENI mode excludes only secondary ENIs",
			ipam:      ipamOption.IPAMENI,
			localNode: eniNode,
			devices: func(t *testing.T) []*tables.Device {
				return []*tables.Device{
					{Name: "eth0", MTU: 9001, HardwareAddr: hwAddr(primaryMAC)},
					{Name: "eth1", MTU: 9001, HardwareAddr: hwAddr(secondaryMAC)},
				}
			},
			wantDevice: []string{"eth0"},
		},
		{
			name:      "ENI mode considers all devices while the local node is unknown",
			ipam:      ipamOption.IPAMENI,
			localNode: func(*testing.T) *v2.CiliumNode { return nil },
			devices: func(t *testing.T) []*tables.Device {
				return []*tables.Device{
					{Name: "eth0", MTU: 9001, HardwareAddr: hwAddr(primaryMAC)},
					{Name: "eth1", MTU: 9001, HardwareAddr: hwAddr(secondaryMAC)},
				}
			},
			wantDevice: []string{"eth0", "eth1"},
		},
		{
			name:      "ENI mode excludes Cilium managed and dummy devices",
			ipam:      ipamOption.IPAMENI,
			localNode: eniNode,
			devices: func(t *testing.T) []*tables.Device {
				return []*tables.Device{
					{Name: "eth0", MTU: 9001, HardwareAddr: hwAddr(primaryMAC)},
					{Name: defaults.VxlanDevice, MTU: 8951},
					{Name: defaults.GeneveDevice, MTU: 8951},
					{Name: defaults.IPIPv4Device, MTU: 8981},
					{Name: defaults.IPIPv6Device, MTU: 8953},
					{Name: "cilium_dummy", MTU: 65520, Type: "dummy"},
				}
			},
			wantDevice: []string{"eth0"},
		},
		{
			name:      "non-ENI mode keeps all non-excluded devices",
			ipam:      ipamOption.IPAMKubernetes,
			localNode: func(*testing.T) *v2.CiliumNode { return nil },
			devices: func(t *testing.T) []*tables.Device {
				return []*tables.Device{
					{Name: "eth0", MTU: 9001, HardwareAddr: hwAddr(primaryMAC)},
					{Name: "eth1", MTU: 1500, HardwareAddr: hwAddr(secondaryMAC)},
					{Name: defaults.VxlanDevice, MTU: 8951},
				}
			},
			wantDevice: []string{"eth0", "eth1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MTUManager{
				mtuParams: mtuParams{
					Log:          hivetest.Logger(t),
					DaemonConfig: &option.DaemonConfig{IPAM: tt.ipam},
				},
			}
			if node := tt.localNode(t); node != nil {
				m.localNode.Store(node)
			}

			considered := m.consideredDevices(tt.devices(t))

			names := make([]string, 0, len(considered))
			for _, dev := range considered {
				names = append(names, dev.Name)
			}
			require.ElementsMatch(t, tt.wantDevice, names)
		})
	}
}
