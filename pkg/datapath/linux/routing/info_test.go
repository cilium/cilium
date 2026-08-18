// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
)

func TestPrivilegedParse(t *testing.T) {
	setupLinuxRoutingSuite(t)

	fakeCIDR := netip.MustParsePrefix("192.168.0.0/16")

	fakeMAC := mac.MustParseMAC("11:22:33:44:55:66")

	validCIDRs := []netip.Prefix{fakeCIDR}

	tests := []struct {
		name      string
		gateway   string
		cidrs     []netip.Prefix
		macAddr   mac.MAC
		masq      bool
		ifaceNum  string
		wantRInfo *RoutingInfo
		wantErr   bool
	}{
		{
			name:      "invalid gateway",
			gateway:   "",
			cidrs:     []netip.Prefix{fakeCIDR},
			macAddr:   fakeMAC,
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "empty cidr",
			gateway:   "192.168.1.1",
			cidrs:     []netip.Prefix{},
			macAddr:   fakeMAC,
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "nil cidr",
			gateway:   "192.168.1.1",
			cidrs:     nil,
			macAddr:   fakeMAC,
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "empty mac address",
			gateway:   "192.168.1.1",
			cidrs:     []netip.Prefix{fakeCIDR},
			macAddr:   mac.MAC{},
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "invalid interface number",
			gateway:   "192.168.1.1",
			cidrs:     []netip.Prefix{fakeCIDR},
			macAddr:   fakeMAC,
			ifaceNum:  "a",
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:     "valid IPv4 input",
			gateway:  "192.168.1.1",
			cidrs:    []netip.Prefix{fakeCIDR},
			macAddr:  fakeMAC,
			ifaceNum: "1",
			wantRInfo: &RoutingInfo{
				Gateway:         net.ParseIP("192.168.1.1"),
				CIDRs:           validCIDRs,
				MasterIfMAC:     fakeMAC,
				InterfaceNumber: 1,
				IpamMode:        ipamOption.IPAMENI,
			},
			wantErr: false,
		},
		{
			name:     "disabled masquerade",
			gateway:  "192.168.1.1",
			cidrs:    []netip.Prefix{},
			macAddr:  fakeMAC,
			masq:     false,
			ifaceNum: "0",
			wantRInfo: &RoutingInfo{
				Gateway:     net.ParseIP("192.168.1.1"),
				CIDRs:       []netip.Prefix{},
				MasterIfMAC: fakeMAC,
				IpamMode:    ipamOption.IPAMENI,
			},
			wantErr: false,
		},
		{
			name:      "masquerade lacking cidrs",
			gateway:   "192.168.1.1",
			cidrs:     []netip.Prefix{},
			macAddr:   fakeMAC,
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			rInfo, err := NewRoutingInfo(logger, tt.gateway, tt.cidrs, tt.macAddr, tt.ifaceNum, ipamOption.IPAMENI, tt.masq)
			if err == nil {
				// Do not compare loggers
				rInfo.logger = nil
			}
			require.Equal(t, tt.wantRInfo, rInfo)
			require.Equal(t, tt.wantErr, err != nil)
		})
	}
}
