// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"net"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
)

func (e *LinuxRoutingSuite) TestParse(c *check.C) {
	_, fakeCIDR, err := net.ParseCIDR("192.168.0.0/16")
	c.Assert(err, check.IsNil)

	fakeMAC, err := mac.ParseMAC("11:22:33:44:55:66")
	c.Assert(err, check.IsNil)

	validCIDRs := []net.IPNet{*fakeCIDR}

	tests := []struct {
		name      string
		gateway   string
		cidrs     []string
		macAddr   string
		masq      bool
		ifaceNum  string
		wantRInfo *RoutingInfo
		wantErr   bool
	}{
		{
			name:      "invalid gateway",
			gateway:   "",
			cidrs:     []string{"192.168.0.0/16"},
			macAddr:   "11:22:33:44:55:66",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "invalid cidr",
			gateway:   "192.168.1.1",
			cidrs:     []string{"192.168.0.0/16", "192.168.0.0/33"},
			macAddr:   "11:22:33:44:55:66",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "empty cidr",
			gateway:   "192.168.1.1",
			cidrs:     []string{},
			macAddr:   "11:22:33:44:55:66",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "nil cidr",
			gateway:   "192.168.1.1",
			cidrs:     nil,
			macAddr:   "11:22:33:44:55:66",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "invalid mac address",
			gateway:   "192.168.1.1",
			cidrs:     []string{"192.168.0.0/16"},
			macAddr:   "11:22:33:44:55:zz",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "empty mac address",
			gateway:   "192.168.1.1",
			cidrs:     []string{"192.168.0.0/16"},
			macAddr:   "",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:      "invalid interface number",
			gateway:   "192.168.1.1",
			cidrs:     []string{"192.168.0.0/16"},
			macAddr:   "11:22:33:44:55:zz",
			ifaceNum:  "a",
			wantRInfo: nil,
			wantErr:   true,
		},
		{
			name:     "valid IPv4 input",
			gateway:  "192.168.1.1",
			cidrs:    []string{"192.168.0.0/16"},
			macAddr:  "11:22:33:44:55:66",
			ifaceNum: "1",
			wantRInfo: &RoutingInfo{
				IPv4Gateway:     net.ParseIP("192.168.1.1"),
				IPv4CIDRs:       validCIDRs,
				MasterIfMAC:     fakeMAC,
				InterfaceNumber: 1,
				IpamMode:        ipamOption.IPAMENI,
			},
			wantErr: false,
		},
		{
			name:     "disabled masquerade",
			gateway:  "192.168.1.1",
			cidrs:    []string{},
			macAddr:  "11:22:33:44:55:66",
			masq:     false,
			ifaceNum: "0",
			wantRInfo: &RoutingInfo{
				IPv4Gateway: net.ParseIP("192.168.1.1"),
				IPv4CIDRs:   []net.IPNet{},
				MasterIfMAC: fakeMAC,
				IpamMode:    ipamOption.IPAMENI,
			},
			wantErr: false,
		},
		{
			name:      "masquerade lacking cidrs",
			gateway:   "192.168.1.1",
			cidrs:     []string{},
			macAddr:   "11:22:33:44:55:66",
			masq:      true,
			wantRInfo: nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		rInfo, err := NewRoutingInfo(tt.gateway, tt.cidrs, tt.macAddr, tt.ifaceNum, ipamOption.IPAMENI, tt.masq)
		c.Assert(rInfo, checker.DeepEquals, tt.wantRInfo)
		c.Assert((err != nil), check.Equals, tt.wantErr)
	}
}
