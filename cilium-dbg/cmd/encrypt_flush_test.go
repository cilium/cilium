// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestFilterXFRMs(t *testing.T) {
	policies := []netlink.XfrmPolicy{
		{Ifid: 1, Proto: netlink.XFRM_PROTO_ESP, Dst: &net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)}},
		{Ifid: 2, Proto: netlink.XFRM_PROTO_AH, Dst: &net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)}},
		{Ifid: 3, Proto: netlink.XFRM_PROTO_ESP, Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(16, 32)}},
		{Ifid: 4, Proto: netlink.XFRM_PROTO_AH, Dst: &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(16, 32)}},
	}
	states := []netlink.XfrmState{
		{Ifid: 1, Proto: netlink.XFRM_PROTO_ESP, Dst: net.ParseIP("192.168.1.0")},
		{Ifid: 2, Proto: netlink.XFRM_PROTO_AH, Dst: net.ParseIP("192.168.1.0")},
		{Ifid: 3, Proto: netlink.XFRM_PROTO_ESP, Dst: net.ParseIP("10.0.0.0")},
		{Ifid: 4, Proto: netlink.XFRM_PROTO_AH, Dst: net.ParseIP("10.0.0.0")},
	}
	filterDstPolicy := func(pol netlink.XfrmPolicy) bool {
		return pol.Dst.IP.String() == "192.168.1.0"
	}
	filterDstState := func(state netlink.XfrmState) bool {
		return state.Dst.String() == "192.168.1.0"
	}
	filterProtoPolicy := func(pol netlink.XfrmPolicy) bool {
		return pol.Proto == netlink.XFRM_PROTO_ESP
	}
	filterProtoState := func(state netlink.XfrmState) bool {
		return state.Proto == netlink.XFRM_PROTO_ESP
	}

	// Test that single call to filterXFRMs provides the expected results.
	resPolicies, resStates := filterXFRMs(policies, states, filterDstPolicy, filterDstState)
	if len(resPolicies) != 2 {
		t.Errorf("Expected two policies to be filtered, but got %d", len(resPolicies))
	}
	if len(resStates) != 2 {
		t.Errorf("Expected two states to be filtered, but got %d", len(resStates))
	}
	if resPolicies[0].Ifid != 1 || resPolicies[1].Ifid != 2 {
		t.Errorf("Expected policies with Ifids 1 and 2 to be filtered, but got policies with Ifids %d and %d", resPolicies[0].Ifid, resPolicies[1].Ifid)
	}
	if resStates[0].Ifid != 1 || resStates[1].Ifid != 2 {
		t.Errorf("Expected state with Ifids 1 and 2 to be filtered, but got states with Ifids %d and %d", resStates[0].Ifid, resStates[1].Ifid)
	}

	// Test that chained calls to filterXFRMs also provide the expected results.
	resPolicies, resStates = filterXFRMs(resPolicies, resStates, filterProtoPolicy, filterProtoState)
	if len(resPolicies) != 1 {
		t.Errorf("Expected one policy to be filtered, but got %d", len(resPolicies))
	}
	if len(resStates) != 1 {
		t.Errorf("Expected one state to be filtered, but got %d", len(resStates))
	}
	if resPolicies[0].Ifid != 1 {
		t.Errorf("Expected policies with Ifid 1 to be filtered, but got policies with Ifid %d", resPolicies[0].Ifid)
	}
	if resStates[0].Ifid != 1 {
		t.Errorf("Expected state with Ifid 1 to be filtered, but got states with Ifid %d", resStates[0].Ifid)
	}
}

func TestParseNodeID(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
		err      bool
	}{
		{"0x0", 0, true},
		{"42", 42, false},
		{"0x1a", 26, false},
		{"65535", 65535, false},
		{"70000", 0, true}, // Too big for uint16
		{"invalid", 0, true},
		{"0xinvalid", 0, true},
		{"0xdeadbeef", 0, true}, // Too big for uint16
	}

	for _, test := range tests {
		result, err := parseNodeID(test.input)
		if test.err {
			if err == nil {
				t.Errorf("Expected error for input %s, but got nil", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}

			if result != test.expected {
				t.Errorf("For input %s, expected %d, but got %d", test.input, test.expected, result)
			}
		}
	}
}
