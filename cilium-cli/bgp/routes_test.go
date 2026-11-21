// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_printRouteSummary(t *testing.T) {
	expectedRoutesColFormat := []string{
		"Node",
		"Instance",
		"Prefix",
		"NextHop",
		"Best",
		"Age",
		"Attrs",
	}
	expectedRoutesColFormatWithPeer := []string{
		"Node",
		"Instance",
		"Peer",
		"Prefix",
		"NextHop",
		"Best",
		"Age",
		"Attrs",
	}

	route1 := []string{
		"Instance\tPrefix\tNextHop\tBest\tAge\tAttrs",
		"test_instance\t10.1.0.0/24\t192.168.0.100\t1s\t[{Origin: i} {AsPath: 65001}]",
	}
	route2 := []string{
		"Instance\tPrefix\tNextHop\tBest\tAge\tAttrs",
		"test_instance\t10.1.0.0/24\t192.168.0.101\t1s\t[{Origin: i} {AsPath: 65001}]",
	}
	route1WithPeer := []string{
		"Instance\tPeer\tPrefix\tNextHop\tBest\tAge\tAttrs",
		"test_instance\tpeer1\t10.1.0.0/24\t192.168.0.100\t1s\t[{Origin: i} {AsPath: 65001}]",
	}
	route2WithPeer := []string{
		"Instance\tPeer\tPrefix\tNextHop\tBest\tAge\tAttrs",
		"test_instance\tpeer2\t10.1.0.0/24\t192.168.0.101\t1s\t[{Origin: i} {AsPath: 65001}]",
	}

	testCases := []struct {
		Name         string
		Config       map[string][]string
		printPeer    bool
		expectedRows int
	}{
		{
			Name: "Single node output, with single route",
			Config: map[string][]string{
				"node_1": route1,
			},
			expectedRows: 2,
		},
		{
			Name: "Single node output, with multiple routes",
			Config: map[string][]string{
				"node_1": append(route1WithPeer, route2WithPeer[1]),
			},
			printPeer:    true,
			expectedRows: 3,
		},
		{
			Name: "Two node output, with single route",
			Config: map[string][]string{
				"node_1": route1,
				"node_2": route2,
			},
			expectedRows: 3,
		},
		{
			Name: "Two node output, with multiple routes",
			Config: map[string][]string{
				"node_1": append(route1, route2[1]),
				"node_2": append(route1, route2[1]),
			},
			expectedRows: 5,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			var out bytes.Buffer

			// function to test
			printRouteSummary(&out, tt.Config, tt.printPeer, true)

			// validate rows and cols
			rows := 0
			scanner := bufio.NewScanner(&out)
			for scanner.Scan() {
				// First row should match col format
				if rows == 0 {
					if tt.printPeer {
						validateColFormat(t, expectedRoutesColFormatWithPeer, scanner.Text())
					} else {
						validateColFormat(t, expectedRoutesColFormat, scanner.Text())
					}
				}
				rows++
			}
			require.Equal(t, tt.expectedRows, rows)
		})
	}
}

func Test_defaultGetRoutesArgs(t *testing.T) {
	testCases := []struct {
		Name       string
		Args       []string
		expectArgs []string
	}{
		{
			Name:       "Missing args",
			Args:       nil,
			expectArgs: []string{locRibTable, ipv4AFI, unicastSAFI},
		},
		{
			Name:       "Missing afi",
			Args:       []string{locRibTable},
			expectArgs: []string{locRibTable, ipv4AFI, unicastSAFI},
		},
		{
			Name:       "Missing safi",
			Args:       []string{locRibTable, ipv6AFI},
			expectArgs: []string{locRibTable, ipv6AFI, unicastSAFI},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			args := defaultGetRoutesArgs(tt.Args)
			require.Equal(t, tt.expectArgs, args)
		})
	}
}

func Test_validateGetRoutesArgs(t *testing.T) {
	testCases := []struct {
		Name      string
		Args      []string
		expectErr bool
	}{
		{
			Name:      "Missing args",
			Args:      nil,
			expectErr: true,
		},
		{
			Name:      "Invalid arg",
			Args:      []string{"invalid"},
			expectErr: true,
		},
		{
			Name:      "Missing afi",
			Args:      []string{locRibTable},
			expectErr: true,
		},
		{
			Name:      "Invalid afi",
			Args:      []string{locRibTable, "invalid"},
			expectErr: true,
		},
		{
			Name:      "Missing safi",
			Args:      []string{locRibTable, ipv4AFI},
			expectErr: true,
		},
		{
			Name:      "Invalid safi",
			Args:      []string{locRibTable, ipv4AFI, "invalid"},
			expectErr: true,
		},
		{
			Name:      "loc-rib",
			Args:      []string{locRibTable, ipv6AFI, unicastSAFI},
			expectErr: false,
		},
		{
			Name:      "adj-rib-in",
			Args:      []string{adjRibInTable, ipv4AFI, unicastSAFI},
			expectErr: false,
		},
		{
			Name:      "adj-rib-out",
			Args:      []string{adjRibInTable, ipv6AFI, unicastSAFI},
			expectErr: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			err := validateGetRoutesArgs(tt.Args)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
