// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/stretchr/testify/require"
)

var (
	expectedRoutesColFormat = []string{
		"Node",
		"VRouter",
		"Prefix",
		"NextHop",
		"Age",
		"Attrs",
	}
	expectedRoutesColFormatWithPeer = []string{
		"Node",
		"VRouter",
		"Peer",
		"Prefix",
		"NextHop",
		"Age",
		"Attrs",
	}

	route1 = &models.BgpRoute{
		Prefix:    "10.1.0.0/24",
		RouterAsn: 65001,
		Paths: []*models.BgpPath{
			{
				Family: &models.BgpFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Nlri: &models.BgpNlri{
					Base64: "GAoBAA==",
				},
			},
		},
	}

	route2 = &models.BgpRoute{
		Prefix:    "10.1.1.0/24",
		RouterAsn: 65001,
		Neighbor:  "192.168.0.100",
		Paths: []*models.BgpPath{
			{
				Family: &models.BgpFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Nlri: &models.BgpNlri{
					Base64: "GAoBAQ==",
				},
				PathAttributes: []*models.BgpPathAttribute{
					{
						Base64: "QAEBAA==",
					},
					{
						Base64: "QAIKAgIAAP3oAAD96g==",
					},
				},
			},
		},
	}

	routeInvalid = &models.BgpRoute{
		Prefix:    "10.1.0.0/24",
		RouterAsn: 65001,
		Paths: []*models.BgpPath{
			{
				Family: &models.BgpFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
				Nlri: &models.BgpNlri{
					Base64: "invalid",
				},
			},
		},
	}
)

func Test_printRouteSummary(t *testing.T) {
	testCases := []struct {
		Name         string
		Config       map[string][]*models.BgpRoute
		printPeer    bool
		expectedRows int
	}{
		{
			Name: "Single node output, with no route",
			Config: map[string][]*models.BgpRoute{
				"node_1": {},
			},
			expectedRows: 1,
		},
		{
			Name: "Single node output, with single route",
			Config: map[string][]*models.BgpRoute{
				"node_1": {route1},
			},
			expectedRows: 2,
		},
		{
			Name: "Single node output, with multiple routes",
			Config: map[string][]*models.BgpRoute{
				"node_1": {route1, route2},
			},
			printPeer:    true,
			expectedRows: 3,
		},
		{
			Name: "Single node output, invalid route",
			Config: map[string][]*models.BgpRoute{
				"node_1": {routeInvalid},
			},
			expectedRows: 2,
		},
		{
			Name: "Single node output, with multiple routes, one invalid",
			Config: map[string][]*models.BgpRoute{
				"node_1": {route1, route2, routeInvalid},
			},
			printPeer:    true,
			expectedRows: 3,
		},
		{
			Name: "Two node output, with single route",
			Config: map[string][]*models.BgpRoute{
				"node_1": {route1},
				"node_2": {route2},
			},
			expectedRows: 3,
		},
		{
			Name: "Two node output, with multiple routes",
			Config: map[string][]*models.BgpRoute{
				"node_1": {route1, route2},
				"node_2": {route1, route2},
			},
			expectedRows: 5,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			var out bytes.Buffer

			// function to test
			printRouteSummary(&out, tt.Config, tt.printPeer)

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
			expectArgs: []string{availableKW, ipv4AFI, unicastSAFI},
		},
		{
			Name:       "Missing afi",
			Args:       []string{advertisedKW},
			expectArgs: []string{advertisedKW, ipv4AFI, unicastSAFI},
		},
		{
			Name:       "Missing safi",
			Args:       []string{advertisedKW, ipv4AFI},
			expectArgs: []string{advertisedKW, ipv4AFI, unicastSAFI},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			args := defaultGetRoutesArgs(tt.Args, true)
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
			Args:      []string{"available"},
			expectErr: true,
		},
		{
			Name:      "Invalid afi",
			Args:      []string{"available", "invalid"},
			expectErr: true,
		},
		{
			Name:      "Missing safi",
			Args:      []string{"available", "ipv4"},
			expectErr: true,
		},
		{
			Name:      "Invalid safi",
			Args:      []string{"available", "ipv4", "invalid"},
			expectErr: true,
		},
		{
			Name:      "Available - all mandatory",
			Args:      []string{"available", "ipv4", "unicast"},
			expectErr: false,
		},
		{
			Name:      "Vrouter - missing ASN",
			Args:      []string{"available", "ipv4", "unicast", "vrouter"},
			expectErr: true,
		},
		{
			Name:      "Vrouter - invalid ASN",
			Args:      []string{"available", "ipv4", "unicast", "vrouter", "invalid"},
			expectErr: true,
		},
		{
			Name:      "Vrouter - valid",
			Args:      []string{"available", "ipv4", "unicast", "vrouter", "65000"},
			expectErr: false,
		},
		{
			Name:      "Advertised - peer not specified",
			Args:      []string{"advertised", "ipv4", "unicast"},
			expectErr: false,
		},
		{
			Name:      "Advertised - missing peer IP",
			Args:      []string{"advertised", "ipv4", "unicast", "peer"},
			expectErr: true,
		},
		{
			Name:      "Advertised - invalid peer IP",
			Args:      []string{"advertised", "ipv4", "unicast", "peer", "invalid"},
			expectErr: true,
		},
		{
			Name:      "Advertised - valid",
			Args:      []string{"advertised", "ipv4", "unicast", "peer", "1.2.3.4"},
			expectErr: false,
		},
		{
			Name:      "Advertised with vrouter - valid",
			Args:      []string{"advertised", "ipv4", "unicast", "vrouter", "65000", "peer", "1.2.3.4"},
			expectErr: false,
		},
		{
			Name:      "Advertised with vrouter - invalid ASN",
			Args:      []string{"advertised", "ipv4", "unicast", "vrouter", "invalid", "peer", "1.2.3.4"},
			expectErr: true,
		},
		{
			Name:      "Advertised with vrouter - missing ASN",
			Args:      []string{"advertised", "ipv4", "unicast", "vrouter", "peer", "1.2.3.4"},
			expectErr: true,
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
