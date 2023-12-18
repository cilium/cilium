// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/stretchr/testify/require"
)

var (
	expectedColFormat = []string{
		"Node",
		"Local AS",
		"Peer AS",
		"Peer Address",
		"Session State",
		"Uptime",
		"Family",
		"Received",
		"Advertised",
	}

	ipv4Unicast1 = &models.BgpPeerFamilies{
		Accepted:   1,
		Advertised: 1,
		Afi:        "ipv4",
		Received:   1,
		Safi:       "unicast",
	}

	ipv6Unicast1 = &models.BgpPeerFamilies{
		Accepted:   0,
		Advertised: 0,
		Afi:        "ipv6",
		Received:   0,
		Safi:       "unicast",
	}

	peer1 = &models.BgpPeer{
		LocalAsn:          65001,
		PeerAddress:       "192.168.0.2",
		PeerAsn:           65002,
		SessionState:      "established",
		UptimeNanoseconds: int64(time.Second),
		Families:          []*models.BgpPeerFamilies{ipv4Unicast1, ipv6Unicast1},
	}

	peer2 = &models.BgpPeer{
		LocalAsn:          65101,
		PeerAddress:       "192.168.0.2",
		PeerAsn:           65102,
		SessionState:      "established",
		UptimeNanoseconds: int64(time.Second),
		Families:          []*models.BgpPeerFamilies{ipv4Unicast1, ipv6Unicast1},
	}
)

func Test_printSummary(t *testing.T) {
	testCases := []struct {
		Name         string
		Config       map[string][]*models.BgpPeer
		expectedRows int
	}{
		{
			Name: "Single node output, with single peer",
			Config: map[string][]*models.BgpPeer{
				"node_1": {peer1},
			},
			expectedRows: 3,
		},
		{
			Name: "Single node output, with multiple peers",
			Config: map[string][]*models.BgpPeer{
				"node_1": {peer1, peer2},
			},
			expectedRows: 5,
		},
		{
			Name: "Two node output, with single peer",
			Config: map[string][]*models.BgpPeer{
				"node_1": {peer1},
				"node_2": {peer1},
			},
			expectedRows: 5,
		},
		{
			Name: "Two node output, with multiple peers",
			Config: map[string][]*models.BgpPeer{
				"node_1": {peer1, peer2},
				"node_2": {peer1, peer2},
			},
			expectedRows: 9,
		},
	}

	for _, tt := range testCases {
		var out bytes.Buffer

		// function to test
		printSummary(&out, tt.Config)

		// validate rows and cols
		rows := 0
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			// First row should match col format
			if rows == 0 {
				validateColFormat(t, expectedColFormat, scanner.Text())
			}

			rows++
		}
		require.Equal(t, tt.expectedRows, rows)
	}
}

func validateColFormat(t *testing.T, expectedFormat []string, output string) {
	outputSlice := strings.Split(output, strings.Repeat(string(paddingChar), padding))

	// clean up white spaces, and empty [""] which can come in output
	i := 0
	for _, outputCol := range outputSlice {
		outputCol = strings.TrimSpace(outputCol)

		// we can get empty col, so delete that while maintaining order
		if outputCol != "" {
			outputSlice[i] = outputCol
			i++
		}
	}
	outputSlice = outputSlice[:i]

	require.Equal(t, expectedFormat, outputSlice)
}
