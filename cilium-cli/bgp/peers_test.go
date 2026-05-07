// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_printSummary(t *testing.T) {
	expectedColFormat := []string{
		"Node",
		"Instance",
		"Peer",
		"Session State",
		"Uptime",
		"Family",
		"Received",
		"Accepted",
		"Advertised",
	}

	peer1 := []string{
		"Instance\tPeer\tSession State\tUptime\tFamily\tReceived\tAccepted\tAdvertised",
		"test_instance\tpeer1\testablished\t1s\tipv4-unicast\t1\t1\t1",
		"test_instance\tpeer1\testablished\t1s\tipv6-unicast\t0\t0\t0",
	}
	peer2 := []string{
		"Instance\tPeer\tSession State\tUptime\tFamily\tReceived\tAccepted\tAdvertised",
		"test_instance\tpeer2\testablished\t1s\tipv4-unicast\t1\t1\t1",
		"test_instance\tpeer2\testablished\t1s\tipv6-unicast\t0\t0\t0",
	}
	testCases := []struct {
		Name         string
		Config       map[string][]string
		expectedRows int
	}{
		{
			Name: "Single node output, with single peer",
			Config: map[string][]string{
				"node_1": peer1,
			},
			expectedRows: 3,
		},
		{
			Name: "Single node output, with multiple peers",
			Config: map[string][]string{
				"node_1": append(peer1, peer2[1:]...),
			},
			expectedRows: 5,
		},
		{
			Name: "Two node output, with single peer",
			Config: map[string][]string{
				"node_1": peer1,
				"node_2": peer1,
			},
			expectedRows: 5,
		},
		{
			Name: "Two node output, with multiple peers",
			Config: map[string][]string{
				"node_1": append(peer1, peer2[1:]...),
				"node_2": append(peer1, peer2[1:]...),
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
