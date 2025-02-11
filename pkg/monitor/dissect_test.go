// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDissectSummary(t *testing.T) {

	srcMAC := "01:23:45:67:89:ab"
	dstMAC := "02:33:45:67:89:ab"

	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	summary := GetDissectSummary(packetData)

	require.NotEqual(t, "", summary.Ethernet)
	require.NotEqual(t, "", summary.IPv4)
	require.NotEqual(t, "", summary.TCP)

	require.Equal(t, srcMAC, summary.L2.Src)
	require.Equal(t, dstMAC, summary.L2.Dst)

	require.Equal(t, srcIP, summary.L3.Src)
	require.Equal(t, dstIP, summary.L3.Dst)

	require.Equal(t, sport, summary.L4.Src)
	require.Equal(t, dport, summary.L4.Dst)
}

func TestConnectionSummaryTcp(t *testing.T) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	summary := GetConnectionSummary(packetData)

	expect := fmt.Sprintf("%s -> %s %s",
		net.JoinHostPort(srcIP, sport),
		net.JoinHostPort(dstIP, dport),
		"tcp SYN")
	require.Equal(t, expect, summary)
}

func TestConnectionSummaryIcmp(t *testing.T) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/ICMP(type=3, code=1)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 28, 0, 1, 0, 0, 64, 1, 106, 205, 1, 2, 3, 4, 5, 6, 7, 8, 3, 1, 252, 254, 0, 0, 0, 0}

	summary := GetConnectionSummary(packetData)

	expect := fmt.Sprintf("%s -> %s %s",
		srcIP,
		dstIP,
		"icmp DestinationUnreachable(Host)")
	require.Equal(t, expect, summary)
}
